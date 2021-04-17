#include <fcntl.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <termios.h>

#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <filesystem>
#include <regex>

extern "C" {
#include <libxl.h>
#include <libxl_utils.h>
#include <xenstore.h>
}

#include <iniparser4/iniparser.h>

static struct termios old_term;

void restore_term()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
}

std::shared_ptr<libxl_ctx> libxl_ctx_alloc(xentoollog_logger* logger)
{
    libxl_ctx* ctx;
    libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, logger);
    if (!ctx) throw std::runtime_error("libxl_ctx_alloc");
    return std::shared_ptr<libxl_ctx>(ctx, libxl_ctx_free);
}

std::shared_ptr<xentoollog_logger> xtl_createlogger_stderr(xentoollog_level min_level, unsigned flags)
{
    xentoollog_logger* logger = (xentoollog_logger*)xtl_createlogger_stdiostream(stderr, min_level, flags);
    if (!logger) throw std::runtime_error("xtl_createlogger_stdiostream");
    return std::shared_ptr<xentoollog_logger>(logger, [](auto logger) { xtl_logger_destroy(logger);});
}

std::optional<std::shared_ptr<libxl_event>> libxl_event_check(libxl_ctx* ctx, uint64_t typemask = LIBXL_EVENTMASK_ALL, libxl_event_predicate* predicate = NULL, void* predicate_user = NULL)
{
    libxl_event* event;
    auto rst = libxl_event_check(ctx, &event, typemask, predicate, predicate_user);
    if (rst == ERROR_NOT_READY) return std::nullopt;
    //else
    if (rst != 0) throw std::runtime_error("libxl_event_wait");
    return std::shared_ptr<libxl_event>(event, [ctx](auto event){libxl_event_free(ctx,event);});
}

std::shared_ptr<libxl_domain_config> libxl_domain_config_init()
{
    libxl_domain_config* d_config = new libxl_domain_config;
    libxl_domain_config_init(d_config);
    return std::shared_ptr<libxl_domain_config>(d_config, [](auto d_config){ libxl_domain_config_dispose(d_config); delete d_config; });
}

std::shared_ptr<xs_handle> xs_open_readwrite()
{
    auto xh = xs_open(0);
    if (!xh) throw std::runtime_error("xs_open");
    return std::shared_ptr<xs_handle>(xh, xs_close);
}

int discard_all_outstanding_events(libxl_ctx* ctx) {
    int ret;
    libxl_event* event;
    while (!(ret = libxl_event_check(ctx, &event, LIBXL_EVENTMASK_ALL, 0,0))) {
      libxl_event_free(ctx, event);
      event = NULL;
    }
    if (ret != ERROR_NOT_READY) {
      // warning
    }
    return ret;
}

struct Disk {
    std::string name;
    std::string path;
    bool readonly = false;
};

struct NIC {
    std::string bridge;
    uint8_t mac[6];
};

uint32_t start_domain(
    const std::string& name, const uint32_t memory, const uint16_t vcpus, bool pvh, 
    const std::string& kernel, const std::optional<std::string>& ramdisk, const std::optional<std::string>& cmdline,
    const std::vector<Disk>& disks, const std::vector<NIC>& nics)
{
    auto logger = xtl_createlogger_stderr(XTL_ERROR, 0);
    auto ctx = libxl_ctx_alloc(logger.get());

    auto d_config = libxl_domain_config_init();
    d_config->c_info.name = strdup(name.c_str());
    d_config->c_info.type = pvh? LIBXL_DOMAIN_TYPE_PVH : LIBXL_DOMAIN_TYPE_PV;
    libxl_uuid_generate(&d_config->c_info.uuid);
    libxl_domain_build_info_init_type(&d_config->b_info, d_config->c_info.type);
    d_config->b_info.target_memkb = memory * 1024;
    d_config->b_info.max_memkb = d_config->b_info.target_memkb;
    if (libxl_cpu_bitmap_alloc(ctx.get(), &d_config->b_info.avail_vcpus, vcpus) != 0) {
        throw std::runtime_error("Unable to allocate cpumap");
    }
    libxl_bitmap_set_none(&d_config->b_info.avail_vcpus);
    for (int i = 0; i < vcpus; i++) {
        libxl_bitmap_set((&d_config->b_info.avail_vcpus), i);
    }
    d_config->b_info.max_vcpus = vcpus;

    d_config->on_poweroff = (libxl_action_on_shutdown)1/*destroy*/;
    d_config->on_reboot = (libxl_action_on_shutdown)2/*restart*/;
    d_config->on_watchdog = (libxl_action_on_shutdown)1/*destroy*/;
    d_config->on_crash = (libxl_action_on_shutdown)1/*destroy*/;
    d_config->on_soft_reset = (libxl_action_on_shutdown)7/*soft-reset*/;

    d_config->b_info.kernel = strdup(kernel.c_str());
    if (ramdisk) d_config->b_info.ramdisk = strdup(ramdisk.value().c_str());
    if (cmdline) d_config->b_info.cmdline = strdup(cmdline.value().c_str());

    d_config->num_disks = disks.size();
    d_config->disks = (libxl_device_disk*)malloc(sizeof(libxl_device_disk) * d_config->num_disks);
    int i = 0;
    for (const auto& disk_config : disks) {
        libxl_device_disk& disk = d_config->disks[i++];
        libxl_device_disk_init(&disk);
        disk.readwrite = disk_config.readonly? 0 : 1;
        disk.format = LIBXL_DISK_FORMAT_RAW;
        disk.is_cdrom = 0;
        disk.removable = 0;
        disk.vdev = strdup(disk_config.name.c_str());
        disk.pdev_path = strdup(disk_config.path.c_str());
    }

    d_config->num_nics = nics.size();
    d_config->nics = (libxl_device_nic*)malloc(sizeof(libxl_device_nic) * d_config->num_nics);
    i = 0;
    for (const auto& nic_config : nics) {
        libxl_device_nic& nic = d_config->nics[i++];
        libxl_device_nic_init(&nic);
        nic.script = strdup("vif-bridge");
        nic.nictype = LIBXL_NIC_TYPE_VIF;
        //nic.mac;
        nic.bridge = strdup(nic_config.bridge.c_str());
        memcpy(nic.mac, nic_config.mac, sizeof(nic.mac));
    }

    uint32_t domid = INVALID_DOMID;
    libxl_domain_create_new(ctx.get(), d_config.get(), &domid, 0, 0/*&autoconnect_console_now*/);
    libxl_domain_unpause(ctx.get(), domid, NULL);
    return domid;
}

size_t tee(struct pollfd& in, int out)
{
    if (!(in.revents & POLLIN)) return 0;
    //else
    char buf[4096];
    size_t count = 0;
    while(true) {
        auto r = read(in.fd, buf, sizeof(buf));
        if (r > 0) {
            int w = write(out, buf, r);
            if (w > 0) count += w;
        }
        if (r < sizeof(buf)) break;
    }
    return count;
}

int monitor_domain(uint32_t domid)
{
    auto logger = xtl_createlogger_stderr(XTL_ERROR, 0);
    auto ctx = libxl_ctx_alloc(logger.get());

    libxl_evgen_domain_death* deathw = nullptr;
    if (libxl_evenable_domain_death(ctx.get(), domid, 0, &deathw) != 0) throw std::runtime_error("libxl_evenable_domain_death");

    auto xs = xs_open_readwrite();
    auto dom_path = xs_get_domain_path(xs.get(), domid);
    if (!dom_path) throw std::runtime_error("xs_get_domain_path");
    auto console_tty_path = std::string(dom_path) + "/console/tty";
    free(dom_path);

    unsigned int len = 0;
    auto console_tty = xs_read(xs.get(), XBT_NULL, console_tty_path.c_str(), &len);
    if (!console_tty) throw std::runtime_error("xs_read");
    auto tty = open((const char*)console_tty, O_RDWR);
    free(console_tty);
    if (tty < 0) throw std::runtime_error("open(tty)");

    struct termios new_term;
    memcpy(&new_term, &old_term, sizeof(new_term));
    cfmakeraw(&new_term);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    const auto poll_slots = 10;
    struct pollfd pollfds[poll_slots];

    sigset_t mask;
    sigemptyset (&mask);
    sigaddset (&mask, SIGINT);
    sigaddset (&mask, SIGTERM);
    sigprocmask(SIG_SETMASK, &mask, NULL);
    auto sigfd = signalfd (-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);

    while (true) {
        int nfds = poll_slots - 3;
        int timeout = 1000;
        struct timeval now;
        if (gettimeofday(&now, 0) < 0) std::runtime_error("gettimeofday");
        libxl_osevent_beforepoll(ctx.get(), &nfds, pollfds + 3, &timeout, now);
        pollfds[0].fd = STDIN_FILENO;
        pollfds[0].events = POLLIN;
        pollfds[1].fd = tty;
        pollfds[1].events = POLLIN;
        pollfds[2].fd = sigfd;
        pollfds[2].events = POLLIN;

        if (poll(pollfds, nfds + 3, timeout) < 0) throw std::runtime_error("poll");
        if (gettimeofday(&now, 0) < 0) std::runtime_error("gettimeofday");
        libxl_osevent_afterpoll(ctx.get(), nfds, pollfds + 3, now);
        while (auto event = libxl_event_check(ctx.get())) {
            switch (event.value()->type) {
            case LIBXL_EVENT_TYPE_DOMAIN_SHUTDOWN:
                switch (event.value()->u.domain_shutdown.shutdown_reason) {
                case LIBXL_SHUTDOWN_REASON_POWEROFF:
                case LIBXL_SHUTDOWN_REASON_CRASH:
                case LIBXL_SHUTDOWN_REASON_WATCHDOG:
                    close(tty);
                    restore_term();
                    libxl_evdisable_domain_death(ctx.get(), deathw);
                    libxl_domain_destroy(ctx.get(), domid, 0);
                    return 0;
                case LIBXL_SHUTDOWN_REASON_REBOOT:
                case LIBXL_SHUTDOWN_REASON_SOFT_RESET:
                    close(tty);
                    restore_term();
                    libxl_evdisable_domain_death(ctx.get(), deathw);
                    libxl_domain_destroy(ctx.get(), domid, 0);
                    discard_all_outstanding_events(ctx.get());
                    return 1;
                case LIBXL_SHUTDOWN_REASON_SUSPEND:
                    continue;
                default:
                    std::runtime_error("Unkonown domain death case");
                }
                break;
            case LIBXL_EVENT_TYPE_DOMAIN_DEATH:
                return 0;
            default:;
                // don't care
                break;
            }
        }
        tee(pollfds[0], tty); // stdin to domain console
        tee(pollfds[1], STDOUT_FILENO); // domain console to stdout
    
        if (pollfds[2].revents & POLLIN) { // signal received
            struct signalfd_siginfo info;
            read(pollfds[2].fd, &info, sizeof(info));
            //std::cout << "Signal received: signo=" << info.ssi_signo << ", code=" << info.ssi_code << ", pid=" << info.ssi_pid << std::endl;
            if (info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) {
                libxl_domain_shutdown(ctx.get(), domid, nullptr);
            }
        }
        //std::cout << "Poll timeout" << std::endl;
    }
}

std::vector<Disk> load_disk_config(const std::filesystem::path& vm_dir, const dictionary* ini)
{
    std::vector<Disk> disks;
    auto disk_names = iniparser_getstring(ini, ":disks", NULL);

    auto is_file_or_block = [](std::filesystem::path& path) {
        return std::filesystem::exists(path) && (std::filesystem::is_regular_file(path) || std::filesystem::is_block_file(path));
    };

    if (!disk_names) {
        auto system_file = vm_dir / "system";
        auto data_file = vm_dir / "data";
        auto swp_file = vm_dir / "swapfile";

        bool system_file_exists = is_file_or_block(system_file);
        bool data_file_exists = is_file_or_block(data_file);

        Disk xvda1;
        xvda1.name = "xvda1";
        if (system_file_exists) {
            xvda1.path = system_file;
            xvda1.readonly = true; // todo: make it false in case image file contains writable filesystem
        } else if (data_file_exists) {
            xvda1.path = data_file;
            xvda1.readonly = false;
        } else {
            std::cerr << "No image file for VM." << std::endl;
            return disks;
        }
        disks.push_back(xvda1);

        if (system_file_exists && data_file_exists) {
            Disk xvda2;
            xvda2.name = "xvda2";
            xvda2.path = data_file;
            xvda2.readonly = false;
            disks.push_back(xvda2);
        }

        if (is_file_or_block(swp_file)) {
            Disk xvda3;
            xvda3.name = "xvda3";
            xvda3.path = swp_file;
            xvda3.readonly = false;
            disks.push_back(xvda3);
        }
        return disks;
    }
    //else
    std::smatch m ;
    std::string disk_names_str = disk_names;
    for (auto iter = disk_names_str.cbegin();
        std::regex_search(iter, disk_names_str.cend(), m, std::regex("[^,]+"));
        iter = m[0].second) {
        const auto& disk_name = m.str();
        if (!disk_name.starts_with("xvd") || disk_name.length() < 4 || (disk_name[3] < 'a' || disk_name[3] > 'z') || (disk_name.length() == 5 && !isdigit(disk_name[4])) || disk_name.length() > 5) {
        std::cerr << "Invalid virtual block device name '" << disk_name << "'. Ignored." << std::endl;
        continue;
        }
        auto path = iniparser_getstring(ini, (disk_name + ":path").c_str(), NULL);
        if (!path) {
            std::cerr << "No path defined for virtual block device '" << disk_name << "'. Ignored." << std::endl;
            continue;
        }
        // else
        disks.push_back({ 
            disk_name, 
            path, 
            iniparser_getboolean(ini, (disk_name + ":readonly").c_str(), 0) == 1? true : false
        });
    };

    return disks;
}

bool parse_mac_address(const std::string& mac_str, uint8_t mac[6])
{
    memset(mac, 0, 6);
    if (mac_str.length() != 17) return false;
    //else
    for (int i = 0; i < 17; i++) {
      char c = tolower(mac_str[i]);
      if (i % 3 == 2) {
        if ( c != ':') return false; // invalid tokenizer
        else continue;
      }
      //else
      if (!isdigit(c) && (c < 'a' || c > 'f')) return false; // invalid hex char
    }
    uint8_t* ptr = mac;
    for (int i = 0; i < 17; i+=3) {
      char hb = tolower(mac_str[i]);
      char lb = tolower(mac_str[i + 1]);
      uint8_t octet = (uint8_t)((int)(hb > '9' ? hb - 'a' + 10 : hb - '0') * 16);
      octet += (uint8_t)((int)(lb > '9' ? lb - 'a' + 10 : lb - '0'));
      *ptr++ = octet;
    }

    return true;
}

void get_or_generate_mac_address(const std::string& vmname, int num, uint8_t mac[6])
{
    std::filesystem::path cache_dir("/var/cache/walbrix/xendomain/nic");
    auto cache_file_path = cache_dir / (vmname + ':' + std::to_string(num));
    {
        // load from cache
        std::ifstream cache_file(cache_file_path);
        if (cache_file) {
            std::string mac_str;
            cache_file >> mac_str;
            if (parse_mac_address(mac_str, mac)) return;
        }
    }
    //else
    libxl_uuid uuid;
    libxl_uuid_generate(&uuid);
    auto r = libxl_uuid_bytearray(&uuid);

    mac[0] = 0x00;
    mac[1] = 0x16;
    mac[2] = 0x3e;
    mac[3] = r[0] & 0x7f;
    mac[4] = r[1];
    mac[5] = r[2];

    std::filesystem::create_directories(cache_dir);
    std::ofstream cache_file(cache_file_path);
    if (cache_file) {
        char mac_str[18];
        sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", (int)mac[0], (int)mac[1], (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);
        cache_file << mac_str;
    }
}

std::vector<NIC> load_nic_config(const std::string& vmname, const dictionary* ini)
{
    std::vector<NIC> nics;
    int max_eth = 0;
    for (int i = 1; i <= 9; i++) {
        char buf[5];
        sprintf(buf, "eth%d", i);
        if (iniparser_find_entry(ini, buf) == 1) max_eth = i;
    }

    for (int i = 0; i <= max_eth; i++) {
        NIC nic;
        char buf[16];
        sprintf(buf, "eth%d:bridge", i);
        nic.bridge = iniparser_getstring(ini, buf, "br0");
        sprintf(buf, "eth%d:mac", i);
        auto mac = iniparser_getstring(ini, buf, NULL);
        if (mac) {
            if (!parse_mac_address(mac, nic.mac)) mac = nullptr;
        }

        if (!mac) {
            get_or_generate_mac_address(vmname, i, nic.mac);
        }
        nics.push_back(nic);
    }

    return nics;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cout << "Usage:" << std::endl;
        std::cout << "  " << argv[0] << " name" << std::endl;
        return 1;
    }
    auto name = argv[1];

    std::filesystem::path vm_root("/var/vm");
    auto vm_dir = vm_root / name;

    if (!std::filesystem::exists(vm_dir) || !std::filesystem::is_directory(vm_dir)) {
        std::cerr << "No such VM: " << name << std::endl;
        return 2;
    }

    //else
    auto ini = std::shared_ptr<dictionary>(iniparser_load((vm_dir / "vm.ini").c_str()), iniparser_freedict);
    if (!ini) {
        ini = std::shared_ptr<dictionary>(dictionary_new(0), iniparser_freedict);
    }

    auto memory = iniparser_getint(ini.get(), ":memory", 512);
    if (memory < 256) throw std::runtime_error("Memory too less");
    auto vcpus = iniparser_getint(ini.get(), ":cpu", 1);
    if (vcpus < 1) throw std::runtime_error("Invalid cpu number");
    auto pvh = iniparser_getboolean(ini.get(), ":pvh", 0) == 1? true: false;
    auto kernel = iniparser_getstring(ini.get(), ":kernel", pvh? "/usr/libexec/xen/boot/pvh-grub2-x86_64.gz" : "/usr/libexec/xen/boot/pv-grub2-x86_64.gz");
    auto ramdisk = iniparser_getstring(ini.get(), ":ramdisk", NULL);
    auto cmdline = iniparser_getstring(ini.get(), ":cmdline", NULL);

    auto disks = load_disk_config(vm_dir, ini.get());
    auto nics = load_nic_config(name, ini.get());

    // save terminal attrs
    tcgetattr(STDIN_FILENO, &old_term);
    std::atexit(restore_term);

    bool restart = false;
    do {
        std::cout << "Starting domain..." << std::endl;
        auto domid = start_domain(name, memory, vcpus, pvh, 
            kernel, 
            ramdisk? std::optional<std::string>(ramdisk) : std::nullopt, 
            cmdline? std::optional<std::string>(cmdline) : std::nullopt, 
            disks, nics);

        std::cout << "Start monitoring..." << std::endl;
        restart = (monitor_domain(domid) == 1);
    } while (restart);

    return 0;
}

// g++ -std=c++2a -o xlcreatec xlcreatec.cpp -lxenlight -lxentoollog -lxenstore -liniparser4
