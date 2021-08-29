#include <iostream>
#include <fstream>
#include <filesystem>
#include <functional>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <variant>

#include <memory.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/utsname.h>

#include <uuid/uuid.h>
#include <libmount/libmount.h>
#include <systemd/sd-daemon.h>

#include <iniparser4/iniparser.h>

#include "common.h"

bool debug = false;

static const std::filesystem::path vm_root("/var/vm"), run_root("/run/vm");

static const std::filesystem::path default_ini_path("/etc/vm/default.ini");
static auto default_ini = std::shared_ptr<dictionary>(std::filesystem::exists(default_ini_path)? iniparser_load(default_ini_path.c_str()) : dictionary_new(0), iniparser_freedict);
static const char* default_bridge = iniparser_getstring(default_ini.get(), ":bridge", std::filesystem::exists("/sys/class/net/br0/bridge")? "br0" : NULL);

std::vector<std::string> getopt(
    int argc, char* argv[], 
    const std::vector<std::tuple<
        std::optional<char>/*shortopt*/,
        std::optional<std::string>/*longopt*/,
        std::variant<
            std::function<void(void)>, // 0: no arg
            std::function<void(const std::optional<std::string>&)>, // 1: optional string arg
            std::function<void(const std::string&)> // 2: required string arg
        >/*func*/
    >>& opts)
{
    std::string shortopts;
    std::vector<struct option> longopts;
    std::map<std::string,std::variant<
        std::function<void(void)>,
        std::function<void(const std::optional<std::string>&)>,
        std::function<void(const std::string&)>
    >> funcs;
    for (const auto& opt:opts) {
        if (std::get<0>(opt).has_value()) {
            char shortopt = std::get<0>(opt).value();
            const auto& func = std::get<2>(opt);
            shortopts += shortopt;
            if (std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func)) shortopts += "::";
            else if (std::holds_alternative<std::function<void(const std::string&)>>(func)) shortopts += ":";
            funcs[std::string(1, shortopt)] = func;
        }
        if (std::get<1>(opt).has_value()) {
            const auto& longopt = std::get<1>(opt).value();
            const auto& shortopt = std::get<0>(opt);
            const auto& func = std::get<2>(opt);
            auto arg_required = std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func)? optional_argument
                : ((std::holds_alternative<std::function<void(const std::string&)>>(func))? required_argument : no_argument);
            longopts.push_back((struct option) {
                longopt.c_str(),
                arg_required,
                0,
                shortopt.has_value()? shortopt.value() : 0
            });
            funcs[longopt] = func;
        }
    }

    struct option* clongopts = new struct option[longopts.size() + 1];
    struct option* p = clongopts;
    for (const auto& lo:longopts) { 
        memcpy(p, &lo, sizeof(*p));
        p++;
    }
    memset(p, 0, sizeof(*p));
    int c;
    int longindex = 0;
    while ((c = getopt_long(argc, argv, shortopts.c_str(), clongopts, &longindex)) >= 0) {
        const auto func = funcs.find(c == 0? clongopts[longindex].name : std::string(1,(char)c));
        if (func != funcs.end()) {
            if (std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func->second)) {
                std::get<1>(func->second)(optarg? std::optional<std::string>(optarg) : std::nullopt);
            } else if (std::holds_alternative<std::function<void(const std::string&)>>(func->second)) {
                std::get<2>(func->second)(optarg? optarg : "");
            } else {
                std::get<0>(func->second)();
            }
        }
    }
    delete []clongopts;

    std::vector<std::string> non_option_args;
    for (int i = optind; i < argc; i++) {
        non_option_args.push_back(argv[i]);
    }

    return non_option_args;
}

void send_qmp_command(const std::filesystem::path& socket_path, const std::string& command)
{
    with_socket(socket_path, [&command](int fd) {
        static const char* qmp_capabilities_cmd = "{\"execute\":\"qmp_capabilities\"}";
        if (write(fd, qmp_capabilities_cmd, strlen(qmp_capabilities_cmd)) < 0) {
            throw std::runtime_error("qmp write(qmp_capabilities_cmd) failed");
        }
        if (write(fd, command.c_str(), command.length()) < 0) {
            throw std::runtime_error("qmp write(command) failed");
        }
    });
}

void with_tempmount(
    const std::filesystem::path& device, const char* fstype, int flags, const char* data,
    std::function<void(const std::filesystem::path&)> func)
{
    struct libmnt_context *ctx = mnt_new_context();
    if (!ctx) throw std::runtime_error("mnt_new_context failed");

    auto path = std::filesystem::temp_directory_path() /= std::string("tempmount-") + std::to_string(getpid());
    std::filesystem::create_directory(path);
    try {
        mnt_context_set_fstype_pattern(ctx, fstype);
        mnt_context_set_source(ctx, device.c_str());
        mnt_context_set_target(ctx, path.c_str());
        mnt_context_set_mflags(ctx, flags);
        mnt_context_set_options(ctx, data);
        auto rst = mnt_context_mount(ctx);
        auto status = mnt_context_get_status(ctx);
        auto helper_success = mnt_context_helper_executed(ctx) == 1 ? (mnt_context_get_helper_status(ctx) == 0) : true;
        mnt_free_context(ctx);
        if (rst != 0) throw std::runtime_error("mnt_context_mount failed");
        if (status != 1) throw std::runtime_error("mnt_context_get_status returned error");
        if (!helper_success) throw std::runtime_error("mnt_context_get_helper_status returned error");
        try {
            func(path);
        }
        catch (...) {
            umount(path.c_str());
            throw;
        }
        umount(path.c_str());
    }
    catch (...) {
        std::filesystem::remove(path);
        throw;
    }
    std::filesystem::remove(path);
}

void create_bootimage(const std::filesystem::path& bootimage_path, const std::string& hostname)
{
    auto bootimage_dir = bootimage_path.parent_path();
    std::filesystem::create_directories(bootimage_dir);

    auto bootimage_tmp_path = bootimage_path.parent_path() / (bootimage_path.filename().string() + ".tmp." + std::to_string(getpid()));
    auto fd = creat(bootimage_tmp_path.c_str(), S_IRUSR|S_IWUSR);
    if (fd < 0) throw std::runtime_error(std::string("creat(") + bootimage_tmp_path.string() + ") failed: " + strerror(errno));
    close(fd);
    try {
        std::filesystem::resize_file(bootimage_tmp_path, 16 * 1024 * 1024);
        check_call({"parted","--script",bootimage_tmp_path.string(),"mklabel msdos", "mkpart primary 2048s -1", "set 1 boot on"});
        check_call({"mkfs.vfat","--offset=2048",bootimage_tmp_path.string()});
        with_tempmount(bootimage_tmp_path, "vfat", MS_RELATIME, "loop,offset=1048576", [&bootimage_tmp_path,&hostname](const auto& path) {
            check_call({"grub-install", "--target=i386-pc", "--skip-fs-probe", std::string("--boot-directory=") + (path / "boot").string(), 
                bootimage_tmp_path, "--modules=part_msdos fat squash4 xfs btrfs serial terminal"});
            std::ofstream grub_cfg(path / "boot" / "grub" / "grub.cfg");
            // hd0 = boot disk
            // hd1 = virtual FAT backed by /run/vm/VMNAME
            grub_cfg << "serial --speed=115200" << std::endl;
            grub_cfg << "terminal_input serial console" << std::endl;
            grub_cfg << "terminal_output serial console" << std::endl;
            grub_cfg << "set hostname=\"" << hostname << '"' << std::endl;
            //grub_cfg << "source (hd1,msdos1)/grub-env.cfg" << std::endl;
            // hd2 = primary disk(typically squashfs)
            grub_cfg << "if [ -f (hd2)/boot/grub/grub.cfg ]; then" << std::endl;
            grub_cfg << "  set root=(hd2)" << std::endl;
            grub_cfg << "  source /boot/grub/grub.cfg" << std::endl;
            grub_cfg << "elif [ -f (hd2)/system ]; then" << std::endl;
            grub_cfg << "  loopback loop (hd2)/system" << std::endl;
            grub_cfg << "  set root=loop" << std::endl;
            grub_cfg << "  source /boot/grub/grub.cfg" << std::endl;
            grub_cfg << "elif [ -f (hd2)/boot/kernel ]; then" << std::endl;
            grub_cfg << "  linux (hd2)/boot/kernel net.ifnames=0 console=ttyS0,115200n8r console=tty0 systemd.hostname=$hostname systemd.firstboot=0" << std::endl;
            grub_cfg << "  initrd (hd2)/boot/initramfs" << std::endl;
            grub_cfg << "  boot" << std::endl;
            grub_cfg << "fi" << std::endl;
        });
        std::filesystem::rename(bootimage_tmp_path, bootimage_path);
    }
    catch (...) {
        std::filesystem::remove(bootimage_tmp_path);
        throw;
    }
}

bool validate_mac_address(const std::string& mac_str)
{
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

    return true;
}

std::string get_or_generate_mac_address(const std::string& vmname, int num)
{
    std::filesystem::path cache_dir("/var/cache/vm");
    auto cache_file_path = cache_dir / vmname / (std::string("eth") + std::to_string(num));
    {
        // load from cache
        std::ifstream cache_file(cache_file_path);
        if (cache_file) {
            std::string mac_str;
            cache_file >> mac_str;
            if (validate_mac_address(mac_str)) return mac_str;
        }
    }
    //else
    char buf[3];
    auto fd = open("/dev/urandom", O_RDONLY, 0);
    if (fd < 0) throw std::runtime_error("open(/dev/urandom) failed");
    if (read(fd, buf, 3) < 3) throw std::runtime_error("read(/dev/urandom, 3) failed");
    close(fd);

    uint8_t mac[6];
    mac[0] = 0x52;
    mac[1] = 0x54;
    mac[2] = 0x00;
    mac[3] = buf[0] & 0x7f;
    mac[4] = buf[1];
    mac[5] = buf[2];

    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", (int)mac[0], (int)mac[1], (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);

    std::filesystem::create_directories(cache_file_path.parent_path());
    std::ofstream cache_file(cache_file_path);
    if (cache_file) {
        cache_file << mac_str;
    }
    return mac_str;
}

bool validate_uuid(const std::string& uuid_str)
{
    if (uuid_str.length() != 36) return false;
    auto ishex = [](char c) { return isdigit(c) || (c >= 'a' || c <= 'f'); };
    const char* format = "hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh";
    for (const char* p = format; *p ; p++) {
        char c = uuid_str[p - format];
        if (*p == 'h' && (!isdigit(c) && (c < 'a' || c > 'f'))) return false;
        else if (c != '-') return false;
    }
    return true;
}

std::string get_or_generate_uuid(const std::string& vmname)
{
    std::filesystem::path cache_dir("/var/cache/vm");
    auto cache_file_path = cache_dir / vmname / "uuid";
    {
        // load from cache
        std::ifstream cache_file(cache_file_path);
        if (cache_file) {
            std::string uuid_str;
            cache_file >> uuid_str;
            if (validate_uuid(uuid_str)) return uuid_str;
        }
    }
    //else
    uuid_t uuid;
    char uuid_str[37];
    uuid_generate(uuid);
    uuid_unparse_lower(uuid, uuid_str);

    std::filesystem::create_directories(cache_file_path.parent_path());
    std::ofstream cache_file(cache_file_path);
    if (cache_file) {
        cache_file << uuid_str;
    }
    return uuid_str;
}

void with_finally_clause(std::function<void(void)> func,std::function<void(void)> finally)
{
    try {
        func();
    }
    catch (...) {
        finally();
        throw;
    }
    finally();
}

void with_vm_lock(const std::string& vmname, std::function<void(void)> func)
{
    auto run_dir = run_root / vmname;
    std::filesystem::create_directories(run_dir);
    auto run_dir_fd = open(run_dir.c_str(), O_RDONLY, 0);
    if (run_dir_fd < 0) throw std::runtime_error(std::string("open(") + run_dir.string() + ") failed");
    if (flock(run_dir_fd, LOCK_EX|LOCK_NB) < 0) {
        close(run_dir_fd);
        if (errno == EWOULDBLOCK) throw std::runtime_error(vmname + " is already running");
        else throw std::runtime_error(std::string("flock(") + run_dir.string() + ") failed");
    }
    with_finally_clause([&func]() {
        func();
    }, [run_dir_fd]() {
        flock(run_dir_fd, LOCK_UN);
        close(run_dir_fd);
    });
}

int vm(const std::string& name)
{
    auto vm_dir = vm_root / name, run_dir = run_root / name;
    auto fs_dir = vm_dir / "fs";

    if (!std::filesystem::is_directory(vm_dir)) throw std::runtime_error("No VM found");

    // parse ini
    auto ini_path = vm_dir / "vm.ini";
    auto ini = std::shared_ptr<dictionary>(std::filesystem::exists(ini_path)? iniparser_load(ini_path.c_str()) : dictionary_new(0), iniparser_freedict);

    auto memory = iniparser_getint(ini.get(), ":memory", iniparser_getint(default_ini.get(), ":memory", 1024));
    if (memory < 256) throw std::runtime_error("Memory too less");
    auto cpus = iniparser_getint(ini.get(), ":cpu", iniparser_getint(default_ini.get(), ":cpu", 1));
    if (cpus < 1) throw std::runtime_error("Invalid cpu number");

    // load DISK config
    std::vector<std::tuple<std::filesystem::path,std::string/*format*/,bool/*readonly*/>> disks;
    for (int i = 0; i < 10; i++) {
        char buf[16];
        sprintf(buf, "disk%d", i);
        if (iniparser_find_entry(ini.get(), buf) == 0) continue;
        //else
        sprintf(buf, "disk%d:path", i);
        std::filesystem::path path = iniparser_getstring(ini.get(), buf, (vm_dir / (std::string("disk") + std::to_string(i))).c_str() );
        if (path.is_relative()) {
            path = vm_dir / path;
        }
        if (!std::filesystem::exists(path)) {
            std::cerr << "Specified path '" << path << "' for disk" << i << " does not exist. ignored." << std::endl;
            continue;
        }
        sprintf(buf, "disk%d:format", i);
        auto format = iniparser_getstring(ini.get(), buf, "raw");

        sprintf(buf, "disk%d:readonly", i);
        bool readonly = (bool)iniparser_getboolean(ini.get(), buf, 0);
        disks.push_back({path, format, readonly});
    }

    // load NIC config
    std::vector<std::tuple<std::optional<std::string>/*bridge*/,std::optional<std::string>/*mac*/>> nics;
    for (int i = 0; i < 10; i++) {
        char buf[16];
        sprintf(buf, "net%d", i);
        if (iniparser_find_entry(ini.get(), buf) == 0) continue;
        //else
        sprintf(buf, "net%d:bridge", i);
        auto bridge = iniparser_getstring(ini.get(), buf, i == 0? default_bridge : NULL);
        if (bridge && !std::filesystem::exists(std::filesystem::path("/sys/class/net") / bridge / "bridge")) {
            std::cerr << "Bridge interface '" << bridge << "' does not exist. network interface ignored." << std::endl;
            continue;
        }
        sprintf(buf, "net%d:mac", i);
        auto mac = iniparser_getstring(ini.get(), buf, NULL);
        if (mac && !validate_mac_address(mac)) {
            std::cerr << "MAC address '" << mac << "' invalid. network interface ignored." << std::endl;
            continue;
        }
        nics.push_back({bridge? std::optional(bridge) : std::nullopt, mac? std::optional(mac) : std::nullopt});
    }
    if (nics.size() == 0) {
        nics.push_back({default_bridge? std::optional(default_bridge) : std::nullopt, std::nullopt});
    }

    // load display setting
    auto display = iniparser_getstring(ini.get(), ":display", iniparser_getstring(default_ini.get(), ":display", NULL)); /*sdl,curses,none,gtk,vnc,egl-headless,spice-app*/
    auto vnc = iniparser_getstring(ini.get(), ":vnc", iniparser_getstring(default_ini.get(), ":vnc", NULL)); // VNC options passed to QEMU
    if (vnc && !display) display = "vnc";  // choose VNC display automatically when vnc option is specified

    // rng
    bool hwrng = iniparser_getboolean(ini.get(), ":hwrng", iniparser_getboolean(default_ini.get(), ":hwrng", 0));

    // rtc
    auto rtc = iniparser_getstring(ini.get(), ":rtc", iniparser_getstring(default_ini.get(), ":rtc", NULL));

    // virtiofsd setting
    auto virtiofsd_cache = iniparser_getstring(ini.get(), "virtiofsd:cache", iniparser_getstring(default_ini.get(), "virtiofsd:cache", "none"));
    auto virtiofsd_modcaps = iniparser_getstring(ini.get(), "virtiofsd:modcaps", iniparser_getstring(default_ini.get(), "virtiofsd:modcaps", "+sys_admin"));

    std::filesystem::create_directories(fs_dir);

    auto virtiofs_sock = run_dir / "virtiofs.sock";
    auto monitor_sock = run_dir / "monitor.sock";
    auto qmp_sock = run_dir / "qmp.sock";
    auto serial_sock = run_dir / "serial.sock";

    std::vector<std::string> virtiofsd_cmdline = {
        "/usr/libexec/virtiofsd","-f","-o","cache=" + std::string(virtiofsd_cache) + ",log_level=" + std::string(debug? "debug" : "warn") 
            + ",xattr,modcaps=" + std::string(virtiofsd_modcaps) + ",allow_root,allow_direct_io,posix_lock,flock",
        /*"--syslog",*/
        "-o", std::string("source=") + fs_dir.string(),
        std::string("--socket-path=") + virtiofs_sock.string()
    };

    std::vector<std::string> qemu_cmdline = {
        "qemu-system-x86_64","-enable-kvm","-M","q35",//"-rtc","base=utc,clock=rt",
        "-m", std::to_string(memory),
        "-smp", "cpus=" + std::to_string(cpus), 
        "-uuid", get_or_generate_uuid(name), 
        "-object", std::string("memory-backend-memfd,id=mem,size=") + std::to_string(memory) + "M,share=on", "-numa", "node,memdev=mem",
        "-chardev", std::string("socket,id=char0,path=") + virtiofs_sock.string(),
        "-monitor", std::string("unix:") + monitor_sock.string() + ",server,nowait",
        "-serial", std::string("unix:") + serial_sock.string() + ",server,nowait",
        "-qmp", std::string("unix:") + qmp_sock.string() + ",server,nowait"
    };

    if (rtc) {
        qemu_cmdline.push_back("-rtc");
        qemu_cmdline.push_back(rtc);
    }

    std::filesystem::path hwrng_path("/dev/hwrng");
    if (hwrng && std::filesystem::exists(hwrng_path) && std::filesystem::is_character_file(hwrng_path)) {
        qemu_cmdline.push_back("-object");
        qemu_cmdline.push_back(std::string("rng-random,filename=") + hwrng_path.string() + ",id=rng0");
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000");
    } else {
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("virtio-rng-pci");
    }

    auto system_image = vm_dir / "system", data_image = vm_dir / "data", swapfile = vm_dir / "swapfile", cdrom = vm_dir / "cdrom";
    bool has_system_image = std::filesystem::exists(system_image);
    bool has_data_image = std::filesystem::exists(data_image);

    std::vector<std::filesystem::path> kernel_candidates = {fs_dir / "boot" / "kernel", fs_dir / "boot" / "vmlinuz"};
    auto kernel = std::find_if(kernel_candidates.begin(), kernel_candidates.end(), [](const auto& path) {return std::filesystem::exists(path);});

    auto boot_from_cdrom = std::filesystem::exists(cdrom); // TODO: check if media is loaded for real drive

    auto boot_from_fs = !boot_from_cdrom && !has_system_image && !has_data_image && kernel != kernel_candidates.end();
    qemu_cmdline.push_back("-device");
    qemu_cmdline.push_back(std::string("vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=") + (boot_from_fs? "/dev/root" : "fs")); //,cache-size=") + std::to_string(memory) + "M");

    std::optional<std::filesystem::path> boot_image = std::nullopt;

    if (boot_from_fs) {
        qemu_cmdline.push_back("-kernel");
        qemu_cmdline.push_back(*kernel);
        qemu_cmdline.push_back("-append");
        qemu_cmdline.push_back("root=/dev/root rootfstype=virtiofs _rootflags=dax rw net.ifnames=0 console=ttyS0,115200n8r console=tty0 systemd.hostname=" + name);
    } else if (boot_from_cdrom) {
        qemu_cmdline.push_back("-cdrom");
        qemu_cmdline.push_back(cdrom.string());
        qemu_cmdline.push_back("-boot");
        qemu_cmdline.push_back("once=d");
    } else if (has_system_image || has_data_image) {
        boot_image = run_dir / "boot.img";
        qemu_cmdline.push_back("-drive");
        qemu_cmdline.push_back(std::string("file=") + boot_image.value().string() + ",format=raw,index=0,media=disk");
        qemu_cmdline.push_back("-drive");
        qemu_cmdline.push_back( std::string("file=fat:rw:") + run_dir.string() + ",format=raw,index=1,media=disk");
    }

    int disk_idx = 0;
    if (!boot_from_cdrom) {
        if (has_system_image) {
            qemu_cmdline.push_back("-drive");
            qemu_cmdline.push_back(std::string("file=") + system_image.string() + ",format=raw,index=" + std::to_string(disk_idx++) + ",readonly=on,media=disk,if=virtio,aio=native,cache.direct=on,readonly=on");
        }
        if (has_data_image) {
            qemu_cmdline.push_back("-drive");
            qemu_cmdline.push_back(std::string("file=") + data_image.string() + ",format=raw,index=" + std::to_string(disk_idx++) + ",media=disk,if=virtio,aio=native,cache.direct=on");
        }
        if (std::filesystem::exists(swapfile)) {
            qemu_cmdline.push_back("-drive");
            qemu_cmdline.push_back(std::string("file=") + swapfile.string() + ",format=raw,index=" + std::to_string(disk_idx++) + ",media=disk,if=virtio,aio=native,cache.direct=on");
        }
    }

    for (const auto& i:disks) {
        qemu_cmdline.push_back("-drive");
        qemu_cmdline.push_back(std::string("file=") + std::get<0>(i).string() + ",format=" + std::get<1>(i) + ",index=" + std::to_string(disk_idx++) 
            + ",readonly=" + (std::get<2>(i)? "on" : "off")
            + ",media=disk,if=virtio,aio=native,cache.direct=on");
    }

    if (!boot_from_fs && disk_idx == 0) throw std::runtime_error("No bootable disk for " + name + ".");

    int nic_idx = 0;
    for (const auto& nic:nics) {
        auto bridge = std::get<0>(nic);
        if (bridge.has_value()) {
            qemu_cmdline.push_back("-netdev");
            qemu_cmdline.push_back("bridge,br=" + bridge.value() + ",id=net" + std::to_string(nic_idx));
        } else {
            qemu_cmdline.push_back("-netdev");
            qemu_cmdline.push_back("user,id=net" + std::to_string(nic_idx));
        }
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("virtio-net-pci,romfile=,netdev=net" + std::to_string(nic_idx) + ",mac=" + std::get<1>(nic).value_or(get_or_generate_mac_address(name, nic_idx)));
        nic_idx++;
    }

    if (display) {
        qemu_cmdline.push_back("-vga");
        qemu_cmdline.push_back("virtio");
        qemu_cmdline.push_back("-display");
        qemu_cmdline.push_back(display);
        qemu_cmdline.push_back("-usb");
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("usb-tablet");
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("virtio-keyboard");
    } else {
        qemu_cmdline.push_back("-nographic");
    }
    if (vnc) {
        qemu_cmdline.push_back("-vnc");
        qemu_cmdline.push_back(vnc);
    }

    with_vm_lock(name, [&]() {
        if (boot_image.has_value() && !std::filesystem::exists(boot_image.value())) {
            std::cout << "Boot image file does not exist.  Creating..." << std::endl;
            create_bootimage(boot_image.value(), name);
        }

        std::cout << "Starting " << name << std::endl;

        int sigfd = -1;
        pid_t virtiofsd_pid = 0;
        pid_t qemu_pid = 0;
        time_t qemu_first_shutdown_signaled_time = -1L, qemu_last_shutdown_signaled_time = -1L;

        with_finally_clause([&]() {
            virtiofsd_pid = fork([&virtiofsd_cmdline]() {
                sigset_t mask;
                sigemptyset (&mask);
                sigaddset (&mask, SIGINT);
                sigprocmask(SIG_SETMASK, &mask, NULL);
                exec(virtiofsd_cmdline);
            });
            std::cout << "Virtiofsd started." << std::endl;

            qemu_pid = fork([&qemu_cmdline]() {
                sigset_t mask;
                sigemptyset (&mask);
                sigaddset (&mask, SIGINT);
                sigprocmask(SIG_SETMASK, &mask, NULL);
                exec(qemu_cmdline);
            });
            std::cout << "QEMU started." << std::endl;

            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGINT);
            sigaddset(&mask, SIGTERM);
            sigaddset(&mask, SIGCHLD);
            sigaddset(&mask, SIGHUP);
            sigprocmask(SIG_SETMASK, &mask, NULL);
            sigfd = signalfd (-1, &mask, SFD_CLOEXEC);
            if (sigfd < 0) throw std::runtime_error("signalfd() failed");

            bool qemu_ready_notified = false;
            struct pollfd pollfds[1];
            pollfds[0].fd = sigfd;
            pollfds[0].events = POLLIN;

            int r;
            while (r = poll(pollfds, 1, qemu_ready_notified? 1000 : 100) >= 0) {
                if (pollfds[0].revents & POLLIN) {
                    struct signalfd_siginfo info;
                    if (read(pollfds[0].fd, &info, sizeof(info)) != sizeof(info)) 
                        throw std::runtime_error(std::string("read(sigal fd) failed: ") + strerror(errno));
                    //else
                    if ((info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) && qemu_last_shutdown_signaled_time < 0) {
                        sd_notify(0, "STOPPING=1");
                        std::cout << "Terminating QEMU..." << std::endl;
                        send_qmp_command(qmp_sock, "{ \"execute\": \"system_powerdown\"}");
                        qemu_first_shutdown_signaled_time = qemu_last_shutdown_signaled_time = time(NULL);
                    }
                    if (info.ssi_signo == SIGHUP) {
                        sd_notify(0, "RELOADING=1");
                        send_qmp_command(qmp_sock, "{ \"execute\": \"system_reset\"}");
                    }
                    if (info.ssi_signo == SIGCHLD) {
                        if (info.ssi_pid == virtiofsd_pid) {
                            std::cout << "Virtiofsd terminated." << std::endl;
                            virtiofsd_pid = 0;
                        }
                        if (info.ssi_pid == qemu_pid) {
                            std::cout << "QEMU terminated." << std::endl;
                            qemu_pid = 0;
                            break;
                        }
                    }
                }

                if (!qemu_ready_notified 
                    && std::filesystem::exists(monitor_sock) && std::filesystem::is_socket(monitor_sock)
                    && std::filesystem::exists(qmp_sock) && std::filesystem::is_socket(qmp_sock)
                    && std::filesystem::exists(serial_sock) && std::filesystem::is_socket(serial_sock)) {
                    std::cout << "QEMU is ready(notified to systemd)." << std::endl;
                    sd_notify(0, "READY=1");
                    qemu_ready_notified = true;
                }

                auto now = time(NULL);
                if (qemu_first_shutdown_signaled_time >= 0 && now - qemu_first_shutdown_signaled_time > 180) {
                    std::cout << "Force terminating QEMU..." << std::endl;
                    send_qmp_command(qmp_sock, "{ \"execute\": \"quit\"}");
                    qemu_first_shutdown_signaled_time = now;
                } else if (qemu_last_shutdown_signaled_time >= 0 && now - qemu_last_shutdown_signaled_time > 5) {
                    std::cout << "Re-sending shutdown signal to QEMU..." << std::endl;
                    send_qmp_command(qmp_sock, "{ \"execute\": \"system_powerdown\"}");
                    qemu_last_shutdown_signaled_time = now;
                }
            }
            if (r < 0) throw std::runtime_error("poll() failed");
        }, [&]()/*finally*/ {
            if (sigfd >= 0) close(sigfd);

            if (qemu_pid > 0) {
                std::cout << "Terminating QEMU..." << std::endl;
                kill(qemu_pid, SIGTERM);
            }

            if (virtiofsd_pid > 0) {
                std::cout << "Terminating virtiofsd..." << std::endl;
                kill(virtiofsd_pid, SIGTERM);
            }
            wait(NULL);
        });
    });

    return 0;
}

std::pair<pid_t,int> forkpty(std::function<void(void)> func,const std::optional<std::pair<unsigned short,unsigned short>>& winsiz = std::nullopt)
{
    int fd;
    struct winsize win = { (unsigned short)25, (unsigned short)80, 0, 0 };
    if (winsiz.has_value()) {
        win.ws_col = winsiz.value().first;
        win.ws_row = winsiz.value().second;
    }
    auto pid = forkpty(&fd, NULL, NULL, &win);
    if (pid < 0) throw std::runtime_error("forkpty() failed");
    if (pid > 0) return {pid, fd};

    //else(child process)
    try {
        func();
    }
    catch (...) {
        // jumping across scope border in forked process may not be a good idea.
    }
    _exit(-1);
}

std::pair<int,std::set<int>/*fds to close*/> poll(const std::map<std::pair<int/*fd*/,short/*event*/>,std::function<bool(int)>>& pollfds, int timeout)
{
    std::map<int,short> fdmap;
    for (const auto& i:pollfds) {
        if (fdmap.find(i.first.first) == fdmap.end()) fdmap[i.first.first] = i.first.second;
        else fdmap[i.first.first] |= i.first.second;
    }

    struct pollfd c_pollfds[fdmap.size()];
    int idx = 0;
    for (const auto& i:fdmap) {
        c_pollfds[idx].fd = i.first;
        c_pollfds[idx].events = i.second;
        idx++;
    }
    int r = poll(c_pollfds, pollfds.size(), timeout);
    if (r < 0) throw std::runtime_error("poll() failed");

    std::set<int> fds_to_close;
    for (int i = 0; i < fdmap.size(); i++) {
        auto fd = c_pollfds[i].fd;
        if (c_pollfds[i].revents & POLLIN) {
            auto func = pollfds.find({fd, POLLIN});
            if (func != pollfds.end()) {
                if (func->second(fd)) fds_to_close.insert(fd);
            }
        }
        if (c_pollfds[i].revents & POLLOUT) {
            auto func = pollfds.find({fd, POLLOUT});
            if (func != pollfds.end()) {
                if (func->second(fd)) fds_to_close.insert(fd);
            }
        }
    }
    return {r, fds_to_close};
}

int vm_nspawn(const std::string& name)
{
    auto vm_dir = vm_root / name, run_dir = run_root / name;
    auto fs_dir = vm_dir / "fs";
    if (!std::filesystem::is_directory(vm_dir)) throw std::runtime_error("No VM found");
    auto ini_path = vm_dir / "vm.ini";
    auto ini = std::shared_ptr<dictionary>(std::filesystem::exists(ini_path)? iniparser_load(ini_path.c_str()) : dictionary_new(0), iniparser_freedict);
    auto bridge = iniparser_getstring(ini.get(), "net0:bridge", default_bridge);

    struct utsname u_name;
    if (uname(&u_name) < 0) throw std::runtime_error("uname() failed");

    std::vector<std::string> nspawn_cmdline = {"systemd-nspawn", "-b", std::string("--hostname=") + name, "--register=no",
            "--uuid=" + get_or_generate_uuid(name), 
            "--capability=CAP_SYS_MODULE", std::string("--bind-ro=/lib/modules/") + u_name.release, "--bind-ro=/sys/module/"};
    if (bridge) {
        nspawn_cmdline.push_back(std::string("--network-bridge=") + bridge);
    }

    auto serial_sock = run_dir / "serial.sock";
    auto system_image = vm_dir / "system";
    std::filesystem::create_directories(fs_dir);

    if (std::filesystem::exists(system_image)) {
        nspawn_cmdline.push_back("-i");
        nspawn_cmdline.push_back(system_image);
        nspawn_cmdline.push_back(std::string("--overlay=+/:") + fs_dir.string() + ":/");
    } else {
        nspawn_cmdline.push_back("-D");
        nspawn_cmdline.push_back(fs_dir);
    }

    nspawn_cmdline.push_back("systemd.firstboot=0");

    if (debug) {
        for (auto i:nspawn_cmdline) { std::cout << i << ' '; }
        std::cout << std::endl;
    }
    with_vm_lock(name, [&]() {
        int sigfd = -1;
        pid_t nspawn_pid = 0;
        int nspawn_fd = -1;
        int serial_server_fd = -1;
        int serial_client_fd = -1;

        time_t nspawn_first_shutdown_signaled_time = -1L, nspawn_last_shutdown_signaled_time = -1L;

        with_finally_clause([&](){
            auto pid_and_fd = forkpty([&nspawn_cmdline]() {
                setenv("TERM", "xterm-256color", 1);
                exec(nspawn_cmdline);
            }, std::make_pair(80, 25));
            nspawn_pid = pid_and_fd.first;
            nspawn_fd = pid_and_fd.second;

            std::cout << "systemd-nspawn started." << std::endl;

            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGINT);
            sigaddset(&mask, SIGTERM);
            sigaddset(&mask, SIGCHLD);
            sigaddset(&mask, SIGHUP);
            sigprocmask(SIG_SETMASK, &mask, NULL);
            sigfd = signalfd (-1, &mask, SFD_CLOEXEC);
            if (sigfd < 0) throw std::runtime_error("signalfd() failed");

            serial_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (serial_server_fd < 0) throw std::runtime_error("Unable to create socket for listening");
            //else
            struct sockaddr_un sockaddr;
            memset(&sockaddr, 0, sizeof(sockaddr));
            sockaddr.sun_family = AF_UNIX;
            if (std::filesystem::exists(serial_sock)) std::filesystem::remove(serial_sock);
            strcpy(sockaddr.sun_path, serial_sock.c_str());
            if (bind(serial_server_fd, (const struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
                throw std::runtime_error("Unable to bind socket");
            }
            if (listen(serial_server_fd, 10) < 0) throw std::runtime_error("Unable to listen socket");
            sd_notify(0, "READY=1");

            while (true) {
                std::map<std::pair<int,short>,std::function<bool(int)>> events;
                events[{sigfd, POLLIN}] = [&nspawn_pid,&nspawn_first_shutdown_signaled_time,&nspawn_last_shutdown_signaled_time](int fd) {
                    struct signalfd_siginfo info;
                    if (read(fd, &info, sizeof(info)) != sizeof(info)) 
                        throw std::runtime_error(std::string("read(sigal fd) failed: ") + strerror(errno));
                    //else
                    if ((info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) && nspawn_last_shutdown_signaled_time < 0) {
                        sd_notify(0, "STOPPING=1");
                        std::cout << "Terminating systemd-nspawn..." << std::endl;
                        kill(nspawn_pid, SIGTERM);
                        nspawn_first_shutdown_signaled_time = nspawn_last_shutdown_signaled_time = time(NULL);
                    }
                    if (info.ssi_signo == SIGCHLD) {
                        std::cout << "systemd-nspawn terminated." << std::endl;
                        nspawn_pid = 0;
                    }
                    return false;
                };
                events[{serial_server_fd, POLLIN}] = [&serial_client_fd](int fd) {
                    int sock = accept(fd, NULL, NULL);
                    if (sock >= 0) {
                        if (serial_client_fd < 0) {
                            serial_client_fd = sock;
                            //std::cout << "Peer accepted." << std::endl;
                        } else {
                            const char* msg = "Simultaneous connections are not allowed\n";
                            write(sock, msg, strlen(msg));
                            close(sock);
                        }
                    }
                    return false;
                };
                if (nspawn_fd) events[{nspawn_fd, POLLIN}] = [&serial_client_fd](int fd) {
                    char buf[1024];
                    auto r = read(fd, buf, sizeof(buf));
                    if (r <= 0) return true;
                    //else
                    write(serial_client_fd, buf, r);
                    return false;
                };
                if (serial_client_fd) events[{serial_client_fd, POLLIN}] = [&nspawn_fd](int fd) {
                    char buf[1024];
                    auto r = read(fd, buf, sizeof(buf));
                    if (r <= 0) return true;
                    //else
                    write(nspawn_fd, buf, r);
                    return false;
                };
                auto r = poll(events, 1000);
                if (r.second.find(serial_client_fd) != r.second.end()) {
                    close(serial_client_fd);
                    serial_client_fd = -1;
                }
                if (r.second.find(nspawn_fd) != r.second.end()) {
                    close(nspawn_fd);
                    nspawn_fd = -1;
                }
                if (nspawn_pid == 0) break;

                auto now = time(NULL);
                if (nspawn_first_shutdown_signaled_time >= 0 && now - nspawn_first_shutdown_signaled_time > 180) {
                    std::cout << "Force terminating systemd-nspawn..." << std::endl;
                    if (nspawn_fd >= 0) write(nspawn_fd, "\x1d\x1d", 2);
                    else break;
                    nspawn_first_shutdown_signaled_time = now;
                } else if (nspawn_last_shutdown_signaled_time >= 0 && now - nspawn_last_shutdown_signaled_time > 5) {
                    std::cout << "Re-sending shutdown signal to systemd-nspawn..." << std::endl;
                    kill(nspawn_pid, SIGTERM);
                    nspawn_last_shutdown_signaled_time = now;
                }
            }
        }, [&]()/*finally*/ {
            if (sigfd >= 0) close(sigfd);
            if (nspawn_fd >= 0) close(nspawn_fd);
            if (serial_server_fd >= 0) close(serial_server_fd);
            if (serial_client_fd >= 0) close(serial_client_fd);
            if (std::filesystem::exists(serial_sock)) std::filesystem::remove(serial_sock);
            if (nspawn_pid > 0) kill(nspawn_pid, SIGKILL);
            wait(NULL);
        });
    });

    return 0;
}

void usage(const std::string& progname)
{
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << progname << ' ' << "vmname" << std::endl;
}

static std::function<int(void)> get_vm_func(const std::string& name)
{
    auto ini_path = vm_root / name / "vm.ini";
    auto ini = std::shared_ptr<dictionary>(std::filesystem::exists(ini_path)? iniparser_load(ini_path.c_str()) : dictionary_new(0), iniparser_freedict);
    std::string type = iniparser_getstring(ini.get(), ":type", "qemu");
    if (type == "qemu") return [name]() -> int { return vm(name); };
    else if (type == "nspawn") return [name]() -> int { return vm_nspawn(name); };
    else throw std::runtime_error("Unknown VM type: " + type);
}

static int _main(int argc, char* argv[])
{
    const std::string progname = argv[0];
    auto args = getopt(argc, argv, {
        {std::nullopt, "debug", []() {
            debug = true;
        }},
        {'h', "help", [&progname]() {
            usage(progname);
            exit(-1);
        }},
        {'v', "version", []() {
            std::cout << "vm 0.1" << std::endl;
            exit(-1);
        }},
    });

    if (args.size() != 1) {
        usage(argv[0]);
        exit(-1);
    }

    try {
        return get_vm_func(args[0])();
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        exit(-1);
    }
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[])
{
    return _main(argc, argv);
}
#endif
