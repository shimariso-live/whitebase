#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>

#include <iostream>
#include <filesystem>
#include <fstream>

#include <uuid/uuid.h>

#include "volume.h"
#include "vm_op.h"

bool is_running(const std::string& vmname)
{
    auto run_vm = run_root / vmname;
    auto serial_sock = run_vm / "serial.sock";
    if (!std::filesystem::exists(serial_sock) || !std::filesystem::is_socket(serial_sock)) return false;
    auto fd = open(run_vm.c_str(), O_RDONLY, 0);
    if (fd < 0) return false;
    bool running = (flock(fd, LOCK_EX|LOCK_NB) < 0 && errno == EWOULDBLOCK);
    close(fd);
    return running;
}

bool is_autostart(const std::string& vmname)
{
    std::filesystem::path multi_user_target_wants("/etc/systemd/system/multi-user.target.wants");
    return std::filesystem::exists(multi_user_target_wants / (std::string("vm@") + vmname + ".service"));
}

void set_autostart(const std::string& vmname, bool autostart)
{
    check_call({"systemctl", autostart? "enable" : "disable", std::string("vm@") + vmname});
}

void for_each_running_vm(std::function<void(const std::string&)> func)
{
    if (!std::filesystem::exists(run_root) || !std::filesystem::is_directory(run_root)) return;
    //else
    for (const auto& d : std::filesystem::directory_iterator(run_root)) {
        auto name = d.path().filename().string();
        if (!is_running(name)) continue;
        func(name);
    }
}

static std::optional<std::string> get_volume_name_from_vm_name(const std::string& vmname)
{
    auto vm_dir = vm_root / vmname;
    if (!std::filesystem::exists(vm_dir) || !std::filesystem::is_directory(vm_dir)) {
        throw std::runtime_error(vmname + " does not exist");
    }
    if (!std::filesystem::is_symlink(vm_dir)) return std::nullopt;
    auto symlink = std::filesystem::read_symlink(vm_dir);

    auto real_vm_dir = symlink.is_relative()? (vm_dir.parent_path() / std::filesystem::read_symlink(vm_dir)) : symlink;
    auto volume_dir = real_vm_dir.parent_path();
    auto volume_name = volume_dir.filename().string();
    if (volume_name[0] != '@') return std::nullopt; // not a volume path
    volume_name.replace(volume_name.begin(), volume_name.begin() + 1, ""); // remove '@'
    auto volume_dir_should_be = get_volume_dir(volume_name);
    if (!volume_dir_should_be) return std::nullopt;
    return (volume_dir_should_be == volume_dir)? std::make_optional(volume_name) : std::nullopt;
}

std::map<std::string,VM> list_vm()
{
    std::map<std::string,VM> vms;

    // for each defined VM
    if (std::filesystem::exists(vm_root) && std::filesystem::is_directory(vm_root)) {
        for (const auto& d : std::filesystem::directory_iterator(vm_root)) {
            if (!d.is_directory()) continue;
            auto name = d.path().filename().string();
            if (name[0] == '@') continue;
            //else
            VM vm;
            // todo: read ini
            vm.volume = get_volume_name_from_vm_name(name);
            vm.autostart = is_autostart(name);
            vms[name] = vm;
        }
    }

    for_each_running_vm([&vms](const std::string& name) {
        std::optional<uint16_t> cpu = std::nullopt;
        std::optional<uint32_t> memory = std::nullopt;
        std::optional<std::string> ip_address = std::nullopt;
        try {
            // query qmp https://qemu-project.gitlab.io/qemu/interop/qemu-qmp-ref.html
            memory = with_qmp_session<std::optional<uint32_t>>(name, [](int fd) {
                write(fd, "{\"execute\":\"query-memory-size-summary\"}\r\n");
                return with_return_value<std::optional<std::uint32_t>>(fd, [](auto val) {
                    return with_object_property<uint32_t>(val, "base-memory", [](const yajl_val val) {
                        return (YAJL_IS_INTEGER(val))? std::make_optional((uint32_t)(YAJL_GET_INTEGER(val) / 1024 / 1024)) : std::nullopt;
                    });
                });
            }, []() {
                return std::nullopt;
            });

            // query qga https://wiki.qemu.org/Features/GuestAgent https://qemu-project.gitlab.io/qemu/interop/qemu-ga-ref.html
            auto rst = with_qga<std::tuple<std::optional<uint16_t>/*cpu*/,std::optional<std::string>/*ip_address*/>>(name, [](int fd) {
                write(fd, "{\"execute\":\"guest-get-osinfo\"}\r\n");
                auto os_info = read_json_object(fd);
                auto kernel_ver = with_object_property<std::string>(os_info.get(), "return", [](const yajl_val val) {
                    return with_object_property<std::string>(val, "kernel-release", [](const yajl_val val) {
                        return YAJL_IS_STRING(val)? std::make_optional(val->u.string) : std::nullopt;
                    });
                });
                write(fd, "{\"execute\":\"guest-get-vcpus\"}\r\n");
                auto vcpus = read_json_object(fd);
                auto cpu = with_object_property<uint16_t>(vcpus.get(), "return", [](const yajl_val val) -> std::optional<uint16_t> {
                    if (!YAJL_IS_ARRAY(val)) return std::nullopt;
                    uint16_t cnt = 0;
                    for (int i = 0; i < val->u.array.len; i++) {
                        auto item = val->u.array.values[i];
                        auto online = with_object_property<bool>(item, "online", [](const yajl_val val) -> std::optional<bool> {
                            return YAJL_IS_TRUE(val) ? true : false;
                        });
                        if (online.value_or(false)) cnt++;
                    }
                    return cnt;
                });
                write(fd, "{\"execute\":\"guest-network-get-interfaces\"}\r\n");
                auto network_interfaces = read_json_object(fd);
                // {"return": [{"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8}, {"ip-address-type": "ipv6", "ip-address": "::1", "prefix": 128}], "statistics": {"tx-packets": 40, "tx-errs": 0, "rx-bytes": }
                //{"name": "eth0", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "192.168.62.81", "prefix": 24}, {"ip-address-type": "ipv6", "ip-address": "2409:11:8720:2100:216:3eff:fe00:ccbe", "prefix": 64}, {"ip-address-type": "ipv6", "ip-address": "fe80::216:3eff:fe00:ccbe", "prefix": 64}]
                auto ip_address = with_object_property<std::string>(network_interfaces.get(), "return", [](const yajl_val val) -> std::optional<std::string> {
                    if (!YAJL_IS_ARRAY(val)) return std::nullopt;
                    for (int i = 0; i < val->u.array.len; i++) {
                        auto item = val->u.array.values[i];
                        if (!YAJL_IS_OBJECT(item)) continue;
                        auto ifname = with_object_property<std::string>(item, "name", [](const yajl_val val) { 
                            return YAJL_IS_STRING(val)? std::make_optional<std::string>(val->u.string) : std::nullopt; 
                        });
                        if (!ifname.has_value() || ifname == "lo") continue;
                        auto ip_address = with_object_property<std::string>(item, "ip-addresses", [](const yajl_val val) -> std::optional<std::string> {
                            if (!YAJL_IS_ARRAY(val)) return std::nullopt;
                            for (int i = 0; i < val->u.array.len; i++) {
                                auto item = val->u.array.values[i];
                                auto ip_address_type = with_object_property<std::string>(item, "ip-address-type", [](const yajl_val val) {
                                    return YAJL_IS_STRING(val)? std::make_optional<std::string>(val->u.string) : std::nullopt;
                                });
                                if (ip_address_type != "ipv4") continue;
                                auto ip_address = with_object_property<std::string>(item, "ip-address", [](const yajl_val val) {
                                    return YAJL_IS_STRING(val)? std::make_optional<std::string>(val->u.string) : std::nullopt;
                                });
                                return ip_address;
                            }
                            return std::nullopt;
                        });
                        if (ip_address.has_value()) return ip_address;
                    }
                    return std::nullopt;
                });
                return std::make_tuple(cpu, ip_address);
            }, []() {
                // do nothing when QGA socket is not available
                return std::make_tuple(std::nullopt,std::nullopt);
            });
            cpu = std::get<0>(rst);
            ip_address = std::get<1>(rst);
        }
        catch (const std::runtime_error& ex) {
            std::cerr << ex.what() << std::endl;
        }
        VM& vm = vms[name];
        vm.running = true;
        vm.cpu = cpu;
        vm.memory = memory;
        vm.ip_address = ip_address;
    });
    return vms;
}

int create_vm(const std::string& vmname, const std::string& volume, int data_partition)
{
    auto vm_dir = vm_root / vmname;
    if (std::filesystem::exists(vm_dir)) {
        throw std::runtime_error(vmname + " already exists");
    }

    auto volume_dir = get_volume_dir(volume, [](auto name) -> std::filesystem::path {throw std::runtime_error("Volume " + name + " does not exist");});
    auto volume_vm_dir = volume_dir / vmname;
    if (std::filesystem::exists(volume_vm_dir)) {
        throw std::runtime_error(vmname + " already exists on volume " + volume);
    }

    try {
        auto fs_dir = volume_vm_dir / "fs";
        std::filesystem::create_directories(fs_dir);
        check_call({"cp", "-a", "/usr/share/wb/stubvm/.", fs_dir.string()});
        if (data_partition > 0) {
            std::string size_str = std::to_string(data_partition) + "G";
            check_call({"truncate", "-s", size_str, volume_vm_dir / "data"});
        }

        auto _home = getenv("HOME");
        if (_home) {
            std::filesystem::path home(_home);
            auto src_ssh_dir = home / ".ssh";
            auto dest_authorized_keys = fs_dir / ".stubroot" / "root" / ".ssh" / "authorized_keys";

            auto append_file = [](const std::filesystem::path& src, const std::filesystem::path& dst) {
                if (!std::filesystem::exists(src) || !std::filesystem::is_regular_file(src)) return false;
                // else
                std::ifstream in(src);
                if (!in) return false;
                // else
                std::ofstream out(dst, std::ios_base::app);
                if (!out) return false;
                // else
                std::string line;
                while (std::getline(in, line)) {
                    if (line != "") out << line << std::endl;
                }
                return true;
            };

            append_file(src_ssh_dir / "authorized_keys", dest_authorized_keys);
            append_file(src_ssh_dir / "id_rsa.pub", dest_authorized_keys);
        }
        std::filesystem::create_directory_symlink(std::filesystem::path("@" + volume) / vmname, vm_dir);
    }
    catch (...) {
        std::filesystem::remove_all(volume_vm_dir);
        throw;
    }

    return 0;
}

int delete_vm(const std::string& vmname)
{
    auto vm_dir = vm_root / vmname;
    if (!std::filesystem::exists(vm_dir) || !std::filesystem::is_directory(vm_dir)) {
        throw std::runtime_error(vmname + " does not exist");
    }

    if (!std::filesystem::is_symlink(vm_dir)) {
        throw std::runtime_error(vmname + " cannot be deleted.  Delete " + vm_dir.string() + " manually.");
    }

    auto symlink = std::filesystem::read_symlink(vm_dir);

    auto real_vm_dir = symlink.is_relative()? (vm_dir.parent_path() / std::filesystem::read_symlink(vm_dir)) : symlink;
    auto volume_dir = real_vm_dir.parent_path();
    auto volume_name = volume_dir.filename().string();
    if (volume_name[0] != '@') throw std::runtime_error(volume_dir.string() + " is not a volume path");
    volume_name.replace(volume_name.begin(), volume_name.begin() + 1, ""); // remove '@'
    auto volume_dir_should_be = get_volume_dir(volume_name, [](auto name) -> std::filesystem::path {
        throw std::runtime_error("Volume " + name + " does not exist");
    });
    if (volume_dir_should_be != volume_dir) {
        throw std::runtime_error("Symlink " + vm_dir.string() + "(points " + real_vm_dir.string() + ") does not point VM dir right under volume");
    }

    if (is_running(vmname)) throw std::runtime_error(vmname + " is running");

    set_autostart(vmname, false);
    std::filesystem::remove(vm_dir);  // remove symlink
    
    // move vm real dir to trash
    uuid_t uuid;
    char uuid_str[37];
    uuid_generate(uuid);
    uuid_unparse_lower(uuid, uuid_str);
    auto trash_dir = volume_dir / ".trash";
    std::filesystem::create_directories(trash_dir);
    std::filesystem::rename(real_vm_dir, trash_dir / (vmname + '.' + uuid_str));

    return 0;
}
