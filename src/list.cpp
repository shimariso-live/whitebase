#include <iostream>
#include <libsmartcols/libsmartcols.h>

#include "common.h"
#include "wb.h"
#include "list.h"
#include "volume.h"

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

std::map<std::string,VM> list()
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

int list(const std::vector<std::string>& args)
{
    auto vms = list();

    std::shared_ptr<libscols_table> table(scols_new_table(), scols_unref_table);
    if (!table) throw std::runtime_error("scols_new_table() failed");
    scols_table_new_column(table.get(), "RUNNING", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "NAME", 0.1, 0);
    scols_table_new_column(table.get(), "VOLUME", 0.1, 0);
    scols_table_new_column(table.get(), "AUTOSTART", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "CPU", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "MEMORY", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "IP ADDRESS", 0.1, SCOLS_FL_RIGHT);
    auto sep = scols_table_new_line(table.get(), NULL);
    scols_line_set_data(sep, 0, "-------");
    scols_line_set_data(sep, 1, "--------");
    scols_line_set_data(sep, 2, "---------");
    scols_line_set_data(sep, 3, "---------");
    scols_line_set_data(sep, 4, "---");
    scols_line_set_data(sep, 5, "-------");
    scols_line_set_data(sep, 6, "---------------");

    for (const auto& i:vms) {
        auto line = scols_table_new_line(table.get(), NULL);
        if (!line) throw std::runtime_error("scols_table_new_line() failed");
        scols_line_set_data(line, 0, i.second.running? "*" : "");
        scols_line_set_data(line, 1, i.first.c_str());
        scols_line_set_data(line, 2, i.second.volume.value_or("-").c_str());
        scols_line_set_data(line, 3, is_autostart(i.first)? "yes":"no");
        const auto& cpu = i.second.cpu;
        scols_line_set_data(line, 4, cpu.has_value()? std::to_string(cpu.value()).c_str() : "-");
        const auto& memory = i.second.memory;
        scols_line_set_data(line, 5, memory.has_value()? std::to_string(memory.value()).c_str() : "-");
        const auto& ip_address = i.second.ip_address;
        scols_line_set_data(line, 6, ip_address.value_or("-").c_str());
    }
    scols_print_table(table.get());

    return 0;
}
