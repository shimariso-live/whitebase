#include <string>
#include <filesystem>
#include "common.h"

const static std::filesystem::path vm_root("/var/vm"), run_root("/run/vm");

bool is_running(const std::string& vmname);
void set_autostart(const std::string& vmname, bool autostart);
bool is_autostart(const std::string& vmname);

struct VM {
    bool running = false;
    bool autostart;
    std::optional<std::string> volume = std::nullopt;
    std::optional<uint16_t> cpu = std::nullopt;
    std::optional<uint32_t> memory = std::nullopt;
    std::optional<std::string> ip_address = std::nullopt;
};

std::map<std::string,VM> list_vm();
int create_vm(const std::string& vmname, const std::string& volume, uint32_t memory = 1024, uint16_t cpu = 1, std::optional<uint32_t> data_partition = std::nullopt, bool stub = true);
int delete_vm(const std::string& vmname);

void for_each_running_vm(std::function<void(const std::string&)> func);

template <typename T> T with_qmp_session(const std::string& name, std::function<T(int)> func, std::function<T(void)> noavail)
{
    auto socket_path = run_root / name / "qmp.sock";
    if (!std::filesystem::exists(socket_path) || !std::filesystem::is_socket(socket_path)) {
        return noavail();
    }
    //else
    return with_socket<T>(socket_path, [&func](int fd) {
        read_json_object(fd); // skip {"QMP":{}}
        if (write(fd, "{\"execute\":\"qmp_capabilities\"}\r\n") < 0) {
            throw std::runtime_error("qmp write(qmp_capabilities_cmd) failed");
        }
        if (!read_json_object(fd)) {
            throw std::runtime_error("qmp_capabilities_cmd failed");
        }
        return func(fd);
    });
}

template <typename T> T with_qga(const std::string& name, std::function<T(int)> func, std::function<T(void)> noavail)
{
    auto socket_path = run_root / name / "qga.sock";
    if (!std::filesystem::exists(socket_path) || !std::filesystem::is_socket(socket_path)) {
        return noavail();
    }
    //else
    return with_socket<T>(socket_path, [&func](int fd) {
        return func(fd);
    });
}
