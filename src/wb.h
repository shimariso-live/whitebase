#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>

#include <optional>
#include <filesystem>
#include <string>
#include <functional>

const static std::filesystem::path vm_root("/var/vm"), run_root("/run/vm");

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

static bool is_running(const std::string& vmname)
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

static void for_each_running_vm(std::function<void(const std::string&)> func)
{
    if (!std::filesystem::exists(run_root) || !std::filesystem::is_directory(run_root)) return;
    //else
    for (const auto& d : std::filesystem::directory_iterator(run_root)) {
        auto name = d.path().filename().string();
        if (!is_running(name)) continue;
        func(name);
    }
}

static bool is_autostart(const std::string& vmname)
{
    std::filesystem::path multi_user_target_wants("/etc/systemd/system/multi-user.target.wants");
    return std::filesystem::exists(multi_user_target_wants / (std::string("vm@") + vmname + ".service"));
}
