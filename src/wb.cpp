#include <pty.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fstream>

#include <uuid/uuid.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <argparse/argparse.hpp>

#include "common.h"
#include "gtk4ui.h"
#include "list.h"
#include "volume.h"
#include "wb.h"

int console(const char* vmname);
int console(const std::vector<std::string>& args);
int monitor(const std::vector<std::string>& args);
int install_cmdline(const std::vector<std::string>& args);

static void with_qmp_session(const std::string& name, std::function<void(int)> func, std::function<void(void)> noavail = [](){})
{
    with_qmp_session<void*>(name, [&func](int fd) {
        func(fd);
        return nullptr;
    }, [&noavail]() {
        noavail();
        return nullptr;
    });
}

static void with_qga(const std::string& name, std::function<void(int)> func, std::function<void(void)> noavail = [](){})
{
    with_qga<void*>(name, [&func](int fd) {
        func(fd);
        return nullptr;
    }, [&noavail]() {
        noavail();
        return nullptr;
    });
}

template <typename T> std::optional<T> with_vmdir(const std::string& name, std::function<T(const std::filesystem::directory_entry&)> func)
{
    std::filesystem::path vm_path = vm_root / name;
    if (!std::filesystem::exists(vm_path) || !std::filesystem::is_directory(vm_path)) return std::nullopt;
    return func(std::filesystem::directory_entry(vm_path));
}

int start(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("--console", "-c").help("Imeddiately connect to console").default_value(false).implicit_value(true);
    program.add_argument("vmname").help("VM name");
    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto vmname = program.get<std::string>("vmname");
    if (is_running(vmname)) {
        std::cerr << vmname << " is already running" << std::endl;
        return 1;
    }

    auto rst = call({"systemctl", "start", std::string("vm@") + vmname});
    if (rst == 0) {
        if (!is_running(vmname)) {
            std::cerr << vmname << " not started(due to some error?)" << std::endl;
            return 1;
        }
        //else
        if (program.get<bool>("--console")) {
            return console(vmname.c_str());
        }
    }

    return rst;
}

static int stop(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("--console", "-c").help("Imeddiately connect to console").default_value(false).implicit_value(true);
    program.add_argument("--force", "-f").help("Force kill vm").default_value(false).implicit_value(true);
    program.add_argument("vmname").help("VM name (@all to all running VMs)");

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    bool enter_console = program.get<bool>("--console");
    bool force = program.get<bool>("--force");
    auto vmname = program.get<std::string>("vmname");
    if (vmname == "@all") {
        if (enter_console) std::cout << "--console ignored." << std::endl;
        for_each_running_vm([force](const std::string& name) {
            std::cout << (force? "Forcefully stopping " : "Stopping ") << name << std::endl;
            check_call({"systemctl", force? "kill":"stop", "--no-block", std::string("vm@") + name});
        });
    } else {
        if (!is_running(vmname)) {
            std::cerr << vmname << " is not running" << std::endl;
            return 1;
        }
        
        check_call({"systemctl", program.get<bool>("--force")? "kill":"stop", "--no-block", std::string("vm@") + vmname});
        if (enter_console) {
            return console(vmname.c_str());
        }
    }

    return 0;
}

static int restart(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("--console", "-c").help("Imeddiately connect to console").default_value(false).implicit_value(true);
    program.add_argument("--force", "-f").help("Force reset vm").default_value(false).implicit_value(true);
    program.add_argument("vmname").help("VM name");

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }
    
    auto vmname = program.get<std::string>("vmname");
    if (!is_running(vmname)) {
        std::cerr << vmname << " is not running" << std::endl;
        return 1;
    }

    if (program.get<bool>("--force")) {
        with_qmp_session(vmname, [](int fd) {
            write(fd, "{ \"execute\": \"system_reset\"}\r\n");
            read_json_object(fd);
        }, [&vmname]() {
            throw std::runtime_error("QMP interface is not available for " + vmname);
        });
    } else {
        check_call({"systemctl", "restart", std::string("vm@") + vmname});
    }

    if (program.get<bool>("--console")) {
        return console(vmname.c_str());
    }

    return 0;
}

static int reboot(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("--console", "-c").help("Imeddiately connect to console").default_value(false).implicit_value(true);
    program.add_argument("vmname").help("VM name");

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }
    
    auto vmname = program.get<std::string>("vmname");
    if (!is_running(vmname)) {
        std::cerr << vmname << " is not running" << std::endl;
        return 1;
    }

    with_qga(vmname, [](int fd) {
        write(fd, "{\"execute\":\"guest-shutdown\", \"arguments\":{\"mode\":\"reboot\"}}\r\n");
    }, [&vmname]() {
        throw std::runtime_error("Guest agent is not running on " + vmname + ".");
    });

    if (program.get<bool>("--console")) {
        return console(vmname.c_str());
    }

    return 0;
}

static int ping(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("vmname").help("VM name");

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }
    
    auto vmname = program.get<std::string>("vmname");
    if (!is_running(vmname)) {
        std::cerr << vmname << " is not running" << std::endl;
        return 1;
    }

    with_qga(vmname, [](int fd) {
        write(fd, "{\"execute\":\"guest-ping\"}\r\n");
        auto tree = read_json_object(fd);
        if (!tree) std::runtime_error("Invalid response from VM");
        std::cout << "OK" << std::endl;

    }, [&vmname]() {
        throw std::runtime_error("Guest agent is not running on " + vmname + ".");
    });
    return 0;
}

static void set_autostart(const std::string& vmname, bool autostart)
{
    check_call({"systemctl", autostart? "enable" : "disable", std::string("vm@") + vmname});
}

int autostart(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("vmname").help("VM name");
    program.add_argument("action").help("'on' or 'off'").default_value(std::string("show"));
    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto vmname = program.get<std::string>("vmname");
    auto action = program.get<std::string>("action");

    auto rst = with_vmdir<int>(vmname, [&vmname,&action](auto vmdir) {
        if (action == "show") {
            std::cout << "autostart is " << (is_autostart(vmname)? "on" : "off") << std::endl;
        } else if (action == "on") {
            set_autostart(vmname, true);
        } else if (action == "off") {
            set_autostart(vmname, false);
        } else {
            std::cerr << "Invalid action specified." << std::endl;
            return -1;
        }
        return 0;
    });

    if (!rst) {
        std::cerr << "VM not found." << std::endl;
        return -1;
    }
    //else
    return rst.value();
}

static int status(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("vmname").help("VM name");
    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    exec({"systemctl", "status", std::string("vm@") + program.get<std::string>("vmname")});
    return 0;
}

static int journal(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("--follow", "-f").help("Act like 'tail -f'").default_value(false).implicit_value(true);
    program.add_argument("vmname").help("VM name");
    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    exec({"journalctl", program.get<bool>("--follow")? "-f" : "--pager", "-u", std::string("vm@") + program.get<std::string>("vmname")});
    return 0; // no reach here, though
}

static int create(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("--volume", "-v").help("Specify volume to create VM on").default_value(std::string("default"));
    program.add_argument("vmname").help("VM name");
    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto vmname = program.get<std::string>("vmname");

    auto vm_dir = vm_root / vmname;
    if (std::filesystem::exists(vm_dir)) {
        throw std::runtime_error(vmname + " already exists");
    }

    auto volume = program.get<std::string>("--volume");
    auto volume_dir = get_volume_dir(volume, [](auto name) -> std::filesystem::path {throw std::runtime_error("Volume " + name + " does not exist");});
    auto volume_vm_dir = volume_dir / vmname;
    if (std::filesystem::exists(volume_vm_dir)) {
        throw std::runtime_error(vmname + " already exists on volume " + volume);
    }

    try {
        auto fs_dir = volume_vm_dir / "fs";
        std::filesystem::create_directories(fs_dir);
        check_call({"cp", "-a", "/usr/share/wb/stubvm/.", fs_dir.string()});

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

static int _delete(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("vmname").help("VM name");
    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto vmname = program.get<std::string>("vmname");
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

static int activate(const std::vector<std::string>& args)
{
    return 0;
}

static int deactivate(const std::vector<std::string>& args)
{
    return 0;
}

static const std::map<std::string,std::pair<int (*)(const std::vector<std::string>&),std::string> > subcommands {
  {"console", {console, "Enter VM console"}},
  {"monitor", {monitor, "Enter VM monitor"}},
  {"create", {create, "Create new VM"}},
  {"delete", {_delete, "Delete VM"}},
  {"start", {start, "Start VM"}},
  {"stop", {stop, "Stop VM"}},
  {"restart", {restart, "Restart VM"}},
  {"reboot", {reboot, "Reboot VM's operating system"}},
  {"ping", {ping, "Ping VM's guest agent"}},
  {"status", {status, "Show VM status using 'systemctl status'"}},
  {"journal", {journal, "Show VM journal using 'journalctl'"}},
  {"autostart", {autostart, "Enable/Disable autostart"}},
  {"list", {list, "List VM"}},
  {"login", {gtk4login, "Show title screen(executed by systemd)"}},
  {"ui", {gtk4ui,  "Run graphical interface"}},
  {"installer", {gtk4installer, "Run graphical installer"}},
  {"install", {install_cmdline, "Run command line installer"}},
  {"volume", {volume, "Manage volumes"}}
};

static void show_subcommands()
{
    for (auto i = subcommands.cbegin(); i != subcommands.cend(); i++) {
        std::cout << i->first << '\t' << i->second.second << std::endl;
    }
}

static int _main(int argc, char* argv[])
{
    setlocale( LC_ALL, "ja_JP.utf8"); // TODO: read /etc/locale.conf

    if (argc < 2) {
        std::cout << "Subcommand not specified. Valid subcommands are:" << std::endl;
        show_subcommands();
        return 1;
    }

    std::string subcommand(argv[1]);

    if (!subcommands.contains(subcommand)) {
        std::cout << "Invalid subcommand '" << subcommand << "'. Valid subcommands are:" << std::endl;
        show_subcommands();
        return 1;
    }

    std::vector<std::string> args;

    args.push_back(std::string(argv[0]) + ' ' + subcommand);
    for (int i = 2; i < argc; i++) {
        args.push_back(argv[i]);
    }

    return subcommands.at(subcommand).first(args);
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif
