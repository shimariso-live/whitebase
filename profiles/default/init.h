#include <sys/mount.h>

#include <filesystem>
#include <optional>
#include <vector>
#include <variant>
#include <functional>
#include <map>

#ifdef PARAVIRT
extern "C" {
#include <xenstore.h>
}
typedef std::pair<xs_handle*,xs_transaction_t> inifile_t;
#else
#include <iniparser4/iniparser.h>
typedef dictionary* inifile_t;
#endif // PARAVIRT

#define RUNTIME_ERROR(msg) throw std::runtime_error((std::string)__FILE__ + '(' + std::to_string(__LINE__) + ") " + msg)
#define RUNTIME_ERROR_WITH_ERRNO(msg) throw std::runtime_error((std::string)__FILE__ + '(' + std::to_string(__LINE__) + ") " + msg + ':' + strerror(errno))

namespace init {
    static const char* TIME_FILE = "boottime.txt";

    namespace progs {
        static const char* CP = "/bin/cp";
        static const char* UMOUNT = "/bin/umount";
        static const char* MKSWAP = "/sbin/mkswap";
        static const char* SWAPON = "/sbin/swapon";
#ifndef PARAVIRT
        static const char* FSCK_FAT = "/usr/sbin/fsck.fat";
        static const char* BTRFS = "/sbin/btrfs";
        static const char* CHATTR = "/usr/bin/chattr";
        static const char* EJECT = "/usr/bin/eject";
#endif
        static const char* ALL[] = {
            CP, UMOUNT, MKSWAP, SWAPON
#ifndef PARAVIRT
            ,FSCK_FAT, BTRFS, CHATTR, EJECT
#endif
        };
    }

    namespace lib {
        const std::vector<std::string>& kernel_cmdline();
        int exec(const std::string& cmd, const std::vector<std::string>& args, 
        const std::filesystem::path& rootdir = "/",
        const std::variant<std::monostate,std::function<void(std::istream&)>,std::function<void(std::ostream&)>>& data = {});
        bool is_file(const std::filesystem::path& path);
        bool is_dir(const std::filesystem::path& path);
        bool is_block(const std::filesystem::path& path);

        int mount(const std::filesystem::path& source, const std::filesystem::path& mountpoint,
          const std::string& fstype = "auto", unsigned int mountflags = MS_RELATIME,
          const std::string& data = "");
        int move_mount(const std::filesystem::path& old, const std::filesystem::path& _new);
        int bind_mount(std::filesystem::path source, std::filesystem::path mountpoint);
        int mount_loop(std::filesystem::path source, std::filesystem::path mountpoint,
            const std::string& fstype = "auto", unsigned int mountflags = MS_RELATIME,
            const std::string& data = "", int offset = 0);
        bool is_mounted(const std::filesystem::path& path);
        int umount_recursive(const std::filesystem::path& path);
        uint64_t get_free_disk_space(const std::filesystem::path& mountpoint);

        std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>> 
            search_partition(const std::string& name, const std::string& value);
        std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>>
            get_partition_by_uuid(const std::string& uuid, int max_retry = 3);
        std::map<std::filesystem::path,std::tuple<std::optional<std::string>/*uuid*/,std::optional<std::string>/*fstype*/>> 
            get_all_partitions();
        bool is_block_readonly(const std::filesystem::path& path);
        std::optional<std::filesystem::path> devname_to_sysfs_path(const std::filesystem::path& blockdevice);
        bool is_removable(const std::filesystem::path& blockdevice);

        int cp_a(const std::filesystem::path& src, const std::filesystem::path& dst);

        std::optional<std::pair<std::filesystem::path,std::string/*fstype*/>> get_source_device_from_mountpoint(const std::filesystem::path& path);

        std::optional<std::string> set_hostname(const std::filesystem::path& rootdir, const std::optional<std::string>& hostname = std::nullopt);
        bool set_root_password(const std::filesystem::path& rootdir, const std::string& password);
        bool set_timezone(const std::filesystem::path& rootdir, const std::string& timezone);
        bool set_locale(const std::filesystem::path& rootdir, const std::string& locale);
        bool set_keymap(const std::filesystem::path& rootdir,  const std::string& keymap);
        bool set_wifi_config(const std::filesystem::path& rootdir, const std::string& ssid, const std::string& key);
        bool set_network_config(const std::filesystem::path& rootdir,
            const std::optional<std::string>& network_interface = std::nullopt,
            const std::optional<std::tuple<std::string/*address*/,std::optional<std::string>/*gateway*/,std::optional<std::string>/*dns*/,std::optional<std::string>/*fallback_dns*/>>& ipv4 = std::nullopt, 
            const std::optional<std::tuple<std::string/*address*/,std::optional<std::string>/*gateway*/,std::optional<std::string>/*dns*/,std::optional<std::string>/*fallback_dns*/>>& ipv6 = std::nullopt);
        bool set_ssh_key(const std::filesystem::path& rootdir, const std::string& ssh_key);
    }

    namespace hooks {
        void print_banner();
        void pre_shutdown(const std::optional<std::string>& mode);
        void post_shutdown(const std::optional<std::string>& mode);
        void setup_data_subvolumes(const std::filesystem::path& mnt_path);

        void setup_hostname(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_network(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_password(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_timezone(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_locale(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_keymap(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_wifi(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_ssh_key(const std::filesystem::path& newroot, inifile_t inifile);
        void setup_autologin(const std::filesystem::path& newroot, inifile_t inifile);
        void post_init(const std::filesystem::path& newroot, 
            std::optional<std::tuple<std::filesystem::path,std::optional<std::string/*uuid*/>,std::optional<std::string/*fstype*/>>>,
            inifile_t inifile);
    }
};
