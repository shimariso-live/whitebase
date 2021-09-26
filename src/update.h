#include <sys/file.h>

#include <filesystem>
#include <optional>
#include <thread>

static const std::filesystem::path boot_dir("/run/initramfs/boot");
static const std::filesystem::path version_file("/.genpack/version");
static const std::filesystem::path system_img = boot_dir / "system.img", system_cur = boot_dir / "system.cur", system_new = boot_dir / "system.new", system_old = boot_dir / "system.old";

std::optional<std::string> get_present_version();
std::optional<std::filesystem::path> get_present_system_image_path();
std::optional<std::string> get_version_from_system_image_file(const std::filesystem::path& image_file);
std::optional<std::tuple<std::string,std::string,size_t>> get_latest_version(bool include_unstable = false);
bool download_system_image(const std::string url, size_t expected_size, std::stop_token& st, std::function<void(double)> progress);

class BootPartitionLock {
    int fd;
public:
    BootPartitionLock() = delete;
    BootPartitionLock(bool nonblock = false);
    ~BootPartitionLock();
    operator bool() { return fd >= 0; }
};
