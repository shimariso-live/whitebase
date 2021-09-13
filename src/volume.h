#include <vector>
#include <filesystem>
#include <optional>
#include <functional>
#include <map>

struct Volume {
    bool online;
    std::filesystem::path path;
    std::string device_or_uuid;
    std::optional<std::string> fstype;
    std::optional<uint64_t> size;
    std::optional<uint64_t> free;
};

std::map<std::string,Volume> volume_list();
std::optional<std::filesystem::path> get_volume_dir(const std::string& volume_name);
std::filesystem::path get_volume_dir(const std::string& volume_name, std::function<std::filesystem::path(const std::string&)> noexists);
int volume(const std::vector<std::string>& args);