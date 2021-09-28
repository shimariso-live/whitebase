#include <filesystem>
#include <map>
#include <vector>
#include <thread>
#include <functional>

bool do_install(const std::filesystem::path& disk, uint64_t size, uint16_t log_sec, const std::map<std::string,std::string>& grub_vars = {}, 
    std::stop_token st = std::stop_token(), std::function<void(double)> progress = [](double){});
int install_cmdline(const std::vector<std::string>& args);
