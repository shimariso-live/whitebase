#include <vector>
#include <string>
#include <functional>
#include <filesystem>

void exec(const std::vector<std::string>& cmdline);
pid_t fork(std::function<void(void)> func);
int call(const std::vector<std::string>& cmdline);
void check_call(const std::vector<std::string>& cmdline);
void with_socket(const std::filesystem::path& socket_file,std::function<void(int)> func);