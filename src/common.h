#include <vector>
#include <string>
#include <functional>
#include <filesystem>
#include <map>

#include <yajl/yajl_tree.h>

void exec(const std::vector<std::string>& cmdline);
pid_t fork(std::function<void(void)> func);
int call(const std::vector<std::string>& cmdline);
void check_call(const std::vector<std::string>& cmdline);
int listen_unix_socket(const std::filesystem::path& socket_path, int backlog = 10);
int connect_unix_socket(const std::filesystem::path& socket_path);
void with_socket(const std::filesystem::path& socket_file,std::function<void(int)> func);
std::shared_ptr<yajl_val_s> read_json_object(int fd);
bool read_json_object_stream(int fd, std::string& buf, std::function<bool(const yajl_val)> func);

template <typename T> std::optional<T> with_object_property(const yajl_val val, const std::string& name, std::function<std::optional<T>(const yajl_val val)> func)
{
    if (!YAJL_IS_OBJECT(val)) return std::nullopt;
    for (int i = 0; i < val->u.object.len; i++) {
        if (name == val->u.object.keys[i]) {
            return func(val->u.object.values[i]);
        }
    }
    return std::nullopt;
}

bool with_object_property(const yajl_val val, const std::string& name, std::function<bool(const yajl_val val)> func);
