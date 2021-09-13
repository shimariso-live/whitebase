#include <pty.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#include <vector>
#include <string>
#include <functional>
#include <filesystem>
#include <map>

#include <yajl/yajl_tree.h>

void exec(const std::vector<std::string>& cmdline);
pid_t fork(std::function<void(void)> func);
std::pair<pid_t,int> forkpty(std::function<void(void)> func,const std::optional<std::pair<unsigned short,unsigned short>>& winsiz = std::nullopt);
int call(const std::vector<std::string>& cmdline, bool propagate_sigterm = false/*DO NOT USE THIS OPTION UNLESS YOU ARE AWARE OF WHAT YOU DOING*/);
void check_call(const std::vector<std::string>& cmdline);
int listen_unix_socket(const std::filesystem::path& socket_path, int backlog = 10);
int connect_unix_socket(const std::filesystem::path& socket_path);
int write(int fd, const std::string& str);
std::string human_readable(uint64_t size);

template <typename T> T with_socket(const std::filesystem::path& socket_path,std::function<T(int)> func)
{
    auto fd = connect_unix_socket(socket_path);
    return with_finally_clause<T>([&func,fd]() {
        const T& rst = func(fd); // https://stackoverflow.com/questions/2822243/store-return-value-of-function-in-reference-c
        shutdown(fd, SHUT_WR);
        char buf[128];
        int r;
        while (r = read(fd, buf, sizeof(buf)) > 0) {
            ;
        }
        return rst;
    }, [fd]() {
        close(fd);
    });
}

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

template <typename T> T with_finally_clause(std::function<T(void)> func,std::function<void(void)> finally)
{
    class finalizer {
        std::function<void(void)>& finally;
    public:
        finalizer(std::function<void(void)>& _finally) : finally(_finally) {}
        ~finalizer() { finally(); }
    };
    finalizer f(finally);
    return func();
}

void with_finally_clause(std::function<void(void)> func,std::function<void(void)> finally);

template <typename T> T with_return_value(int fd, std::function<T(yajl_val)> func)
{
    auto res = read_json_object(fd);
    if (!res || !YAJL_IS_OBJECT(res.get())) throw std::runtime_error("Invalid JSON response");
    //else
    for (int i = 0; i < res.get()->u.object.len; i++) {
        if (strcmp("return", res.get()->u.object.keys[i]) == 0) {
            return func(res.get()->u.object.values[i]);
        }
    }
    //else
    throw std::runtime_error("No return value in JSON response");
}
