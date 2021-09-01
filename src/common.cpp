#include <stdexcept>
#include <iostream>

#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "common.h"

void exec(const std::vector<std::string>& cmdline)
{
    if (cmdline.size() < 1) throw std::logic_error("cmdline too short");
    char ** argv = new char *[cmdline.size() + 1];
    for (int i = 0; i < cmdline.size(); i++) {
        argv[i] = strdup(cmdline[i].c_str());
    }
    argv[cmdline.size()] = NULL;
    if (execvp(cmdline[0].c_str(), argv) < 0) exit(-1);
}

pid_t fork(std::function<void(void)> func)
{
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid > 0) return pid;

    //else(child process)
    try {
        func();
    }
    catch (...) {
        // jumping across scope border in forked process may not be a good idea.
    }
    _exit(-1);
}

int call(const std::vector<std::string>& cmdline)
{
    auto pid = fork([&cmdline](){exec(cmdline);});
    int wstatus;
    if (waitpid(pid, &wstatus, 0) < 0) throw std::runtime_error("waitpid() failed");
    if (!WIFEXITED(wstatus)) {
        if (WIFSIGNALED(wstatus)) {
            throw std::runtime_error(std::string("Command(") + cmdline[0] + ") execution terminated by signal " + std::to_string(WTERMSIG(wstatus)) + ".");
        }
        //else
        throw std::runtime_error(std::string("Command(") + cmdline[0] + ") execution terminated.");
    }
    return WEXITSTATUS(wstatus);
}

void check_call(const std::vector<std::string>& cmdline)
{
    auto status = call(cmdline);
    if (status != 0) throw std::runtime_error(std::string("Command(") + cmdline[0] + ") execution failed. Exit status: " + std::to_string(status));
}

int listen_unix_socket(const std::filesystem::path& socket_path, int backlog/*=10*/)
{
    auto sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) throw std::runtime_error("socket() failed");
    //else
    struct sockaddr_un sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sun_family = AF_UNIX;
    if (std::filesystem::exists(socket_path) && std::filesystem::is_socket(socket_path)) std::filesystem::remove(socket_path);
    strcpy(sockaddr.sun_path, socket_path.c_str());
    if (bind(sock, (const struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
        throw std::runtime_error("bind(" + socket_path.string() + ") failed");
    }
    if (listen(sock, backlog) < 0) throw std::runtime_error("listen(" + socket_path.string() + ") failed");
    //else
    return sock;
}

int connect_unix_socket(const std::filesystem::path& socket_path)
{
    struct sockaddr_un sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));

    auto sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) throw std::runtime_error("socket() failed");

    sockaddr.sun_family = AF_UNIX;
    std::filesystem::path run_root("/run/vm");
    strcpy(sockaddr.sun_path, socket_path.c_str());

    if (connect(sock, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        close(sock);
        throw std::runtime_error("connect() failed");
    }

    return sock;
}

void with_socket(const std::filesystem::path& socket_path,std::function<void(int)> func)
{
    auto fd = connect_unix_socket(socket_path);
    try {
        func(fd);
    }
    catch (...) {
        close(fd);
        throw;
    }
    shutdown(fd, SHUT_WR);
    char buf[128];
    int r;
    while (r = read(fd, buf, sizeof(buf)) > 0) {
        ;
    }
    close(fd);
}

bool read_json_object_stream(int fd, std::string& buf, std::function<bool(const yajl_val)> func)
{
    char _buf[1024];
    auto r = read(fd, _buf, sizeof(_buf));
    if (r < 0) throw std::runtime_error("read() failed");
    if (r > 0) buf.append(_buf, r);
    else buf += "\r\n";
    int i = -1;
    while ((i = buf.find_first_of("\r\n")) >= 0) {
        std::shared_ptr<yajl_val_s> tree(yajl_tree_parse(buf.substr(0, i).c_str(), NULL, 0), yajl_tree_free);
        buf.erase(0, i + 2);
        if (!tree) throw std::runtime_error("yajl_tree_parse() failed");
        //else
        if (!func(tree.get())) return false;
    }
    return r > 0; // false if EOF
}

std::shared_ptr<yajl_val_s> read_json_object(int fd)
{
    std::string buf;
    while (true) {
        char c;
        auto r = read(fd, &c, 1);
        if (r < 0) std::runtime_error("read() failed");
        if (r == 0) break; // EOF
        buf += c;
        //std::cout << c;
        if (buf.ends_with("\r\n")) {
            buf.erase(buf.length() - 2, 2);
            break;
        } else if (buf.ends_with("\n")) {
            buf.erase(buf.length() - 1, 1);
            break;
        }
    }
    auto tree = std::shared_ptr<yajl_val_s>(yajl_tree_parse(buf.c_str(), NULL, 0), yajl_tree_free);
    if (!tree) throw std::runtime_error("yajl_tree_parse() failed");
    if (!YAJL_IS_OBJECT(tree.get())) throw std::logic_error("Not a JSON object");
    return tree;
}

bool with_object_property(const yajl_val val, const std::string& name, std::function<bool(const yajl_val val)> func)
{
    return with_object_property<bool>(val, name, [&func](const yajl_val val) {
        auto rst = func(val);
        return rst? std::optional<bool>(true) : std::nullopt;
    }).value_or(false);
}