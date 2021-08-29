#include <stdexcept>

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

void with_socket(const std::filesystem::path& socket_path,std::function<void(int)> func)
{
    auto fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket() failed");
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(struct sockaddr_un));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, socket_path.c_str(), sizeof(sa.sun_path) - 1);
    if (connect(fd, (const struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) < 0) {
        throw std::runtime_error("connect(" + socket_path.string() + ") failed");
    }
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