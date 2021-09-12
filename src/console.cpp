#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>

#include <iostream>
#include <filesystem>
#include <cstdlib>
#include <sys/ioctl.h>
#include <argparse/argparse.hpp>

static struct termios old_term;

void restore_term()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
}

int connect(const char* vmname, const std::string& socket_name = "serial.sock")
{
    struct sockaddr_un sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));

    auto sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) throw std::runtime_error("Cannot create socket");

    sockaddr.sun_family = AF_UNIX;
    std::filesystem::path run_root("/run/vm");
    auto vm_root = run_root / vmname;
    auto serial_socket = vm_root / socket_name;
    strcpy(sockaddr.sun_path, serial_socket.c_str());

    if (connect(sock, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        close(sock);
        throw std::runtime_error("Failed to connect");
    }

    return sock;
}

int console(const char* vmname, const std::string& socket_name)
{
    int sock = connect(vmname, socket_name);

    // init terminal
    if (tcgetattr(STDIN_FILENO, &old_term) >= 0) {
        struct termios new_term;
        memcpy(&new_term, &old_term, sizeof(new_term));
        cfmakeraw(&new_term);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
        std::atexit(restore_term);
    }

    while(true) {
        struct pollfd pollfds[2];
        pollfds[0].fd = sock;
        pollfds[0].events = POLLIN;
        pollfds[1].fd = STDIN_FILENO;
        pollfds[1].events = POLLIN;

        poll(pollfds, 2, 1000);

        char buf[4096];

        if (pollfds[0].revents & POLLIN) {
            auto r = read(sock, buf, sizeof(buf));
            if (r == 0) { // EOF
                break;
            }
            //else
            write(STDOUT_FILENO, buf, r);
        }

        if (pollfds[1].revents & POLLIN) {
            auto r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r == 0) { // EOF
                break;
            }
            //else
            for (int i = 0; i < r; i++) {
                if (buf[i] == 29/*C-]*/) goto out;
                write(sock, &buf[i], 1);
            }
        }

    }
out:;

    close(sock);
    return 0;
}

int console(const char* vmname)
{
    return console(vmname, "serial.sock");
}

int monitor(const std::vector<std::string>& args)
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
    return console(vmname.c_str(), "monitor.sock");
}

int console(const std::vector<std::string>& args)
{
    argparse::ArgumentParser program(args[0]);
    program.add_argument("--graphical", "-g").help("Graphical console").default_value(false).implicit_value(true);
    program.add_argument("vmname").help("VM name");

    try {
        program.parse_args(args);
    }
    catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }

    auto graphical = program.get<bool>("--graphical"); 
    auto vmname = program.get<std::string>("vmname");
    return console(vmname.c_str());
}

static int _main(int,char*[])
{
    return 0;
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif
