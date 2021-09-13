#include <sys/wait.h>

#include "subprocess.h"

static std::tuple<pid_t,int/*in*/,int/*out*/> forkpipe(std::function<int(void)> func)
{
    int fd0[2], fd1[2];
    if (pipe(fd0) < 0) throw std::runtime_error("pipe() failed");
    if (pipe(fd1) < 0) { close(fd0[0]); close(fd0[1]); throw std::runtime_error("pipe() failed"); }
    //else

    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid > 0) {
        // parent process
        close(fd0[1]);
        close(fd1[0]);
        return {pid, fd0[0], fd1[1]};
    }

    //else(child process)
    try {
        dup2(fd0[1], STDOUT_FILENO);
        dup2(fd1[0], STDIN_FILENO);
        close(fd0[0]);
        close(fd0[1]);
        close(fd1[0]);
        close(fd0[1]);
        // TODO: connect stderr to logfile
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
        _exit(func());
    }
    catch (...) {
        // jumping across scope border in forked process may not be a good idea.
    }
    _exit(-1);
}

void SubprocessDialog::run(std::function<int(void)> subprocess, 
    std::function<void(int/*in*/,int/*out*/,std::function<void(const std::string&)>/*set_status_string*/,std::function<void(int)>/*set_progress*/)> mainprocess) {

    // setup contents
    progressbar.set_margin(8);
    get_content_area()->append(progressbar);
    progressbar.set_show_text();

    progress.store(-1);
    status_string = "";
    wstatus = 0;
    force_kill_count = 0;
    auto rst = forkpipe(subprocess);
    pid = std::get<0>(rst);
    thread.reset(new std::thread([this,&mainprocess,&rst]() {
        auto in = std::get<1>(rst);
        auto out = std::get<2>(rst);
        mainprocess(in, out, [this](const std::string& status_string) { set_status_string(status_string); }, [this](int progress) { set_progress(progress); });
        ::close(in);
        ::close(out);
        int wstatus;
        waitpid(pid, &wstatus, 0);
        pid = 0;
        this->wstatus = wstatus;
        process_done();
    }));

    process_done.connect([this]() {
        hide();
        if (thread->joinable()) thread->join(); // probably not necessary though
        thread.release();
        _signal_process_done(wstatus);
    });

    update_status_string.connect([this]() {
        std::lock_guard<std::mutex> lock(mutex);
        progressbar.set_text(status_string);
    });

    update_progress.connect([this]() {
        auto progress = this->progress.load();
        if (progress >= 0) {
            progressbar.set_fraction(progress / 100.0);
        } else {
            progressbar.pulse();
        }
    });

    signal_response().connect([this](int resid) {
        if (force_kill_count >= 3) {
            kill(pid, SIGKILL);
        } else {
            kill(pid, SIGTERM);
            force_kill_count++;
        }
    });
    show();
}
