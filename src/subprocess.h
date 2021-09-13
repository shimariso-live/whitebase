#include <memory>
#include <thread>
#include <mutex>
#include <functional>

#include <gtkmm.h>

class SubprocessDialog : public Gtk::MessageDialog {
    pid_t pid;
    std::unique_ptr<std::thread> thread;
    int wstatus;
    int force_kill_count;
    
    std::mutex mutex;
    std::string status_string;
    std::atomic_int progress;
    
    Gtk::ProgressBar progressbar;

    Glib::Dispatcher process_done, update_status_string, update_progress;
    sigc::signal<void(int)> _signal_process_done;
protected:
    void set_status_string(const std::string& status_string) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            this->status_string = status_string;
        }
        update_status_string();
    }
    void set_progress(int progress) {
        this->progress.store(progress);
        update_progress();
    }

public:
    SubprocessDialog(Gtk::Window& parent, const std::string& message, bool use_markup = false, bool cancellable = true) 
        : MessageDialog(parent, message, use_markup, Gtk::MessageType::INFO, cancellable? Gtk::ButtonsType::CANCEL : Gtk::ButtonsType::NONE, true),
        pid(0) {

    }
    ~SubprocessDialog() {
        if (pid > 0) kill(pid, SIGKILL);
        if (thread) thread->join();
    }

    void run(std::function<int(void)> subprocess, 
        std::function<void(int/*in*/,int/*out*/,std::function<void(const std::string&)>/*set_status_string*/,std::function<void(int)>/*set_progress*/)> mainprocess);

    sigc::signal<void(int)> signal_process_done() { return _signal_process_done; }
};
