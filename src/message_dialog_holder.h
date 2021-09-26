#include <variant>
#include <thread>

#include <gtkmm.h>

class MessageDialogHolder {
public:
    class MarkupText : public std::string {};
private:
    Gtk::Window& parent;
    Gtk::Spinner spinner;
    Gtk::ProgressBar progressbar;
    std::jthread thread;
    Glib::Dispatcher done, cancelled;
    std::unique_ptr<Gtk::MessageDialog> dialog, dialog_to_be_disposed;
    void check_vacancy() { if (dialog) throw std::runtime_error("Message dialog already shown"); }
    std::pair<std::string,bool> classify_message(const std::variant<std::string,MarkupText>& message) { 
        return { message.index() == 0? std::get<0>(message) : std::get<1>(message), message.index() == 1};
    }

    class AsyncJob {
        std::jthread thread;
        std::atomic<double> progress_value;
        Glib::Dispatcher done, cancelled, progress;
    public:
        AsyncJob(std::function<bool(std::stop_token)> job, std::function<void(bool)> on_done) {
            done.connect([on_done]() { on_done(true); });
            cancelled.connect([on_done]() { on_done(false); });
            thread = std::jthread([this,job](std::stop_token st) {
                auto rst = job(st);
                if (rst) done();
                else cancelled();
            });
        }
        AsyncJob(std::function<bool(std::stop_token,std::function<void(double)>)> job, std::function<void(bool)> on_done, std::function<void(double)> on_progress) {
            done.connect([on_done]() { on_done(true); });
            cancelled.connect([on_done]() { on_done(false); });
            progress.connect([this,on_progress]() { on_progress(progress_value.load()); });
            progress_value.store(0.0);
            on_progress(0.0);
            thread = std::jthread([this,job](std::stop_token st) {
                auto rst = job(st, [this](double p) { progress_value.store(p); progress(); });
                if (rst) done();
                else cancelled();
            });
        }
        void request_stop() { thread.request_stop(); }
    };
    std::unique_ptr<AsyncJob> async_job;

public:
    MessageDialogHolder() = delete;
    MessageDialogHolder(Gtk::Window& _parent) : parent(_parent) { }
    MessageDialogHolder(const MessageDialogHolder& other) = delete;

    void show_message_dialog(const std::variant<std::string,MarkupText>& message, Gtk::MessageType message_type = Gtk::MessageType::INFO);
    void show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<void()> func, Gtk::MessageType message_type = Gtk::MessageType::INFO);
    void show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<void()> posfunc, std::function<void()> negfunc, 
        Gtk::MessageType message_type = Gtk::MessageType::QUESTION, Gtk::ButtonsType buttons_type = Gtk::ButtonsType::OK_CANCEL);
    // cancellable no progressbar
    void show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<bool(std::stop_token)> job, std::function<void()> posfunc, std::function<void()> negfunc);
    // cancellable progressbar
    void show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<bool(std::stop_token,std::function<void(double)>)> job, std::function<void()> posfunc, std::function<void()> negfunc);
    // non-cancellable no progressbar
    void show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<bool()> job, std::function<void()> posfunc, std::function<void()> negfunc);
    // non-cancellable progressbar
    void show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<bool(std::function<void(double)>)> job, std::function<void()> posfunc, std::function<void()> negfunc);
};
