#include <iostream>
#include "message_dialog_holder.h"

void MessageDialogHolder::show_message_dialog(const std::variant<std::string,MarkupText>& message, Gtk::MessageType message_type/* = Gtk::MessageType::INFO*/)
{
    check_vacancy();
    const auto [actual_message, markup] = classify_message(message);
    dialog.reset(new Gtk::MessageDialog(parent, actual_message, markup, message_type, Gtk::ButtonsType::OK, true));
    dialog->set_hide_on_close();
    dialog->set_deletable(false);
    dialog->signal_response().connect([this](int res){
        dialog->hide();
        dialog_to_be_disposed = std::move(dialog);
    });
    dialog->show();
}

void MessageDialogHolder::show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<void()> func, Gtk::MessageType message_type/* = Gtk::MessageType::INFO*/) {
    check_vacancy();
    const auto [actual_message, markup] = classify_message(message);
    dialog.reset(new Gtk::MessageDialog(parent, actual_message, markup, message_type, Gtk::ButtonsType::OK, true));
    dialog->set_hide_on_close();
    dialog->signal_response().connect([this,func](int res){
        dialog->hide();
        dialog_to_be_disposed = std::move(dialog);
        func();
    });
    dialog->show();
}

void MessageDialogHolder::show_message_dialog(const std::variant<std::string,MarkupText>& message, std::function<void()> posfunc, std::function<void()> negfunc, 
    Gtk::MessageType message_type/* = Gtk::MessageType::INFO*/, Gtk::ButtonsType buttons_type/* = Gtk::ButtonsType::OK_CANCEL*/) {
    check_vacancy();
    const auto [actual_message, markup] = classify_message(message);
    dialog.reset(new Gtk::MessageDialog(parent, actual_message, markup, message_type, buttons_type, true));
    dialog->set_hide_on_close();
    dialog->set_deletable(false);
    dialog->signal_response().connect([this,posfunc,negfunc](int res){
        dialog->hide();
        dialog_to_be_disposed = std::move(dialog);
        if (res == Gtk::ResponseType::OK || res == Gtk::ResponseType::YES || res == Gtk::ResponseType::ACCEPT || res == Gtk::ResponseType::APPLY) {
            posfunc();
        } else {
            negfunc();
        }
    });
    dialog->show();
}

// cancellable no progressbar
void MessageDialogHolder::show_message_dialog(const std::variant<std::string,MarkupText>& message, 
    std::function<bool(std::stop_token)> job, std::function<void()> posfunc, std::function<void()> negfunc) {
    check_vacancy();
    const auto [actual_message, markup] = classify_message(message);
    dialog.reset(new Gtk::MessageDialog(parent, actual_message, markup, Gtk::MessageType::OTHER, Gtk::ButtonsType::CANCEL, true));
    dialog->get_content_area()->append(spinner);
    dialog->set_hide_on_close();
    dialog->set_deletable(false);

    async_job.reset(new AsyncJob(job, [this,posfunc,negfunc](bool finished) {
        spinner.stop();
        dialog->get_content_area()->remove(spinner);
        dialog->hide();
        dialog_to_be_disposed = std::move(dialog);
        if (finished) posfunc();
        else negfunc();
    }));

    dialog->signal_response().connect([this](int res){
        if (res == Gtk::ResponseType::CANCEL && async_job) async_job->request_stop();
    });
    spinner.start();
    dialog->show();
}

// cancellable progressbar
void MessageDialogHolder::show_message_dialog(const std::variant<std::string,MarkupText>& message, 
    std::function<bool(std::stop_token,std::function<void(double)>)> job, std::function<void()> posfunc, std::function<void()> negfunc) {
    check_vacancy();
    const auto [actual_message, markup] = classify_message(message);
    dialog.reset(new Gtk::MessageDialog(parent, actual_message, markup, Gtk::MessageType::OTHER, Gtk::ButtonsType::CANCEL, true));
    dialog->get_content_area()->append(progressbar);
    dialog->set_hide_on_close();
    dialog->set_deletable(false);

    async_job.reset(new AsyncJob(job, [this,posfunc,negfunc](bool finished) {
        dialog->get_content_area()->remove(progressbar);
        dialog->hide();
        dialog_to_be_disposed = std::move(dialog);
        if (finished) posfunc();
        else negfunc();
    }, [this](double progress) {
        progressbar.set_fraction(progress);
    }));

    dialog->signal_response().connect([this](int res){
        if (res == Gtk::ResponseType::CANCEL && async_job) async_job->request_stop();
    });
    spinner.start();
    dialog->show();
}

// non-cancellable no progressbar
void MessageDialogHolder::show_message_dialog(const std::variant<std::string,MarkupText>& message, 
    std::function<bool()> job, std::function<void()> posfunc, std::function<void()> negfunc) {
    check_vacancy();
    const auto [actual_message, markup] = classify_message(message);
    dialog.reset(new Gtk::MessageDialog(parent, actual_message, markup, Gtk::MessageType::OTHER, Gtk::ButtonsType::NONE, true));
    dialog->get_content_area()->append(spinner);
    dialog->set_hide_on_close();
    dialog->set_deletable(false);

    async_job.reset(new AsyncJob([job](std::stop_token) { return job();}, [this,posfunc,negfunc](bool finished) {
        spinner.stop();
        dialog->get_content_area()->remove(spinner);
        dialog->hide();
        dialog_to_be_disposed = std::move(dialog);
        if (finished) posfunc();
        else negfunc();
    }));

    spinner.start();
    dialog->show();
}

// non-cancellable progressbar
void MessageDialogHolder::show_message_dialog(const std::variant<std::string,MarkupText>& message, 
    std::function<bool(std::function<void(double)>)> job, std::function<void()> posfunc, std::function<void()> negfunc) {
    check_vacancy();
    const auto [actual_message, markup] = classify_message(message);
    dialog.reset(new Gtk::MessageDialog(parent, actual_message, markup, Gtk::MessageType::OTHER, Gtk::ButtonsType::NONE, true));
    dialog->get_content_area()->append(progressbar);
    dialog->set_hide_on_close();
    dialog->set_deletable(false);

    async_job.reset(new AsyncJob([job](std::stop_token,std::function<void(double)> progress) { return job(progress);}, [this,posfunc,negfunc](bool finished) {
        dialog->get_content_area()->remove(progressbar);
        dialog->hide();
        dialog_to_be_disposed = std::move(dialog);
        if (finished) posfunc();
        else negfunc();
    }, [this](double progress) {
        progressbar.set_fraction(progress);
    }));

    spinner.start();
    dialog->show();
}

#ifdef __MAIN_MODULE__
static int _main(int argc, char* argv[])
{
    class MainWindow : public Gtk::Window, MessageDialogHolder {
        Gtk::Button button;
    public:
        MainWindow() : MessageDialogHolder((Gtk::Window&)*this), button("ボタソ") { set_child(button); }
        virtual void on_realize() {
            Gtk::Window::on_realize();
            button.signal_clicked().connect([this]() {
                show_message_dialog("HOGE1", [this]() {
                    show_message_dialog("しますか？", [this]() {
                        show_message_dialog("ジョブ", [](/*std::stop_token st,*/std::function<void(double)> progress) {
                            for (int i = 0; i < 10; i++) {
                                std::cout << i << std::endl;
                                progress((i + 1) / 10.0);
                                //if (st.stop_requested()) return false;
                                sleep(1);
                            }
                            return true;
                        }, [this](){
                            show_message_dialog("HI!<b>しました</b>");
                        }, [this](){
                            show_message_dialog("HI!<b>したけどキャンセル</b>");
                        });
                    }, [this]() {
                        show_message_dialog(MarkupText("HI!<b>しませんでした!</b>"));
                    });
                });
            });
        }
    };

    auto app = Gtk::Application::create("org.gtkmm.examples.base");

    return app->make_window_and_run<MainWindow>(argc, argv);
}

int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif
