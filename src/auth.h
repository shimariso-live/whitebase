#include <thread>
#include <memory>
#include <string>
#include <gtkmm.h>

class AuthDialog : public Gtk::MessageDialog {
    Gtk::Label invalid_password;
    Gtk::Entry password_entry;
    std::string password;
    Glib::Dispatcher pam_try, pam_retry, pam_success, pam_fail;
    std::shared_ptr<GAsyncQueue> queue;
    std::shared_ptr<std::thread> auth_thread;

    sigc::signal<void(void)> m_auth_success;
    sigc::signal<void(void)> m_auth_cancelled;
public:
    AuthDialog(Gtk::Window& parent, const std::string& caption, bool use_markup = false); 
    ~AuthDialog();

    void ask_password(bool fail = false);

    void do_auth();

    sigc::signal<void(void)> auth_success() { return m_auth_success; }
    sigc::signal<void(void)> auth_cancelled() { return m_auth_cancelled; }
};
