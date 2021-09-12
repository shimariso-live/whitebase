#include <iostream>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "auth.h"

AuthDialog::AuthDialog(Gtk::Window& parent, const std::string& caption, bool use_markup/* = false*/) 
    : MessageDialog(parent, caption, use_markup, Gtk::MessageType::QUESTION, Gtk::ButtonsType::OK_CANCEL, true), 
        queue(std::shared_ptr<GAsyncQueue>(g_async_queue_new(), g_async_queue_unref)),
        auth_thread(nullptr) {
    invalid_password.set_markup("<span foreground=\"#ff0000\">パスワードが正しくありません</span>");
    invalid_password.set_visible(false);
    password_entry.set_input_purpose(Gtk::InputPurpose::PASSWORD);
    password_entry.set_visibility(false);
    get_content_area()->append(invalid_password);
    get_content_area()->append(password_entry);
    set_hide_on_close(true);

    pam_try.connect([this]() { ask_password(); });
    pam_retry.connect([this]() { set_sensitive(true); ask_password(true);});
    pam_success.connect([this]() { hide(); m_auth_success(); });
    pam_fail.connect([this]() { std::cout << "pam_fail" << std::endl; hide(); m_auth_cancelled(); });

    signal_response().connect([this](int res){
        //std::cout << ">>>dialog->response()" << std::endl;
        password = password_entry.get_text();
        if (res == Gtk::ResponseType::OK) {
            if (password == "") return;
            set_sensitive(false);
            g_async_queue_push(queue.get(), (void*)&password);
        } else {
            std::cout << "cancel auth" << std::endl;
            password = "";
            g_async_queue_push(queue.get(), (void*)&password);
            hide();
            m_auth_cancelled();
        }
    });
}

AuthDialog::~AuthDialog()
{
    if (auth_thread) auth_thread->join();
}

void AuthDialog::ask_password(bool fail/* = false*/) {
    //std::cout << "<<<ask_password" << std::endl;
    invalid_password.set_visible(fail);
    set_sensitive(true);
    show();
    //std::cout << ">>>ask_password" << std::endl;
}

void AuthDialog::do_auth() {
    auth_thread = std::shared_ptr<std::thread>(new std::thread([this]{
        std::cout << "auth thread start" << std::endl;
        pam_handle_t *pamh;
        const char* user = getenv("USER");
        if (!user) user = "root";

        struct Env {
            int result = 0;
            bool cancelled = false;
            Glib::Dispatcher& pam_try;
            Glib::Dispatcher& pam_retry;
            Glib::Dispatcher& pam_fail;
            GAsyncQueue* queue;

            Env(Glib::Dispatcher& _pam_try, Glib::Dispatcher& _pam_retry, Glib::Dispatcher& _pam_fail, GAsyncQueue* _queue) 
            : pam_try(_pam_try), pam_retry(_pam_retry), pam_fail(_pam_fail), queue(_queue) {;}
        } env(pam_try, pam_retry, pam_fail, queue.get());

        struct pam_conv conv = {
            [](int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
                std::cout << "conversation start" << std::endl;
                Env& env = *((Env*)appdata_ptr);
                struct pam_response *aresp;
                if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) return PAM_CONV_ERR;
                if ((aresp = (pam_response*)calloc(num_msg, sizeof *aresp)) == NULL) return PAM_BUF_ERR;
    
                for (int i = 0; i < num_msg; i++) {
                    if (msg[i]->msg_style == PAM_ERROR_MSG || msg[i]->msg_style == PAM_TEXT_INFO) {
                        std::cout << msg[i]->msg << std::endl;
                        continue;
                    }
                    if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF && msg[i]->msg_style != PAM_PROMPT_ECHO_ON) continue;
                    //else
                    aresp[i].resp_retcode = 0;

                    if (env.result == PAM_PERM_DENIED) {
                        std::cout << "pam_retry" << std::endl;
                        env.pam_retry();
                    } else {
                        std::cout << "pam_try" << std::endl;
                        env.pam_try();
                    }
                    auto password = (std::string*)g_async_queue_pop(env.queue);
                    if ((*password) == "") env.cancelled = true;
                    else aresp[i].resp = strdup(password->c_str());
                }
                *resp = aresp;
                std::cout << "conversation end" << std::endl;
                return PAM_SUCCESS;
            },
            &env
        };

        pam_start("login", user, &conv, &pamh);
        do {
            env.result = pam_authenticate(pamh, 0);
            std::cout << env.result << std::endl;
        } while (env.result != PAM_SUCCESS && env.result != PAM_ABORT && env.result != PAM_MAXTRIES && env.result != PAM_AUTH_ERR && !env.cancelled);
        pam_end(pamh, env.result);

        if (env.result == PAM_SUCCESS) pam_success();
        else if (!env.cancelled) {
            std::cout << "pam_fail" << std::endl;
            pam_fail();
        }
        std::cout << "auth thread end" << std::endl;
    }));
}
