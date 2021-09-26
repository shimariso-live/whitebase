#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf

#include <unistd.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <glibmm.h>
#include <gdk/gdk.h>
#include <wayland-client.h>
#include <qrencode.h>
#include <iniparser4/iniparser.h>

#include "terminal.h"
#include "volume.h"
#include "gtk4ui.h"
#include "auth.h"
#include "message_dialog_holder.h"
#include "subprocess.h"
#include "vm_op.h"
#include "console.h"
#include "update.h"
#include "wg.h"
#include "yajl_value.h"

static const int WINDOW_WIDTH = 1024;
static const int WINDOW_HEIGHT = 768;

static int shutdown_cmd = 0;

static std::string resource_path(const std::filesystem::path& name)
{
  static const std::filesystem::path default_theme("/usr/share/wb/themes/default");
  return std::filesystem::exists(default_theme / name)? (default_theme / name).string() : name.string();
}

class TitleWindow : public Gtk::Window {
    Gtk::MessageDialog entry_dialog;
    AuthDialog auth_dialog;
    Gtk::Picture m_Title;
public:
    TitleWindow();
    ~TitleWindow() { std::cout << "~TitleWindow" << std::endl; }
};

TitleWindow::TitleWindow() 
    : entry_dialog(*this, "ようこそ", false, Gtk::MessageType::INFO, Gtk::ButtonsType::OK, true), 
        auth_dialog(*this, "パスワード")
{
    set_default_size(WINDOW_WIDTH, WINDOW_HEIGHT);
    auto title_background = Gdk::Pixbuf::create_from_file(resource_path("title_background.png"));
    auto title = Gdk::Pixbuf::create_from_file(resource_path("title.png"));
    auto width = title_background->get_width();
    auto height = title_background->get_height();

    auto surface = Cairo::ImageSurface::create(Cairo::Surface::Format::ARGB32, width, height);
    auto cairo = Cairo::Context::create(surface);
    Gdk::Cairo::set_source_pixbuf(cairo, title_background, 0, 0);
    cairo->paint();
    Gdk::Cairo::set_source_pixbuf(cairo, title, (width - title->get_width()) / 2, (height - title->get_height()) / 2);
    cairo->paint();
    cairo->set_source_rgba(0, 0, 0, 1);
    cairo->set_font_size(height / 22);
    auto copyright = "Copyright © 2009-2021 Walbrix Corporation";
    Cairo::TextExtents extents;
    cairo->get_text_extents(copyright, extents);
    cairo->move_to((width - extents.width) / 2, height - extents.height);
    cairo->show_text(copyright);
    m_Title.set_pixbuf(Gdk::Pixbuf::create(surface, 0, 0, width, height));
    set_child(m_Title);

    ((Gtk::Button*)entry_dialog.get_widget_for_response(Gtk::ResponseType::OK))->set_label("Enterキーで続行");

    entry_dialog.set_hide_on_close();
    entry_dialog.signal_response().connect([this](int response){
        if (!response == Gtk::ResponseType::OK) return;
        //else
        entry_dialog.hide();
        auth_dialog.do_auth();
    });

    auth_dialog.auth_success().connect([this]() {
        close();
    });

    auth_dialog.auth_cancelled().connect([this]() {
        entry_dialog.show();
    });

    entry_dialog.show();
}

class StatusPage : public Gtk::Grid {
    Gtk::Label hdr_serialnumber, hdr_kernel_version, hdr_ipaddress, hdr_cpus, hdr_clock, hdr_memory;
    Gtk::Label serialnumber, kernel_version, ipaddress, cpus, clock, memory;
public:
    StatusPage() : hdr_serialnumber("シリアルナンバー"), hdr_kernel_version("カーネルバージョン"), hdr_ipaddress("IPアドレス"),
        hdr_cpus("論理CPUコア数"), hdr_clock("CPUクロック"), hdr_memory("メモリ容量") {

        set_margin(8);

        auto set_row = [this](Gtk::Label& header_label, Gtk::Label& value_label, const std::string& content, int row, bool selectable = false) {
            header_label.set_margin(4);
            header_label.set_margin_end(16);
            attach(header_label, 0, row);
            value_label.set_label(content);
            value_label.set_halign(Gtk::Align::START);
            if (selectable) value_label.set_selectable();
            attach(value_label, 1, row);
        };

        struct utsname u;
        if (uname(&u) < 0) throw std::runtime_error("uname(2) failed");
        set_row(hdr_serialnumber, serialnumber, u.nodename, 0);
        set_row(hdr_kernel_version, kernel_version, u.release, 1);

        auto ipv4_address = get_ipv4_address();
        set_row(hdr_ipaddress, ipaddress, ipv4_address.value_or("不明"), 2);

        auto ncpu = std::thread::hardware_concurrency();
        set_row(hdr_cpus, cpus, ncpu > 0? std::to_string(ncpu) : "不明", 3);

        auto cpu_clock = get_cpu_clock();
        set_row(hdr_clock, clock, cpu_clock.value_or("不明"), 4);

        auto memory_cap = get_memory_capacity();
        set_row(hdr_memory, memory, memory_cap? ("空き" + std::to_string(memory_cap.value().first) + "MB / 全体" + std::to_string(memory_cap.value().second) + "MB") :"不明", 5);
    }

    static std::optional<std::string> get_interface_name_with_default_gateway() {
        std::ifstream routes("/proc/net/route");
        if (!routes) return std::nullopt;
        std::string line;
        if (!std::getline(routes, line)) return std::nullopt;// skip header
        while (std::getline(routes, line)) {
            std::string ifname;
            auto i = line.begin();
            while (i != line.end() && !isspace(*i)) ifname += *i++;
            if (i == line.end()) continue; // no destination
            while (i != line.end() && isspace(*i)) i++; // skip space(s)
            std::string destination;
            while (i != line.end() && !isspace(*i)) destination += *i++;

            if (destination == "00000000") return ifname;
        }
        return std::nullopt; // not found
    }

    static std::optional<std::string> get_ipv4_address() {
        auto ifname = get_interface_name_with_default_gateway();
        if (!ifname || ifname.value().length() >= IFNAMSIZ) return std::nullopt;
        //else
        auto s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return std::nullopt;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, ifname.value().c_str());
        if (ioctl(s, SIOCGIFADDR, &ifr) < 0) return std::nullopt;
        return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    }

    static std::optional<std::string> get_cpu_clock() {
        std::ifstream cpuinfo("/proc/cpuinfo");
        if (!cpuinfo) return std::nullopt;
        std::string line;
        std::list<int> freqs;
        const char* mhz_header = "cpu MHz		: ";
        const size_t header_len = strlen(mhz_header);
        while (std::getline(cpuinfo, line)) {
            if (!line.starts_with(mhz_header)) continue;
            freqs.push_back((int)atof(line.substr(header_len).c_str()));
        }
        if (freqs.size() == 0) return std::nullopt;
        //else
        auto minmax = std::minmax_element(freqs.begin(), freqs.end());
        int min = *minmax.first;
        int max = *minmax.second;
        if (min == max) return std::to_string(min) + "MHz";
        //else
        return  std::to_string(min) + "-" + std::to_string(max) + "MHz";
    }

    static std::optional<std::pair<int,int> > get_memory_capacity() {
        std::ifstream meminfo("/proc/meminfo");
        if (!meminfo) return std::nullopt;
        std::string line;
        int available = 0, total = 0;
        while (std::getline(meminfo, line)) {
            std::string column_name;
            auto i = line.begin();
            while (i != line.end() && *i != ':') column_name += *i++;
            if (i == line.end()) continue; // unexpected EOL
            i++; // skip ':'
            while (i != line.end() && isspace(*i)) i++; // skip space(s)
            std::string value, unit;
            while (i != line.end() && !isspace(*i)) value += *i++;
            while (i != line.end() && isspace(*i)) i++; // skip space(s)
            if (i != line.end()) {
                while (i != line.end()) unit += *i++;
            }
            if (column_name == "MemTotal" && unit == "kB") total = atoi(value.c_str()) / 1024; // MB
            else if (column_name == "MemAvailable" && unit == "kB") available = atoi(value.c_str()) / 1024; // MB
            if (total > 0 && available > 0) break;
        }
        if (total == 0 || available == 0) return std::nullopt;
        //else
        return std::make_pair(available, total);
    }
};

class VMPage : public Gtk::Notebook, MessageDialogHolder {
    Gtk::Stack list_and_operate, create_new;
    Gtk::Box box, buttons_box, console_box;
    Gtk::Label console_label;
    Gtk::TreeView treeview;
    Terminal console_terminal;
    Gtk::Button reload, start, stop, force_stop, console, _delete, rename, create;

    Glib::RefPtr<Gtk::ListStore> vm_liststore;

    pid_t console_pid;
    int console_fd;
    std::optional<std::string> console_vmname;
    std::optional<sigc::connection> io_signal;
    std::optional<std::pair<int,int>> terminal_size;

    class Columns : public Gtk::TreeModelColumnRecord {
    public:
        Columns() { add(running); add(autostart); add(name); add(volume); add(cpu); add(memory); add(ip_address); }

        Gtk::TreeModelColumn<bool> running;
        Gtk::TreeModelColumn<bool> autostart;
        Gtk::TreeModelColumn<std::string> name;
        Gtk::TreeModelColumn<std::string> volume;
        Gtk::TreeModelColumn<std::string> cpu;
        Gtk::TreeModelColumn<std::string> memory;
        Gtk::TreeModelColumn<std::string> ip_address;
    } columns;

public:
    VMPage(Gtk::Window& _parent) : MessageDialogHolder(_parent), 
        console_pid(0), console_fd(-1),
        box(Gtk::Orientation::VERTICAL) , buttons_box(Gtk::Orientation::HORIZONTAL), console_box(Gtk::Orientation::VERTICAL),
        console_label("コンソールから抜けるには Ctrl+] を押してください"),
        reload("最新の情報に更新(Alt+_R)", true), 
        start("開始(Alt+_T)", true), stop("停止(Alt+_P)", true), force_stop("強制停止(Alt+_K)", true), console("コンソール(Alt+_C)", true),
        _delete("削除(Alt+_D)", true) {

        // setup list and operate page
        treeview.set_expand();
        vm_liststore = Gtk::ListStore::create(columns);
        treeview.set_model(vm_liststore);

        treeview.append_column("稼働", columns.running);
        treeview.append_column("自動起動", columns.autostart);
        treeview.append_column("名前", columns.name);
        treeview.append_column("領域", columns.volume);
        treeview.append_column("CPUコア数", columns.cpu);
        treeview.append_column("メモリ", columns.memory);
        treeview.append_column("IPアドレス", columns.ip_address);

        box.append(treeview);

        buttons_box.append(reload);
        buttons_box.append(start);
        buttons_box.append(stop);
        buttons_box.append(force_stop);
        buttons_box.append(console);
        buttons_box.append(_delete);
        box.append(buttons_box);
        list_and_operate.add(box, "listview");

        // setup console page
        console_box.append(console_label);
        console_terminal.set_expand();
        console_box.append(console_terminal);
        list_and_operate.add(console_box, "console");

        append_page(list_and_operate, "一覧と操作");

        // TODO: setup create page
        append_page(create_new, "新規作成", "new");

        reload.signal_clicked().connect([this]() {do_reload();});

        treeview.signal_cursor_changed().connect([this](){ on_cursor_change(); });

        do_reload();
    }

    ~VMPage() {
        if (io_signal) io_signal->disconnect();
        console_terminal.disconnect(); 
        if (console_fd >= 0) close(console_fd);
        if (console_pid > 0) kill(console_pid, SIGTERM);
        waitpid(console_pid, NULL, 0);
    }

    void do_reload() {
        start.set_sensitive(false);
        stop.set_sensitive(false);
        force_stop.set_sensitive(false);
        console.set_sensitive(false);
        _delete.set_sensitive(false);
        treeview.get_selection()->unselect_all();
        auto vms = list_vm();
        auto get_or_append = [this](const std::string& name) {
            auto i = vm_liststore->get_iter("0");
            while (i) {
                if (i->get_value(columns.name) == name) return i;
                i++;
            }
            return vm_liststore->append();
        };

        for (const auto& i:vms) {
            auto row = get_or_append(i.first);
            row->set_value(columns.name, i.first);
            row->set_value(columns.running, i.second.running);
            row->set_value(columns.autostart, i.second.autostart);
            row->set_value(columns.volume, i.second.volume.value_or("-"));
            row->set_value(columns.cpu, i.second.cpu? std::to_string(i.second.cpu.value()) : std::string("-"));
            row->set_value(columns.memory, i.second.memory? std::to_string(i.second.memory.value()) + "MB" : std::string("-"));
            row->set_value(columns.ip_address, i.second.ip_address.value_or("-"));
        }

        // erase vanished vms
        auto i = vm_liststore->get_iter("0");
        while (i) {
            if (vms.find(i->get_value(columns.name)) == vms.end()) {
                i = vm_liststore->erase(i);
            } else {
                i++;
            }
        }

        if (vms.size() == 0) set_current_page(1);
    }

    void fork_console_subprocess(int cols, int rows, const std::string& name)
    {
        auto console = forkpty([name]() {
            setenv("TERM", "xterm-256color", 1);
            std::cout << "\033[H\033[2J" << std::flush;
            ::console(name);
        }, std::make_optional(std::make_pair(cols, rows)));
        console_pid = console.first;
        console_fd = console.second;
        console_terminal.connect(console_fd);
        write(console_fd, "\n", 1); // to get login pronpt

        if (io_signal) io_signal->disconnect();
        io_signal = Glib::signal_io().connect([this](Glib::IOCondition cond){
            char buf[1024];
            int size = 0;
            if ((int)(cond & Glib::IOCondition::IO_IN) > 0) {
                size = read(console_fd, buf, sizeof(buf));
            }
            if (size == 0) {
                console_terminal.disconnect();
                close(console_fd);
                console_fd = -1;
                waitpid(console_pid, NULL, 0);
                console_pid = 0;
                console_vmname = std::nullopt;
                list_and_operate.set_visible_child("listview");
                return false;
            }
            //else
            console_terminal.process_input(buf, size);
            return true;
        }, console_fd, Glib::IOCondition::IO_IN | Glib::IOCondition::IO_HUP);
    }

    virtual void on_realize() {
        Gtk::Notebook::on_realize();

        start.signal_clicked().connect([this]() { on_click_start(); });
        stop.signal_clicked().connect([this]() { on_click_stop(); });
        force_stop.signal_clicked().connect([this]() { on_click_force_stop(); });
        console.signal_clicked().connect([this]() { on_click_console(); });
        _delete.signal_clicked().connect([this]() { on_click_delete(); });

        console_terminal.signal_open_terminal().connect([this]() {
            if (console_vmname) fork_console_subprocess(terminal_size->first, terminal_size->second, console_vmname.value());
        });
        console_terminal.signal_resize_terminal().connect([this](int cols, int rows) {
            terminal_size = {cols, rows};
        });
    }

    std::optional<std::string> get_selected_vm_name() {
        auto i = treeview.get_selection()->get_selected();
        return i? std::make_optional(i->get_value(columns.name)) : std::nullopt;
    }

    void on_cursor_change() {
        auto selected_rows = treeview.get_selection()->get_selected();
        if (!selected_rows) return;
        if (selected_rows->get_value(columns.running)) {
            start.set_sensitive(false);
            stop.set_sensitive(true);
            force_stop.set_sensitive(true);
            console.set_sensitive(true);
            _delete.set_sensitive(false);
        } else {
            start.set_sensitive(true);
            stop.set_sensitive(false);
            force_stop.set_sensitive(false);
            console.set_sensitive(false);
            _delete.set_sensitive(true);
        }
    }

    void on_click_start() {
        auto _name = get_selected_vm_name();
        if (!_name) return;
        //else
        auto name = _name.value();

        show_message_dialog("仮想マシンを開始中...", [name]() {
            return call({"systemctl", "start", std::string("vm@") + name}) == 0 && is_running(name);
        }, [this,name]() {
            show_message_dialog(name + "を開始しました", [this]() {
                do_reload();
            });
        }, [this,name]() {
            show_message_dialog(name + "を開始できませんでした", Gtk::MessageType::ERROR);
        });
    }

    void on_click_stop() {
        auto _name = get_selected_vm_name();
        if (!_name) return;
        //else
        auto name = _name.value();

        show_message_dialog(name + "に停止要求を送信します。よろしいですか？", [this,name]() {
            if (call({"systemctl", "stop", "--no-block", std::string("vm@") + name}, true) == 0) {
                show_message_dialog(name + "に停止要求を送信しました", [this]() {
                    do_reload();
                });
            } else {
                show_message_dialog(name + "に停止要求を送信できませんでした", Gtk::MessageType::ERROR);
            }
        }, []() {
            // cancelled by user
        });
    }

    void on_click_force_stop() {
        auto _name = get_selected_vm_name();
        if (!_name) return;
        //else
        auto name = _name.value();

        show_message_dialog(name + "を強制停止します。よろしいですか？", [this,name]() {
            if (call({"systemctl", "kill", std::string("vm@") + name}, true) == 0) {
                show_message_dialog(name + "を強制停止しました", [this]() {
                    do_reload();
                });
            } else {
                show_message_dialog(name + "を強制停止できませんでした", Gtk::MessageType::ERROR);
            }
        }, []() {
            // cancelled by user
        });
    }

    void on_click_console() {
        auto _name = get_selected_vm_name();
        if (!_name) return;
        //else
        console_vmname = _name.value();

        console.grab_focus();
        list_and_operate.set_visible_child("console");
        if (terminal_size) fork_console_subprocess(terminal_size->first, terminal_size->second, console_vmname.value());
        // defer fork when terminal hasn't opened yet
    }

    void on_click_delete() {
        auto _name = get_selected_vm_name();
        if (!_name) return;
        //else
        auto name = _name.value();

        show_message_dialog(name + "を削除します。よろしいですか？", [this,name]() {
            if (delete_vm(name) == 0) {
                show_message_dialog(name + "を削除しました", [this]() {
                    do_reload();
                });
            } else {
                show_message_dialog(name + "を削除できませんでした", Gtk::MessageType::ERROR);
            }
        }, []() {
            // cancelled by user
        });
    }
};

class VolumePage : public Gtk::Notebook {
    Gtk::Box buttons_box, create_page;
    Gtk::TreeView treeview;

    Glib::RefPtr<Gtk::ListStore> volume_liststore;

    class Columns : public Gtk::TreeModelColumnRecord {
    public:
        Columns() { add(online); add(name); add(path); add(device_or_uuid); add(fstype); add(size); add(free); }

        Gtk::TreeModelColumn<bool> online;
        Gtk::TreeModelColumn<std::string> name;
        Gtk::TreeModelColumn<std::string> path;
        Gtk::TreeModelColumn<std::string> device_or_uuid;
        Gtk::TreeModelColumn<std::string> fstype;
        Gtk::TreeModelColumn<std::string> size;
        Gtk::TreeModelColumn<std::string> free;
    } columns;
public:
    VolumePage() {
        treeview.set_expand();
        volume_liststore = Gtk::ListStore::create(columns);
        treeview.set_model(volume_liststore);

        treeview.append_column("オンライン", columns.online);
        treeview.append_column("名前", columns.name);
        treeview.append_column("パス", columns.path);
        treeview.append_column("デバイス名又はUUID", columns.device_or_uuid);
        treeview.append_column("ファイルシステム", columns.fstype);
        treeview.append_column("全容量", columns.size);
        treeview.append_column("空き容量", columns.free);

        append_page(treeview, "一覧と操作");
        append_page(create_page, "新規作成");

        do_reload();
    }

    void do_reload()
    {
        treeview.get_selection()->unselect_all();
        auto volumes = volume_list();

        auto get_or_append = [this](const std::string& name) {
            auto i = volume_liststore->get_iter("0");
            while (i) {
                if (i->get_value(columns.name) == name) return i;
                i++;
            }
            return volume_liststore->append();
        };

        for (const auto& i:volumes) {
            auto row = get_or_append(i.first);
            row->set_value(columns.name, i.first);
            row->set_value(columns.online, i.second.online);
            row->set_value(columns.path, i.second.path.string());
            row->set_value(columns.device_or_uuid, i.second.device_or_uuid);
            row->set_value(columns.fstype, i.second.fstype.value_or("-"));
            row->set_value(columns.size, i.second.size? human_readable(i.second.size.value()) : std::string("-"));
            row->set_value(columns.free, i.second.free? human_readable(i.second.free.value()) : std::string("-"));
        }

        // erase vanished volumes
        auto i = volume_liststore->get_iter("0");
        while (i) {
            if (volumes.find(i->get_value(columns.name)) == volumes.end()) {
                i = volume_liststore->erase(i);
            } else {
                i++;
            }
        }

    }
};

class ConsolePage : public Gtk::Stack {
    Gtk::Box m_box_button, m_box_terminal;
    Gtk::Label m_label_description, m_label_howtoclose;
    Gtk::Button m_button;
    Terminal m_terminal;
    pid_t shell_pid;
    int shell_fd;
    std::optional<sigc::connection> io_signal;
    std::optional<std::pair<int,int>> terminal_size;
public:
    ConsolePage(): shell_pid(0), shell_fd(-1), m_box_button(Gtk::Orientation::VERTICAL), m_box_terminal(Gtk::Orientation::VERTICAL), 
        m_button("コンソールを開く(Alt+_C)", true),
        m_label_description("Linuxのコマンドラインで直接システムを操作します"), 
        m_label_howtoclose("exit コマンドでコンソールを終了します")  {

        m_label_description.set_margin_bottom(10);
        m_button.set_halign(Gtk::Align::CENTER);
        m_box_button.append(m_label_description);
        m_box_button.append(m_button);
        m_box_button.set_valign(Gtk::Align::CENTER);
        add(m_box_button, "button");

        m_label_howtoclose.set_halign(Gtk::Align::START);
        m_label_howtoclose.set_margin(4);
        m_box_terminal.append(m_label_howtoclose);
        m_terminal.set_expand();
        m_box_terminal.append(m_terminal);
        add(m_box_terminal, "terminal");
        set_transition_type(Gtk::StackTransitionType::CROSSFADE);

        m_terminal.signal_open_terminal().connect([this]() {
            fork_shell_subprocess(terminal_size->first, terminal_size->second);
        });
        m_terminal.signal_resize_terminal().connect([this](int cols, int rows) {
            //std::cout << "terminal size" << cols << ',' << rows << std::endl;
            terminal_size = {cols, rows};
        });
        m_button.signal_clicked().connect([this]() {
            m_button.grab_focus();
            set_visible_child("terminal");
            if (terminal_size) fork_shell_subprocess(terminal_size->first, terminal_size->second);
            // defer fork when terminal hasn't opened yet
        });
    }
    ~ConsolePage() { 
        if (io_signal) io_signal->disconnect();
        m_terminal.disconnect(); 
        if (shell_fd >= 0) close(shell_fd);
        if (shell_pid > 0) kill(shell_pid, SIGTERM);
        waitpid(shell_pid, NULL, 0);
    }
    void fork_shell_subprocess(int cols, int rows)
    {
        auto shell_subprocess = []() {
            setenv("TERM", "xterm-256color", 1);
            std::cout << "\033[H\033[2J" << std::flush;
            struct utsname uname_buf;
            if (uname(&uname_buf) == 0) {
                std::cout << uname_buf.sysname << ' ' << uname_buf.release << std::endl << std::endl;
            }

            if (geteuid() == 0) {
                exec({"login", "-f", "root"});
            } else {
                const char* shell = getenv("SHELL");
                if (!shell) shell = "/bin/bash";
                exec({shell, "-"});
            }
        };
        auto shell = forkpty(shell_subprocess, std::make_optional(std::make_pair(cols, rows)));
        shell_pid = shell.first;
        shell_fd = shell.second;
        m_terminal.connect(shell_fd);

        if (io_signal) io_signal->disconnect();
        io_signal = Glib::signal_io().connect([this](Glib::IOCondition cond){
            char buf[1024];
            int size = 0;
            if ((int)(cond & Glib::IOCondition::IO_IN) > 0) {
                size = read(shell_fd, buf, sizeof(buf));
                //std::cout << size << std::endl;
            }
            if (size == 0) {
                m_terminal.disconnect();
                close(shell_fd);
                shell_fd = -1;
                waitpid(shell_pid, NULL, 0);
                shell_pid = 0;
                //fork_shell_subprocess(m_terminal.get_cols(), m_terminal.get_rows());
                set_visible_child("button");
                return false;
            }
            //else
            m_terminal.process_input(buf, size);
            return true;
        }, shell_fd, Glib::IOCondition::IO_IN | Glib::IOCondition::IO_HUP);
    }
};

class KeyboardSettings : public Gtk::Frame, MessageDialogHolder {
    Gtk::Box inner;

    Gtk::Label label;
    Gtk::ComboBoxText selection;
    Gtk::Button apply;

    sigc::signal<void(std::string)> _signal_restart;
public:
    KeyboardSettings(Gtk::Window& parent) : MessageDialogHolder(parent), Gtk::Frame("キーボード設定"), inner(Gtk::Orientation::HORIZONTAL),
        label("キーボードの種類"), apply("適用") {

        label.set_margin_end(8);
        inner.append(label);

        selection.append("jp106", "日本語");
        selection.append("", "英語");
        selection.set_margin_end(8);
        inner.append(selection);

        apply.set_sensitive(false);
        apply.signal_clicked().connect([this]() {
            auto keymap = selection.get_active_id();
            if (call({"localectl", "set-keymap", keymap}) == 0) {
                apply.set_sensitive(false);
                _signal_restart("設定変更を反映するためにログアウトしますか？");
            } else {
                show_message_dialog("キーボード設定を変更できませんでした(localectl)", Gtk::MessageType::ERROR);
            }
        });
        inner.append(apply);

        set_hexpand();
        set_vexpand(false);
        set_child(inner);
    }

    virtual void on_realize() {
        Gtk::Frame::on_realize();
        auto weston_config_file = getenv("WESTON_CONFIG_FILE");
        std::string keymap_layout = "";
        if (weston_config_file && std::filesystem::exists(weston_config_file)) {
            std::shared_ptr<dictionary> ini(iniparser_load(weston_config_file), iniparser_freedict);
            keymap_layout = iniparser_getstring(ini.get(), "keyboard:keymap_layout", "");
        }
        std::map<std::string,std::string> keymap_layout_to_model = {
            {"jp", "jp106"}
        };
        selection.set_active_id(keymap_layout_to_model[keymap_layout]);
        selection.signal_changed().connect([this]() { // must be after setting first selection
            apply.set_sensitive(true);
        });
    }

    sigc::signal<void(std::string)> signal_restart() { return _signal_restart; }
};

class CentralServer : public Gtk::Frame, MessageDialogHolder {
    Gtk::Box inner;
    Gtk::Box status_header;
    Gtk::Label status_label;
    Gtk::DrawingArea qrcode_area;
    std::shared_ptr<QRcode> qrcode;
    std::optional<std::string> pubkey_b64;
    Gtk::Button reload_button, connect, disconnect;
    Gtk::CheckButton accept_ssh_key;

    struct {
        int status;
        std::optional<std::string> pubkey_b64;
    } async_result;
public:
    CentralServer(Gtk::Window& parent) : MessageDialogHolder(parent), Gtk::Frame("中央サーバー"), inner(Gtk::Orientation::VERTICAL),
        status_header(Gtk::Orientation::HORIZONTAL),
        reload_button("最新の情報に更新(_R)", true), 
        connect("中央サーバへ接続する(_C)", true), disconnect("中央サーバから切断する(_D)", true), 
        accept_ssh_key("開発元からの遠隔ログインを受け入れる(_A)", true) {

        status_label.set_hexpand();
        status_header.append(status_label);
        status_header.append(reload_button);

        reload_button.signal_clicked().connect([this]() { reload(); });

        qrcode_area.set_expand();
        qrcode_area.set_draw_func([this](const Cairo::RefPtr<Cairo::Context>& cairo, int width, int height) {
            if (!qrcode) return;
            int size = std::min(width, height);
            int content_size = size * 9 / 10, hmargin = (width - content_size) / 2, vmargin = (height - content_size) / 2;
            int square_size = content_size / qrcode->width;

            cairo->set_source_rgb(1.0, 1.0, 1.0);
            cairo->rectangle(0, 0, width, height);
            cairo->fill();

            cairo->set_source_rgb(0.0, 0.0, 0.0);

            for (int y = 0; y < qrcode->width; y++) {
                for (int x = 0; x < qrcode->width; x++) {
                    if (qrcode->data[y * qrcode->width + x] & 1) {
                        cairo->rectangle(x * square_size + hmargin, y * square_size + vmargin, square_size, square_size);
                    }
                }
            }
            cairo->fill();
        });

        connect.signal_clicked().connect([this]() {
            try {
                if (wg_getconfig(accept_ssh_key.get_active()) == 0) {
                    check_call({"systemctl", "start", "wg-quick@wg-walbrix"});
                    check_call({"systemctl", "enable", "wg-quick@wg-walbrix"});
                }
                reload();
            }
            catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
            }
        });

        disconnect.signal_clicked().connect([this]() {
            if (call({"systemctl", "stop", "wg-quick@wg-walbrix"}) == 0) {
                call({"systemctl", "disable", "wg-quick@wg-walbrix"});
                reload();
            }
        });

        set_expand();
        set_child(inner);
        inner.append(status_header);
        inner.append(qrcode_area);
        inner.append(accept_ssh_key);
        inner.append(connect);
        inner.append(disconnect);
    }

    void reload() {
        show_message_dialog("読み込み中...", [this](){
            async_result.status = 0;
            try {
                async_result.pubkey_b64 = get_pubkey_b64();
            }
            catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
            }
            if (call({"systemctl", "is-active", "wg-quick@wg-walbrix"}) == 0) async_result.status = 2;
            else if (async_result.pubkey_b64 && get_content_length(get_authorization_url(async_result.pubkey_b64.value()))) async_result.status = 1;
            return true;
        }, [this](){
            pubkey_b64 = async_result.pubkey_b64;
            if (async_result.status == 0/*not even authorized*/) {
                status_label.set_text("中央サーバへの接続承認を受けるには下記のQRコードを\n読み取って承認依頼メールを送信してください。\n接続が承認されたら「最新の情報に更新」を押して\n接続処理へ進みます");
                qrcode_area.show();
                connect.hide();
                disconnect.hide();
                accept_ssh_key.hide();

                if (pubkey_b64) {
                    std::string content = "mailto:csr@walbrix.net?subject=authorization request&body=" + pubkey_b64.value();
                    qrcode = std::shared_ptr<QRcode>(QRcode_encodeString(content.c_str(), 0, QR_ECLEVEL_L, QR_MODE_8, 1), QRcode_free);
                }
            } else if (async_result.status == 1/*authorized but not connected*/) {
                status_label.set_text("中央サーバへの接続承認が完了しています。");
                qrcode_area.hide();
                connect.show();
                disconnect.hide();
                accept_ssh_key.show();
            } else {// connected
                status_label.set_text("中央サーバへ接続済みです");
                qrcode_area.hide();
                connect.hide();
                disconnect.show();
                accept_ssh_key.hide();
            }
        }, [this](){
            show_message_dialog("中央サーバへの接続ステータスチェックに失敗しました", Gtk::MessageType::ERROR);
        });
    }

    virtual void on_realize() {
        Gtk::Frame::on_realize();
        reload();
    }
};

class SoftwareUpdate : public Gtk::Frame, MessageDialogHolder{
    Gtk::Box inner;
    Gtk::Grid grid;
    Gtk::Button download_button;
    Gtk::CheckButton include_unstable;

    Gtk::Label present_version_label, present_version_value;
    Gtk::Label downloaded_version_label, downloaded_version_value;
    Gtk::Label available_version_label, available_version_value;

    Gtk::Label need_reboot;

    std::optional<std::tuple<std::string,std::string,size_t>> available_version;

    struct {
        std::optional<std::string> present_version;
        std::optional<std::string> downloaded_version;
        std::optional<std::tuple<std::string,std::string,size_t>> available_version;
    } async_result;

    bool postpone_reboot;

    sigc::signal<void(std::string)> _signal_reboot;
public:
    SoftwareUpdate(Gtk::Window& parent) : MessageDialogHolder(parent), Gtk::Frame("ソフトウェア更新"), inner(Gtk::Orientation::VERTICAL), 
        present_version_label("現在稼働中のバージョン"), downloaded_version_label("ダウンロード済みのバージョン"), available_version_label("利用可能なバージョン"),
        download_button("ダウンロード(_L)", true), include_unstable("未テストのバージョンも含める", true), 
        need_reboot("ダウンロード済みバージョンを有効にするにはシステムを再起動してください"), postpone_reboot(false) {

        // setup grid
        std::vector<std::pair<Gtk::Label&,Gtk::Widget&>> grid_labels({
            {present_version_label, present_version_value}, 
            {downloaded_version_label, downloaded_version_value}, 
            {available_version_label, available_version_value}
        });
        int row = 0;
        for (const auto& i : grid_labels) {
            i.first.set_margin(4);
            i.first.set_margin_end(16);
            grid.attach(i.first, 0, row);
            i.second.set_halign(Gtk::Align::START);
            grid.attach(i.second, 1, row++);
        }

        inner.append(grid);

        include_unstable.signal_toggled().connect([this]() {
            reload();
        }, true);

        inner.append(include_unstable);
        inner.append(download_button);
        download_button.set_sensitive(false);
        download_button.signal_clicked().connect([this]() {
            download();
        });
        inner.append(need_reboot);
        need_reboot.hide();
        set_expand();
        set_child(inner);
    }

    static bool left_version_newer_than_right(const std::string& left, const std::string& right) {
        auto parse_version = [](const std::string& version_str) -> std::tuple<int,int,int,int> {
            int maj = 0, min = 0, rel = 0, rev = 0;
            try {
                auto dot1 = version_str.find_first_of('.');
                if (dot1 != version_str.npos) {
                    maj = std::stoi(version_str.substr(0, dot1));
                    auto dot2 = version_str.find_first_of('.', dot1 + 1);
                    if (dot2 != version_str.npos) {
                        min = std::stoi(version_str.substr(dot1 + 1, dot2 - dot1 - 1));
                        auto dash = version_str.find_first_of("-r", dot2 + 1);
                        if (dash != version_str.npos) {
                            rel = std::stoi(version_str.substr(dot2 + 1, dash - dot2 - 1));
                            rev = std::stoi(version_str.substr(dash + 2));
                        } else {
                            rel = std::stoi(version_str.substr(dot2 + 1));
                        }
                    }
                }
            }
            catch (const std::logic_error& e) {
                // abandon further parse
            }
            return {maj, min, rel, rev};
        };

        if (left == "HEAD") return true;

        auto left_parsed = parse_version(left);
        auto right_parsed = parse_version(right);

        if (std::get<0>(left_parsed) > std::get<0>(right_parsed)) return true;
        //else
        if (std::get<0>(left_parsed) < std::get<0>(right_parsed)) return false;
        //else
        if (std::get<1>(left_parsed) > std::get<1>(right_parsed)) return true;
        //else
        if (std::get<1>(left_parsed) < std::get<1>(right_parsed)) return false;
        //else
        if (std::get<2>(left_parsed) > std::get<2>(right_parsed)) return true;
        //else
        if (std::get<2>(left_parsed) < std::get<2>(right_parsed)) return false;
        //else
        if (std::get<3>(left_parsed) > std::get<3>(right_parsed)) return true;
        //else
        return false;
    }

    void reload() {
        show_message_dialog("ソフトウェアの更新版を確認中...", [this]() {
            try {
                async_result.present_version = get_present_version();
                if (get_present_system_image_path() != system_img) {
                    async_result.downloaded_version = get_version_from_system_image_file(system_img);
                }
                async_result.available_version = get_latest_version(include_unstable.get_active());
            }
            catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
                return false;
            }
            return true;
        }, [this]() {
            present_version_value.set_text(async_result.present_version.value_or("-"));
            downloaded_version_value.set_text(async_result.downloaded_version.value_or("-"));
            available_version_value.set_text(
                async_result.available_version? 
                    (std::get<0>(async_result.available_version.value()) + " (" + human_readable(std::get<2>(async_result.available_version.value())) + "B)")
                    : "-");
            if (async_result.downloaded_version) need_reboot.show();
            bool enable_download = false;
            if (async_result.available_version) {
                available_version = async_result.available_version;
                const auto& av = std::get<0>(available_version.value());
                if (!async_result.present_version && !async_result.downloaded_version) enable_download = true;
                if (async_result.present_version && left_version_newer_than_right(av, async_result.present_version.value())) enable_download = true;
                if (async_result.downloaded_version && left_version_newer_than_right(av, async_result.downloaded_version.value())) enable_download = true;
            }
            download_button.set_sensitive(enable_download);

            if (async_result.downloaded_version) {
                if (!postpone_reboot) _signal_reboot("新しいバージョンを有効にするため再起動しますか？");
                postpone_reboot = true;
            }
        }, [this]() {
            show_message_dialog("ソフトウェアの更新版チェックに失敗しました", Gtk::MessageType::ERROR);
        });
    }

    void download() {
        if (!available_version) return;
        auto size = human_readable(std::get<2>(available_version.value())) + "B";
        auto version = std::get<0>(available_version.value());
        show_message_dialog("バージョン " + version + " (" + size + ")をダウンロード中...", [this](std::stop_token st, std::function<void(double)> progress) {
            BootPartitionLock lock(true/*nonblocking*/);
            if (!lock) return false;
            //else
            return download_system_image(std::get<1>(available_version.value()), std::get<2>(available_version.value()), st, progress);
        }, [this]() {
            postpone_reboot = false;
            reload();
        }, [this]() {
            show_message_dialog("ダウンロードが中断されました", Gtk::MessageType::WARNING);
        });
    }

    virtual void on_realize() {
        Gtk::Frame::on_realize();
        reload();
    }

    sigc::signal<void(std::string)> signal_reboot() { return _signal_reboot; }
};

class SettingsPage : public Gtk::Box {
    Gtk::Box vbox_left, vbox_right;
    KeyboardSettings keyboard_settings;
    CentralServer central_server;
    SoftwareUpdate software_update;
    sigc::signal<void(std::string,bool)> _signal_reboot;
public:
    SettingsPage(Gtk::Window& parent) : keyboard_settings(parent), central_server(parent), software_update(parent), 
        Gtk::Box(Gtk::Orientation::HORIZONTAL), vbox_left(Gtk::Orientation::VERTICAL), vbox_right(Gtk::Orientation::VERTICAL) {

        keyboard_settings.signal_restart().connect([this](std::string message) {
            _signal_reboot(message, false);
        });
        vbox_left.append(keyboard_settings);
        append(vbox_left);
        vbox_right.append(central_server);
        software_update.signal_reboot().connect([this](std::string message) {
            _signal_reboot(message, true);
        });
        vbox_right.append(software_update);
        append(vbox_right);
    }
    sigc::signal<void(std::string,bool)> signal_reboot() { return _signal_reboot; }
};

class ShutdownPage : public Gtk::Box {
    Gtk::Label m_label;
    Gtk::Button m_exit_button, m_shutdown_button, m_reboot_button;
    Gtk::Separator m_sep;
    std::unique_ptr<Gtk::MessageDialog> m_pDialog;
    sigc::signal<void(int)> m_signal_quit;
public:
    ShutdownPage(bool login) : Gtk::Box(Gtk::Orientation::VERTICAL), 
        m_label("シャットダウン・再起動"), 
        m_exit_button(login? "タイトルに戻る":"終了する(Alt+_X)", true), m_shutdown_button("シャットダウン"), m_reboot_button("再起動") {
        m_exit_button.signal_clicked().connect([this]() {
            m_signal_quit(0);
        });

        m_shutdown_button.signal_clicked().connect([this]() {
            m_signal_quit(1);
        });

        m_reboot_button.signal_clicked().connect([this]() {
            m_signal_quit(2);
        });

        m_label.set_margin(10);
        append(m_label);

        m_exit_button.set_margin(10);
        append(m_exit_button);

        if (login) {
            m_sep.set_margin_top(10);
            m_sep.set_margin_bottom(10);
            append(m_sep);
            m_shutdown_button.set_margin(10);
            append(m_shutdown_button);
            m_reboot_button.set_margin(10);
            append(m_reboot_button);
        }
    }
    sigc::signal<void(int)> signal_quit() { return m_signal_quit; }
};

class HeaderPicture : public Gtk::Picture {
public:
    HeaderPicture() {
        auto header = Gdk::Pixbuf::create_from_file(resource_path("header.png"));
        auto header_logo = Gdk::Pixbuf::create_from_file(resource_path("header_logo.png"));
        header_logo->composite(header, 0, 0, header_logo->get_width(), header_logo->get_height(), 0, 0, 1, 1, Gdk::InterpType::BILINEAR, 255);
        set_pixbuf(header);
        set_valign(Gtk::Align::START);
    }
};

class FooterPicture : public Gtk::Picture {
public:
    FooterPicture() {
        set_pixbuf(Gdk::Pixbuf::create_from_file(resource_path("footer.png")));
        set_valign(Gtk::Align::END);
    }
};

class MainWindow : public Gtk::Window, MessageDialogHolder
{
    HeaderPicture header;
    FooterPicture footer;
    Gtk::Stack m_stack;
    Gtk::StackSidebar m_sidebar;
    Gtk::Overlay overlay;
    Gtk::Spinner spinner;
    Gtk::Box m_box, m_sidebar_stack_box;

    StatusPage m_status_page;
    VMPage m_vm_page;
    VolumePage m_volume_page;
    ConsolePage m_console_page;
    SettingsPage m_settings_page;
    ShutdownPage m_shutdown_page;
public:
    MainWindow(bool login = false);
    virtual void on_enter_async_job();
    virtual void on_leave_async_job();
};

MainWindow::MainWindow(bool login) : MessageDialogHolder((Gtk::Window&)*this), m_vm_page(*this), m_settings_page(*this), m_shutdown_page(login), m_box(Gtk::Orientation::VERTICAL), m_sidebar_stack_box(Gtk::Orientation::HORIZONTAL)
{
    set_default_size(WINDOW_WIDTH, WINDOW_HEIGHT);

    m_stack.add(m_status_page, "status", "状態");
    m_stack.add(m_vm_page, "vm", "仮想マシン");
    m_stack.add(m_volume_page, "volume", "領域");
    m_stack.add(m_console_page, "console", "Linuxコンソール");
    m_stack.add(m_settings_page, "settings", "設定");
    m_stack.add(m_shutdown_page, "shutdown", login? "終了と再起動" : "終了");
    m_stack.set_expand();
    m_stack.set_transition_type(Gtk::StackTransitionType::SLIDE_UP_DOWN);

    m_sidebar_stack_box.append(m_sidebar);
    m_sidebar_stack_box.append(m_stack);
    m_sidebar_stack_box.set_expand();
    m_sidebar.set_stack(m_stack);
    m_status_page.set_focusable(false);

    m_shutdown_page.signal_quit().connect([this](int _shutdown_cmd) {
        if (_shutdown_cmd > 0) {
            auto message = (_shutdown_cmd == 1)? "システムをシャットダウンします。よろしいですか？" : "システムを再起動します。よろしいですか？";
            show_message_dialog(message, [this, _shutdown_cmd](){
                shutdown_cmd = _shutdown_cmd;
                close();
            }, [](){
                // cancelled
            }, Gtk::MessageType::WARNING);
        } else {
            close();
        }
    });

    m_settings_page.signal_reboot().connect([this](std::string message, bool hard) {
        show_message_dialog(message, [this,hard](){
            shutdown_cmd = hard? 2/*reboot*/:3/*just restart ui*/;
            close();
        }, [](){
            // cancelled
        }, Gtk::MessageType::WARNING, Gtk::ButtonsType::YES_NO);
    });

    m_box.append(header);
    m_box.append(m_sidebar_stack_box);
    m_box.append(footer);

    overlay.set_child(m_box);
    spinner.set_expand(false);
    set_child(overlay);
}

void MainWindow::on_enter_async_job()
{
    overlay.add_overlay(spinner);
    spinner.start();
    m_box.set_sensitive(false);
}

void MainWindow::on_leave_async_job()
{
    spinner.stop();
    overlay.remove_overlay(spinner);
    m_box.set_sensitive(true);
}

class InstallerWindow : public Gtk::Window {
    HeaderPicture header;
    FooterPicture footer;
    Gtk::Label content;
    Gtk::Notebook notebook;
    Gtk::Box box;
    ConsolePage console;
public:
    InstallerWindow() : content("Walbrix インストーラー"), box(Gtk::Orientation::VERTICAL) {
        notebook.append_page(content, "インストール");
        notebook.append_page(console, "Linuxコンソール");
        notebook.set_vexpand();

        box.append(header);
        box.append(notebook);
        box.append(footer);
        set_child(box);
    }
};

static const char* app_name = "com.walbrix.wb";

int gtk4installer(const std::vector<std::string>& args)
{
    auto rst = Gtk::Application::create(app_name)->make_window_and_run<InstallerWindow>(0, nullptr);
    if (shutdown_cmd == 1) {
        rst = call({"/bin/systemctl", "poweroff"});
    } else if (shutdown_cmd == 2) {
        rst = call({"/bin/systemctl", "reboot"});
    }
    // 0, 3: just quit
    return rst;
}

int gtk4ui(const std::vector<std::string>& args)
{
    auto rst = Gtk::Application::create(app_name)->make_window_and_run<MainWindow>(0, nullptr, false);
    if (shutdown_cmd == 1) {
        rst = call({"/bin/systemctl", "poweroff"});
    } else if (shutdown_cmd == 2) {
        rst = call({"/bin/systemctl", "reboot"});
    }
    // 0, 3: just quit
    return rst;
}

static bool ping()
{
    std::shared_ptr<wl_display> display(wl_display_connect(NULL), wl_display_disconnect);

    if (!display) {
        throw std::runtime_error("Can't connect to display");
    }

    //else
    bool output = false;
    struct wl_registry *registry = wl_display_get_registry(display.get());
    const struct wl_registry_listener registry_listener = {
        [](void *data, struct wl_registry *, uint32_t,const char *interface, uint32_t){
            if (std::string(interface) == "wl_output") *((bool *)data) = true;
        }, NULL
    };
    wl_registry_add_listener(registry, &registry_listener, &output);

    wl_display_dispatch(display.get());
    wl_display_roundtrip(display.get());

    return output;
}

int gtk4login(const std::vector<std::string>& args)
{
    try {
        while (!ping()) {
            sleep(1);
        }
    }
    catch (const std::exception& ex) {
        ;
    }

    class AppWindow : public Gtk::Window {
        std::unique_ptr<Gtk::Window> title_window;
        std::unique_ptr<Gtk::Window> main_window;
    public:
        AppWindow() {
            set_can_focus(false);
            title_window.reset(new TitleWindow());
            title_window->set_hide_on_close(true);
            title_window->signal_hide().connect([this]() {
                main_window.reset(new MainWindow(true));
                main_window->set_hide_on_close(true);
                main_window->signal_hide().connect([this]() {
                    close();
                });
                main_window->show();
            });
            title_window->show();
        }
    };

    int rst;
    while (shutdown_cmd == 0) {
        auto app = Gtk::Application::create(app_name);
        rst = app->make_window_and_run<AppWindow>(0, nullptr);
    }
    if (shutdown_cmd == 1) {
        rst = call({"/bin/systemctl", "poweroff"});
    } else if (shutdown_cmd == 2) {
        rst = call({"/bin/systemctl", "reboot"});
    }
    // 3 : just restart ui
    return rst;
}

static int authtest(const std::vector<std::string>& args)
{
    class DoSomethingWindow : public Gtk::Window {
        AuthDialog dialog;
    public:
        DoSomethingWindow() : dialog(*this, "パスワード") {
            dialog.auth_success().connect([]() {
                std::cout << "Auth success!" << std::endl;
            });
            dialog.auth_cancelled().connect([]() {
                std::cout << "Auth cancelled!" << std::endl;
            });
            dialog.do_auth();
        }
        ~DoSomethingWindow() {
        }
    };

    return Gtk::Application::create(app_name)->make_window_and_run<DoSomethingWindow>(0, nullptr);
}

static int _main(int,char*[])
{
    return gtk4ui({});
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif
