#include <unicode/unistr.h>
#include <unicode/normlzr.h>

#include "terminal.h"

Terminal::Terminal(int _font_size/* = 20*/) : font_size(_font_size), fd(-1), vterm(nullptr), screen(nullptr) {
    set_draw_func([this](const Cairo::RefPtr<Cairo::Context>& cairo, int width, int height) {
        if (!vterm || !matrix || !surface) return;
        //std::cout << "draw" << std::endl;
        Pango::FontDescription desc("monospace");
        desc.set_absolute_size(font_size * PANGO_SCALE);
        auto surface_cairo = Cairo::Context::create(surface);
        auto get_color = [this](VTermScreenCell& cell) {
            std::tuple<double,double,double> color = {0.5, 0.5, 0.5};
            std::tuple<double,double,double> bgcolor = {0, 0, 0};
            if (VTERM_COLOR_IS_INDEXED(&cell.fg)) {
                vterm_screen_convert_color_to_rgb(screen, &cell.fg);
            }
            if (VTERM_COLOR_IS_RGB(&cell.fg)) {
                color = {(double)cell.fg.rgb.red / 255, (double)cell.fg.rgb.green / 255, (double)cell.fg.rgb.blue / 255};
            }
            if (VTERM_COLOR_IS_INDEXED(&cell.bg)) {
                vterm_screen_convert_color_to_rgb(screen, &cell.bg);
            }
            if (VTERM_COLOR_IS_RGB(&cell.bg)) {
                bgcolor = {(double)cell.bg.rgb.red / 255, (double)cell.bg.rgb.green / 255, (double)cell.bg.rgb.blue / 255};
            }

            if (cell.attrs.reverse) std::swap(color, bgcolor);
            return std::make_pair(color, bgcolor);
        };

        // clear destroyed background
        for (int row = 0; row < matrix.get_rows(); row++) {
            for (int col = 0; col < matrix.get_cols(); col++) {
                if (!matrix(row, col)) continue;
                VTermPos pos = { row, col };
                VTermScreenCell cell;
                vterm_screen_get_cell(screen, pos, &cell);

                auto color = get_color(cell);

                surface_cairo->set_source_rgb(std::get<0>(color.second), std::get<1>(color.second), std::get<2>(color.second));
                double x = col * font_size / 2.0, y = row * font_size;
                surface_cairo->rectangle(x, y, font_size / 2.0, font_size);
                surface_cairo->fill();
            }
        }

        // draw updated chars
        for (int row = 0; row < matrix.get_rows(); row++) {
            for (int col = 0; col < matrix.get_cols(); col++) {
                if (!matrix(row, col)) continue;

                VTermPos pos = { row, col };
                VTermScreenCell cell;
                vterm_screen_get_cell(screen, pos, &cell);
                if (cell.chars[0] != 0xffffffff/*2nd cell of wide char*/) {
                    icu::UnicodeString ustr;
                    for (int i = 0; cell.chars[i] != 0 && i < VTERM_MAX_CHARS_PER_CELL; i++) {
                        ustr.append((UChar32)cell.chars[i]);
                    }
                    
                    /*
                    int style = TTF_STYLE_NORMAL;
                    if (cell.attrs.bold) style |= TTF_STYLE_BOLD;
                    if (cell.attrs.underline) style |= TTF_STYLE_UNDERLINE;
                    if (cell.attrs.italic) style |= TTF_STYLE_ITALIC;
                    if (cell.attrs.strike) style |= TTF_STYLE_STRIKETHROUGH;
                    if (cell.attrs.blink) {  } // TBD
                    */

                    if (ustr.length() > 0) {
                        UErrorCode status = U_ZERO_ERROR;
                        auto normalizer = icu::Normalizer2::getNFKCInstance(status);
                        if (U_FAILURE(status)) throw std::runtime_error("unable to get NFKC normalizer");
                        auto ustr_normalized = normalizer->normalize(ustr, status);
                        std::string utf8;
                        if (U_SUCCESS(status)) {
                            ustr_normalized.toUTF8String(utf8);
                        } else {
                            ustr.toUTF8String(utf8);
                        }
                        auto layout = create_pango_layout(utf8);
                        layout->set_font_description(desc);
                        auto color = get_color(cell);
                        double x = col * font_size / 2.0, y = row * font_size;
                        surface_cairo->move_to(x, y);
                        surface_cairo->set_source_rgb(std::get<0>(color.first), std::get<1>(color.first), std::get<2>(color.first));
                        layout->show_in_cairo_context(surface_cairo);
                    }
                }

                matrix(row, col) = 0;
            }
        }


        cairo_set_source_surface(cairo->cobj(), surface->cobj(), 0, 0);
        cairo->paint();
        // draw cursor
        cairo->set_source_rgba(1, 1, 1, 0.5);
        cairo->rectangle(cursor_pos.col * font_size / 2.0, cursor_pos.row * font_size, font_size / 2.0, font_size);
        cairo->fill();
        if (!has_focus() || ringing) {
            cairo->set_source_rgba(1, 1, 1, 0.8);
            cairo->rectangle(0, 0, width, height);
            cairo->fill();
        }
    });
    auto controller = Gtk::EventControllerKey::create();
    controller->signal_key_pressed().connect([this](guint keyval, guint keycode, Gdk::ModifierType state){
        if (!vterm) return false;
        //std::cout << "key pressed: " << keyval << "," << keycode << "," << (int)state << std::endl;
        if (keyval == GDK_KEY_ISO_Left_Tab) return false;
        //else
        int _mod = VTERM_MOD_NONE;
        if (((int)state & (int)Gdk::ModifierType::SHIFT_MASK) != 0) _mod |= VTERM_MOD_SHIFT;
        if (((int)state & (int)Gdk::ModifierType::ALT_MASK) != 0) _mod |= VTERM_MOD_ALT;
        if (((int)state & (int)Gdk::ModifierType::CONTROL_MASK) != 0) _mod |= VTERM_MOD_CTRL;
        auto mod = (VTermModifier)_mod;

        switch (keyval) {
        case GDK_KEY_Return:
        case GDK_KEY_KP_Enter:
            vterm_keyboard_key(vterm, VTERM_KEY_ENTER, mod);
            return true;
        case GDK_KEY_BackSpace:
            vterm_keyboard_key(vterm, VTERM_KEY_BACKSPACE, mod);
            return true;
        case GDK_KEY_Escape:
            vterm_keyboard_key(vterm, VTERM_KEY_ESCAPE, mod);
            return true;
        case GDK_KEY_Tab:
            vterm_keyboard_key(vterm, VTERM_KEY_TAB, mod);
            return true;
        case GDK_KEY_Up:
        case GDK_KEY_KP_Up:
            vterm_keyboard_key(vterm, VTERM_KEY_UP, mod);
            return true;
        case GDK_KEY_Down:
        case GDK_KEY_KP_Down:
            vterm_keyboard_key(vterm, VTERM_KEY_DOWN, mod);
            return true;
        case GDK_KEY_Left:
        case GDK_KEY_KP_Left:
            vterm_keyboard_key(vterm, VTERM_KEY_LEFT, mod);
            return true;
        case GDK_KEY_Right:
        case GDK_KEY_KP_Right:
            vterm_keyboard_key(vterm, VTERM_KEY_RIGHT, mod);
            return true;
        case GDK_KEY_Page_Up:
        case GDK_KEY_KP_Page_Up:
            vterm_keyboard_key(vterm, VTERM_KEY_PAGEUP, mod);
            return true;
        case GDK_KEY_Page_Down:
        case GDK_KEY_KP_Page_Down:
            vterm_keyboard_key(vterm, VTERM_KEY_PAGEDOWN, mod);
            return true;
        case GDK_KEY_Home:
        case GDK_KEY_KP_Home:
            vterm_keyboard_key(vterm, VTERM_KEY_HOME, mod);
            return true;
        case GDK_KEY_End:
        case GDK_KEY_KP_End:
            vterm_keyboard_key(vterm, VTERM_KEY_END, mod);
            return true;
        default:
            if (keyval < 127) {
                vterm_keyboard_unichar(vterm, keyval, mod);
                return true;
            }
        }
        //else
        return false;
    }, false);
    add_controller(controller);

    set_can_focus();
    set_focusable();
    set_can_target();
    set_focus_on_click();

    signal_resize().connect([this](int width, int height) {
        //std::cout << "Widget resized" << std::endl;
        surface = Cairo::ImageSurface::create(Cairo::Surface::Format::ARGB32, width, height);
        auto rows = height / font_size, cols = width / (font_size / 2);
        //std::cout << "set_size " << rows << ',' << cols << std::endl;
        matrix.set_size(rows, cols);
        if (!vterm) {
            vterm = vterm_new(rows,cols);
            vterm_set_utf8(vterm, 1);
            screen = vterm_obtain_screen(vterm);
            static const VTermScreenCallbacks screen_callbacks = {
                [](VTermRect rect, void *user) { // damage
                    auto terminal = (Terminal*)user;
                    for (int row = rect.start_row; row < rect.end_row; row++) {
                        for (int col = rect.start_col; col < rect.end_col; col++) {
                            terminal->matrix(row, col) = 1;
                        }
                    }
                    terminal->queue_draw();
                    return 0;
                },
                [](VTermRect dest, VTermRect src, void *user) { // moverect
                    return 0;
                },
                [](VTermPos pos, VTermPos oldpos, int visible, void *user) {// movecursor
                    auto terminal = (Terminal*)user;
                    terminal->cursor_pos = pos;
                    terminal->queue_draw();
                    return 0;
                },
                [](VTermProp prop, VTermValue *val, void *user) {// settermprop
                    return 0;
                },
                [](void *user) { //bell
                    auto terminal = (Terminal*)user;
                    if (terminal->ringing) terminal->ringing.value().disconnect();
                    terminal->ringing = Glib::signal_timeout().connect([terminal]() {
                        terminal->ringing = std::nullopt;
                        terminal->queue_draw();
                        return false; // timer will automatically be disconnected
                    }, 100);
                    terminal->queue_draw();
                    return 0;
                },
                [](int rows, int cols, void *user) { // resize
                    return 0;
                },
                [](int cols, const VTermScreenCell *cells, void *user) { // sb_pushline
                    return 0;
                },
                [](int cols, VTermScreenCell *cells, void *user) {// sb_popline
                    return 0;
                }
            };
            vterm_screen_set_callbacks(screen, &screen_callbacks, this);
            m_signal_resize_terminal(cols, rows);
            m_signal_open_terminal();
        } else {
            vterm_set_size(vterm, rows, cols);
            m_signal_resize_terminal(cols, rows);
        }
        vterm_screen_reset(screen, 1);
        matrix.fill(0);
        cursor_pos.col = cursor_pos.row = 0;
        auto cairo = Cairo::Context::create(surface);
        cairo->set_source_rgb(0, 0, 0);
        cairo->rectangle(0, 0, width, height);
        cairo->fill();
    });
    signal_state_flags_changed().connect([this](Gtk::StateFlags previous_flags) {
        if (((int)previous_flags & (int)Gtk::StateFlags::FOCUSED) != ((int)get_state_flags() & (int)Gtk::StateFlags::FOCUSED)) {
            queue_draw();
        }
    });
}

Terminal::~Terminal() {
    disconnect();
    if (vterm) {
        vterm_free(vterm);
        vterm = nullptr;
    }
}

void Terminal::connect(int fd) { 
    this->fd = fd;
    if (!vterm) std::logic_error("vterm has not been initialized");
    vterm_output_set_callback(vterm, [](const char* s, size_t len, void* user) {
        write(*(int*)user, s, len);
    }, (void*)&(this->fd));
}
void Terminal::disconnect() { 
    this->fd = -1;
    if (vterm) vterm_output_set_callback(vterm, NULL, NULL);
}
void Terminal::process_input(const char* buf, size_t len) {
    if (!vterm) std::logic_error("vterm has not been initialized");
    vterm_input_write(vterm, buf, len);
}
