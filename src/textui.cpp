#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <string>
#include <optional>
#include <stdexcept>
#include <list>
#include <tuple>

#include "termbox.h"

#define RUNTIME_ERROR(msg) throw std::runtime_error((std::string)__FILE__ + '(' + std::to_string(__LINE__) + ") " + msg)
#define RUNTIME_ERROR_WITH_ERRNO(msg) throw std::runtime_error((std::string)__FILE__ + '(' + std::to_string(__LINE__) + ") " + msg + ':' + strerror(errno))

std::pair<uint16_t, uint16_t> measure_text_size(const char* text);
std::pair<uint16_t, uint16_t> resize(const std::pair<uint16_t, uint16_t>& size, int16_t width, int16_t height);

class TbAbstractWindow {
  uint16_t _width, _height;
  std::optional<std::string> _caption;
public:
  TbAbstractWindow(uint16_t __width, uint16_t __height, std::optional<std::string> __caption = std::nullopt) : _width(__width), _height(__height), _caption(__caption) {;}
  virtual ~TbAbstractWindow() {;}
  virtual operator tb_cell*() = 0;

  tb_cell& cell_at(uint16_t x, uint16_t y) { return ((tb_cell*)(*this))[y * _width + x]; }

  uint16_t width() { return _width; }
  uint16_t height() { return _height; }

  void put_cell(int16_t x, int16_t y, const tb_cell& cell) {
    tb_put_cell(x, y, &cell);
  }
  void change_cell(int16_t x, int16_t y, uint32_t ch, uint16_t fg = TB_DEFAULT, uint16_t bg = TB_DEFAULT) {
    if (x < 0 || x >= _width || y < 0 || y >= _height) return;
    //else
    tb_cell& cell = cell_at(x, y);
    cell.ch = ch;
    cell.fg = fg;
    cell.bg = bg;
  }

  void draw_text(int16_t x, int16_t y, const char* text, uint16_t fg = TB_DEFAULT, uint16_t bg = TB_DEFAULT);
  void draw_text_center(int16_t y, const char* text, uint16_t fg = TB_DEFAULT, uint16_t bg = TB_DEFAULT);
  void draw_hline(int16_t y) {
    if (y < 0 || y >= _height) return;
    //else
    for (uint16_t x = 0 ; x < _width; x++) {
     // ─
      change_cell(x, y, 0x2500);
    }
  }

  virtual void draw_self() {;} // to be overridden

  void draw(TbAbstractWindow& dst, int16_t x, int16_t y, bool border = true);

  void draw_center(TbAbstractWindow& dst, bool border = true) {
    int16_t x = dst.width() / 2 - (_width + (border? 2 : 0)) / 2;
    int16_t y = dst.height() / 2 - (_height + (border? 2 : 0)) / 2;
    draw(dst, x, y, border);
  }

};

class TbRootWindow : public TbAbstractWindow {
  friend class Termbox;
  TbRootWindow() : TbAbstractWindow(tb_width(), tb_height()) {;}
public:
  virtual operator tb_cell*() { return tb_cell_buffer(); }
};

class Termbox {
public:
  Termbox() { if (tb_init() != 0) RUNTIME_ERROR("tb_init"); }
  ~Termbox() { tb_shutdown(); }
  void clear() { tb_clear(); }
  void present() { tb_present(); }
  int peek_event(tb_event* event, int timeout) {
    auto event_type = tb_peek_event(event, timeout);
    if (event_type < 0) RUNTIME_ERROR("tb_peek_event");
    return event_type;
  }
  int poll_event(tb_event* event) {
    auto event_type = tb_poll_event(event);
    if (event_type < 0) RUNTIME_ERROR("tb_poll_event");
    return event_type;
  }
  bool wait_for_enter_or_esc_key() {
    tb_event event;
    while (true) {
      if (poll_event(&event) != TB_EVENT_KEY) continue;
      if (event.key == TB_KEY_ENTER) return true;
      if (event.key == TB_KEY_ESC) return false;
    }
  }
  TbRootWindow root() { return TbRootWindow(); }
};

class TbWindow : public TbAbstractWindow {
  tb_cell* _buffer;
public:
  TbWindow(uint16_t width, uint16_t height, std::optional<std::string> caption = std::nullopt) : TbAbstractWindow(width, height, caption) {
    if (width < 1 || height < 1) RUNTIME_ERROR("Invalid window size");
    _buffer = (tb_cell*)malloc(sizeof(tb_cell) * width * height);
    if (!_buffer) RUNTIME_ERROR("Failed to allocate window drawing buffer");
    memset(_buffer, 0, width * height * sizeof(tb_cell));
  }
  TbWindow(std::pair<uint16_t, uint16_t> size, std::optional<std::string> caption = std::nullopt) : TbWindow(size.first, size.second, caption) {;}
  virtual ~TbWindow() {
    if (_buffer) free(_buffer);
  }
  operator tb_cell*() { return _buffer; }
};

template <typename T> class TbMenu {
  int16_t _selection;
  std::list<std::tuple<std::optional<T>,std::string,bool> > items;
  uint16_t _width;
public:
  TbMenu() : _selection(-1), _width(0) {}
  void add_item(std::optional<T> value, const char* label, bool center = false) {
    items.push_back(std::make_tuple(value, label, center));
    auto label_width = measure_text_size(label).first;
    if (label_width > _width) _width = label_width;
  }
  std::pair<uint16_t, uint16_t> get_size() {
    uint16_t width = 0, height = 0;
    for (const auto& i : items) {
      auto size = measure_text_size(std::get<1>(i).c_str());
      width = size.first > width? size.first : width;
      height += size.second;
    }
    return std::make_pair(width, height);
  }
  std::optional<T> get_selected()
  {
    if (_selection >= 0) {
      auto ii = items.cbegin();
      for (int i = 0; ii != items.cend(); i++, ii++) {
        if (i == _selection) {
          return std::get<0>(*ii);
        }
      }
    }
    return std::nullopt;
  }
  void selection(int16_t __selection) { _selection = __selection; }
  int16_t selection() { return _selection; }
  uint16_t width() { return _width; }
  std::pair<bool, std::optional<T> > process_event(tb_event& event) {
    if (event.type == TB_EVENT_KEY) {
      switch(event.key) {
      case TB_KEY_ARROW_UP:
        if (_selection < 0) _selection = items.size() - 1;
        else if (_selection > 0) _selection--;
        return std::make_pair(false, get_selected());
      case TB_KEY_ARROW_DOWN:
        if (_selection < 0) _selection = 0;
        else if (_selection < items.size() - 1) _selection++;
        return std::make_pair(false, get_selected());
      case TB_KEY_ENTER: return std::make_pair(true, get_selected());
      case TB_KEY_ESC: return std::make_pair(true, std::nullopt);
      default: break;
      }
    }
    //else
    return std::make_pair(false, get_selected());
  }
  void draw(TbWindow& window, int16_t x = 0, int16_t y = 0) {
    auto ii = items.cbegin();
    for (int i = 0; ii != items.cend(); i++, ii++) {
      if (std::get<2>(*ii)) {
        window.draw_text_center(y + i, std::get<1>(*ii).c_str());
      } else {
        window.draw_text(x, y + i, std::get<1>(*ii).c_str());
      }
      for (int xi = 0; xi < _width; xi++) {
        auto& cell = window.cell_at(x + xi, y + i);
        cell.fg = i == _selection? (TB_YELLOW | TB_REVERSE) : TB_DEFAULT;
        cell.bg = i == _selection? TB_REVERSE : TB_DEFAULT;
      }
    }
  }
};

class MessageBox : public TbWindow {
  std::string message;
public:
  MessageBox(const char* _message) : message(_message), TbWindow(measure_text_size(_message)) {;}
  virtual void draw_self() {
    draw_text(0, 0, message.c_str());
  }
};

class MessageBoxOk : public TbWindow {
  std::string message;
public:
  MessageBoxOk(const char* _message) : message(_message), TbWindow(resize(measure_text_size(_message), 0, 2)) {;}
  virtual void draw_self() {
    draw_text(0, 0, message.c_str());
    draw_hline(height() - 2);
    draw_text_center(height() - 1, "[ OK ]", TB_YELLOW | TB_REVERSE, TB_REVERSE);
  }
};

std::pair<uint16_t, uint16_t> measure_text_size(const char* text)
{
  uint16_t x = 0, width = 0;
  uint16_t height = 1;
  const char* pt = text;
  while (*pt) {
    if (*pt == '\n') {
      if (x > width) width = x;
      x = 0;
      height++;
      pt++;
      continue;
    }
    int len = tb_utf8_char_length(*pt);
    if (len == TB_EOF) break;
    uint32_t ch;
    tb_utf8_char_to_unicode(&ch, pt);
    int w = wcwidth(ch);
    if (w < 1) w = 1;
    x += w;
    pt += len;
  }
  if (x > width) width = x;
  return std::make_pair(width, height);
}

std::pair<uint16_t, uint16_t> resize(const std::pair<uint16_t, uint16_t>& size, int16_t width, int16_t height)
{
  return std::make_pair(size.first + width, size.second + height);
}

void TbAbstractWindow::draw_text(int16_t x, int16_t y, const char* text, uint16_t fg/* = TB_DEFAULT*/, uint16_t bg/* = TB_DEFAULT*/) {
  const char* pt = text;
  while (*pt) {
    if (*pt == '\n') {
      x = 0;
      y ++;
      pt++;
      continue;
    }
    int len = tb_utf8_char_length(*pt);
    if (len == TB_EOF) break;
    uint32_t ch;
    tb_utf8_char_to_unicode(&ch, pt);
    int w = wcwidth(ch);
    if (w < 1) w = 1;
    if (x + w > _width) {
      y ++;
      x = 0;
    }
    change_cell(x, y, ch, fg, bg);
    x += w;
    pt += len;
  }
}

void TbAbstractWindow::draw_text_center(int16_t y, const char* text, uint16_t fg/* = TB_DEFAULT*/, uint16_t bg/* = TB_DEFAULT*/) {
  int16_t x = _width / 2 - measure_text_size(text).first / 2;
  draw_text(x, y, text, fg, bg);
}

void TbAbstractWindow::draw(TbAbstractWindow& dst, int16_t x, int16_t y, bool border/*=true*/)
{
  draw_self();
  for (uint16_t yi = 0; yi < _height; yi++) {
    for (uint16_t xi = 0; xi < _width; xi++){
      if (x + xi < 0 || x + xi >= dst.width() || y + yi < 0 || y + yi >= dst.height()) continue;
      dst.put_cell(x + xi, y + yi, cell_at(xi, yi));
    }
  }
  dst.change_cell(x - 1, y - 1, 0x250c); // ┌
  dst.change_cell(x + _width, y - 1, 0x2510); // 	┐
  dst.change_cell(x - 1, y + _height, 0x2514); // └
  dst.change_cell(x + _width, y + _height, 0x2518); // 	┘

  if (border) {
    for (uint16_t xi = 0 ; xi < _width; xi++) {
     // ─
      dst.change_cell(x + xi, y - 1, 0x2500);
      dst.change_cell(x + xi, y + _height, 0x2500);
    }

    for (uint16_t yi = 0; yi < _height; yi++) {
      // │
      dst.change_cell(x - 1, y + yi, 0x2502);
      dst.change_cell(x + _width, y + yi, 0x2502);
    }

    if (_caption) {
      const auto& caption = _caption.value();
      dst.draw_text(x, y - 1, caption.c_str(), TB_CYAN|TB_REVERSE, TB_REVERSE);
    }
  }
}

int ui_old(bool login/* = false*/)
{
  /* TODO: remove after -
  utsname uname_buf;
  std::string version = uname(&uname_buf) == 0? uname_buf.release : "";
  */
  std::pair<bool, std::optional<int> > result;
  {
    Termbox termbox;
    TbRootWindow root = termbox.root();
    TbMenu<int> menu;
    menu.add_item(1, "シャットダウン");
    menu.add_item(2, "再起動");
    if (login) {
      menu.add_item(3, "Linuxコンソール");
    }
    menu.add_item(std::nullopt, "メニューを終了[ESC]");
    TbWindow window(menu.get_size(), (std::string)"Walbrix"/* + version*/);
    tb_event event;
    event.type = 0;
    menu.selection(0);
    while (!(result = menu.process_event(event)).first) {
      menu.draw(window);
      window.draw_center(root);
      termbox.present();
      termbox.poll_event(&event);
    }
  }

  if (!result.second) return 0;

  switch (result.second.value()) {
  case 1:
    execl("/sbin/poweroff", "/sbin/poweroff", NULL);
    break;
  case 2:
    execl("/sbin/reboot", "/sbin/reboot", NULL);
    break;
  case 3:
    if (execlp("/bin/login", "/bin/login", "-p", "-f", "root", NULL) < 0) {
      RUNTIME_ERROR("execlp");
    }
    break;
  default:
    RUNTIME_ERROR("menu");
  }
  return 0;
}

int login()
{
  {
    Termbox termbox;
    TbRootWindow root = termbox.root();
    const char* msg = "    Walbrixへようこそ！\n 【Enterキーで操作を開始】";
    auto size = measure_text_size(msg);
    TbWindow win(size.first, size.second);

    win.draw_text(0, 0, msg);
    win.draw_center(root);
    tb_present();
    tb_event event;
    while (true) {
      tb_poll_event(&event);
      if (event.key == TB_KEY_ENTER) break;
    }
  }

  pam_handle_t *pamh;
  struct pam_conv conv = { misc_conv, NULL };
  pam_start("login", "root", &conv, &pamh);
  int rc;
  do {
    rc = pam_authenticate(pamh, 0);
  } while (rc != PAM_SUCCESS && rc != PAM_ABORT && rc != PAM_MAXTRIES);
  pam_end(pamh, rc);

  if (rc == PAM_ABORT || rc == PAM_MAXTRIES) return -1;

  return ui_old(true);
}

static int _main(int,char*[])
{
    setlocale( LC_ALL, "ja_JP.utf8"); // TODO: read /etc/locale.conf
    return login();
}

#ifdef __MAIN_MODULE__
int main(int argc, char* argv[]) { return _main(argc, argv); }
#endif

