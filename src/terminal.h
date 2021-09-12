#include <gtkmm.h>
#include <vterm.h>

class Terminal : public Gtk::DrawingArea {
    template <typename T> class Matrix {
        T* buf;
        int rows, cols;
    public:
        Matrix() : buf(nullptr) {;}
        Matrix(int _rows, int _cols) : rows(_rows), cols(_cols) {
            buf = new T[cols * rows];
        }
        ~Matrix() {
            if (buf) delete buf;
        }
        void set_size(int rows, int cols) {
            if (rows < 1 || cols < 1) throw std::runtime_error("invalid matrix size");
            if (buf) {
                //std::cout << "delete buf" << std::endl;
                delete buf;
            }
            this->rows = rows;
            this->cols = cols;
            buf = new T[cols * rows];
        }
        void fill(const T& by) {
            for (int row = 0; row < rows; row++) {
                for (int col = 0; col < cols; col++) {
                    buf[cols * row + col] = by;
                }
            }
        }
        T& operator()(int row, int col) {
            if (!buf || row < 0 || col < 0 || row >= rows || col >= cols) throw std::runtime_error("invalid position");
            //else
            return buf[cols * row + col];
        }
        int get_rows() const { if (!buf) throw std::runtime_error("empty matrix"); else return rows; }
        int get_cols() const { if (!buf) throw std::runtime_error("empty matrix"); else return cols; }
        operator bool() const { return buf != nullptr; }
    };
    VTerm* vterm;
    VTermScreen* screen;
    VTermPos cursor_pos;
    std::optional<sigc::connection> ringing;
    Cairo::RefPtr<Cairo::ImageSurface> surface;

    Matrix<unsigned char> matrix;
    int font_size;
    int fd;

    sigc::signal<void(void)> m_signal_open_terminal;
    sigc::signal<void(int,int)> m_signal_resize_terminal;
public:
    Terminal(int _font_size = 20);

    void connect(int fd);
    void disconnect();
    void process_input(const char* buf, size_t len);
    ~Terminal();

    sigc::signal<void(void)> signal_open_terminal() { return m_signal_open_terminal; }
    sigc::signal<void(int,int)> signal_resize_terminal() { return m_signal_resize_terminal; }
    int get_cols() { return matrix.get_cols(); }
    int get_rows() { return matrix.get_rows(); }
};
