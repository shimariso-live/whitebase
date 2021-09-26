#include <sys/wait.h>
#include <fstream>
#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf

#include <curl/curl.h>

#include "common.h"
#include "yajl_value.h"
#include "update.h"

std::optional<std::string> get_present_version()
{
    if (!std::filesystem::exists(version_file) || !std::filesystem::is_regular_file(version_file)) return std::nullopt;
    std::ifstream f(version_file);
    if (!f) return std::nullopt;
    std::string v;
    f >> v;
    return v;
}

std::optional<std::filesystem::path> get_present_system_image_path()
{
    static const std::filesystem::path loop0_backing_file("/sys/block/loop0/loop/backing_file");
    if (!std::filesystem::exists(loop0_backing_file) || !std::filesystem::is_regular_file(loop0_backing_file)) return std::nullopt;
    std::string s;
    std::ifstream f(loop0_backing_file);
    if (!f) return std::nullopt;
    f >> s;
    return s;
}

std::optional<std::string> get_version_from_system_image_file(const std::filesystem::path& image_file)
{
    auto [pid, in] = forkinput([]() {
        return exec({"unsquashfs", "-cat", "/run/initramfs/boot/system.img", "/.genpack/version"});
    });
    std::string s;
    {
        __gnu_cxx::stdio_filebuf<char> filebuf(in, std::ios::in);
        std::istream f(&filebuf);
        f >> s;
    }
    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0 || s == "") return std::nullopt;
    return s;
}

std::optional<std::tuple<std::string,std::string,size_t>> get_latest_version(bool include_unstable)
{
    auto update_json = load_json("https://update.walbrix.net/");
    for (auto val : get<std::vector<yajl_val>>(get(update_json.get(), "releases"))) {
        auto obj = get<std::map<std::string,yajl_val>>(val);
        if (!obj.contains("version") || !obj.contains("href")) continue;
        if (!include_unstable && !is_true(obj["stable"])) continue;
        auto href = get<std::string>(obj["href"]);
        auto content_length = get_content_length(href);
        if (!content_length) break;
        //else
        return std::make_tuple(
            get<std::string>(obj["version"]),
            href,
            content_length.value()
        );
    }
    return std::nullopt;
}

BootPartitionLock::BootPartitionLock(bool nonblock)
{
    fd = open(boot_dir.c_str(), O_RDONLY, 0);
    if (fd < 0) throw std::runtime_error("open(" + boot_dir.string() + ") failed");
    if (flock(fd, LOCK_EX|(nonblock? LOCK_NB : 0)) < 0) {
        close(fd);
        fd = -1;
        if (errno != EWOULDBLOCK) throw std::runtime_error(std::string("flock(") + boot_dir.string() + ") failed");
    }
}

BootPartitionLock::~BootPartitionLock()
{
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}

static size_t download_callback(char *buffer, size_t size, size_t nmemb, void *data)
{
    auto& [f, expected_size, downloaded_size, st, progress_func] = *((std::tuple<std::ofstream&,size_t,size_t&,std::stop_token&,std::function<void(double)>>*)data);
    if (st.stop_requested()) return 0;
    //else
    f.write(buffer, size * nmemb);
    downloaded_size += size * nmemb;
    double progress = (double)downloaded_size / (double)expected_size;
    if (progress > 1.0) progress = 1.0;
    progress_func(progress);
    return size * nmemb;
}

static bool download_system_image(std::ofstream& f, const std::string url, size_t expected_size, std::stop_token& st, std::function<void(double)> progress)
{
    size_t downloaded_size = 0;
    std::tuple<std::ofstream&,size_t,size_t&,std::stop_token&,std::function<void(double)>> data(f, expected_size, downloaded_size, st, progress);

    std::shared_ptr<CURL> curl(curl_easy_init(), curl_easy_cleanup);
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, download_callback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &data);    
    if (curl_easy_perform(curl.get()) != CURLE_OK) return false;

    long http_code = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_code);
    char *ct = nullptr;
    if (curl_easy_getinfo(curl.get(), CURLINFO_CONTENT_TYPE, &ct) != CURLE_OK) return false;
    // check status code and content type
    if (http_code != 200) return false;

    return true;
}

bool download_system_image(const std::string url, size_t expected_size, std::stop_token& st, std::function<void(double)> progress)
{
    if (std::filesystem::exists(system_old) && std::filesystem::is_regular_file(system_old)) {
        std::filesystem::remove(system_old);
    }
    bool rst;
    {
        std::ofstream f(system_new);
        rst = download_system_image(f, url, expected_size, st, progress);
    }
    if (!rst) {
        std::filesystem::remove(system_new);
        return false;
    }
    //else
    if (std::filesystem::exists(system_img) && !std::filesystem::exists(system_cur)) {
        std::filesystem::rename(system_img, system_cur);
    }
    std::filesystem::rename(system_new, system_img);

    return true;
}