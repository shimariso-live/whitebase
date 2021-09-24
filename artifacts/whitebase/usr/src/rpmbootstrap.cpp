#include <unistd.h>
#include <memory.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include <filesystem>
#include <memory>
#include <iostream>
#include <functional>
#include <set>
#include <map>
#include <variant>
#include <optional>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <curl/curl.h>

std::vector<std::string> getopt(
    int argc, char* argv[], 
    const std::vector<std::tuple<
        std::optional<char>/*shortopt*/,
        std::optional<std::string>/*longopt*/,
        std::variant<
            std::function<void(void)>, // 0: no arg
            std::function<void(const std::optional<std::string>&)>, // 1: optional string arg
            std::function<void(const std::string&)> // 2: required string arg
        >/*func*/
    >>& opts)
{
    std::string shortopts;
    std::vector<struct option> longopts;
    std::map<std::string,std::variant<
        std::function<void(void)>,
        std::function<void(const std::optional<std::string>&)>,
        std::function<void(const std::string&)>
    >> funcs;
    for (const auto& opt:opts) {
        if (std::get<0>(opt).has_value()) {
            char shortopt = std::get<0>(opt).value();
            const auto& func = std::get<2>(opt);
            shortopts += shortopt;
            if (std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func)) shortopts += "::";
            else if (std::holds_alternative<std::function<void(const std::string&)>>(func)) shortopts += ":";
            funcs[std::string(1, shortopt)] = func;
        }
        if (std::get<1>(opt).has_value()) {
            const auto& longopt = std::get<1>(opt).value();
            const auto& shortopt = std::get<0>(opt);
            const auto& func = std::get<2>(opt);
            auto arg_required = std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func)? optional_argument
                : ((std::holds_alternative<std::function<void(const std::string&)>>(func))? required_argument : no_argument);
            longopts.push_back((struct option) {
                longopt.c_str(),
                arg_required,
                0,
                shortopt.has_value()? shortopt.value() : 0
            });
            funcs[longopt] = func;
        }
    }

    struct option* clongopts = new struct option[longopts.size() + 1];
    struct option* p = clongopts;
    for (const auto& lo:longopts) { 
        memcpy(p, &lo, sizeof(*p));
        p++;
    }
    memset(p, 0, sizeof(*p));
    int c;
    int longindex = 0;
    while ((c = getopt_long(argc, argv, shortopts.c_str(), clongopts, &longindex)) >= 0) {
        const auto func = funcs.find(c == 0? clongopts[longindex].name : std::string(1,(char)c));
        if (func != funcs.end()) {
            if (std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func->second)) {
                std::get<1>(func->second)(optarg? std::optional<std::string>(optarg) : std::nullopt);
            } else if (std::holds_alternative<std::function<void(const std::string&)>>(func->second)) {
                std::get<2>(func->second)(optarg? optarg : "");
            } else {
                std::get<0>(func->second)();
            }
        }
    }
    delete []clongopts;

    std::vector<std::string> non_option_args;
    for (int i = optind; i < argc; i++) {
        non_option_args.push_back(argv[i]);
    }

    return non_option_args;
}

void for_each_node(xmlNodeSetPtr nodeset, std::function<void(xmlNodePtr)> func)
{
    if (!nodeset) return;
    for (int i = 0; i < nodeset->nodeNr; i++) {
        func(nodeset->nodeTab[i]);
    }
}

void for_each_node(xmlXPathContextPtr ctx, const std::string& xpath, std::function<void(xmlNodePtr)> func)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathEval(BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    for_each_node(xpathobj->nodesetval, func);
}

void for_each_node(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath, std::function<void(xmlNodePtr)> func)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathNodeEval(node, BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    for_each_node(xpathobj->nodesetval, func);
}

std::string get_single_text_element(xmlNodePtr node)
{
    auto text = xmlNodeGetContent(node);
    if (!text) throw std::runtime_error("No text available with the node");
    std::string rst((const char*)text);
    xmlFree(text);
    return rst;
}

xmlNodePtr get_single_element(xmlXPathContextPtr ctx, const std::string& xpath)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathEval(BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    if (!xpathobj->nodesetval) throw std::runtime_error("Nodeset is null");
    if (xpathobj->nodesetval->nodeNr == 0) throw std::runtime_error("Empty nodeset");
    return xpathobj->nodesetval->nodeTab[0];
}

xmlNodePtr get_single_element(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathNodeEval(node, BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    if (!xpathobj->nodesetval) throw std::runtime_error("Nodeset is null");
    if (xpathobj->nodesetval->nodeNr == 0) throw std::runtime_error("Empty nodeset");
    return xpathobj->nodesetval->nodeTab[0];
}

std::string get_single_text_element(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath)
{
    return get_single_text_element(get_single_element(ctx, node, xpath));
}

std::string get_single_attribute_element(xmlNodePtr node, const std::string& attr)
{
    if (node->type != XML_ELEMENT_NODE)  throw std::runtime_error("Must be an element");
    auto prop = xmlGetProp(node, BAD_CAST attr.c_str());
    if (!prop) throw std::runtime_error("No attribute " + attr);
    std::string rst((const char*)prop);
    xmlFree(prop);
    return rst;
}

std::string get_single_attribute_element(xmlXPathContextPtr ctx, const std::string& xpath, const std::string& attr)
{
    return get_single_attribute_element(get_single_element(ctx, xpath), attr);
}

std::string get_single_attribute_element(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath, const std::string& attr)
{
    return get_single_attribute_element(get_single_element(ctx, node, xpath), attr);
}

static size_t curl_callback_readtostr(char *buffer, size_t size, size_t nmemb, void *f)
{
    const static size_t limit = 128 * 1024; // Limit size to 128KB
    std::string& buf = *((std::string*)f);
    if (buf.length() + size * nmemb > limit) return 0; // tell curl to stop download(causes CURLE_WRITE_ERROR)
    buf += std::string(buffer, size * nmemb);
    return size * nmemb;
}

static size_t curl_callback_passtofd(char *buffer, size_t size, size_t nmemb, void *f)
{
    int fd  = *((int*)f);
    return write(fd, buffer, size * nmemb);
}

static pid_t fork(std::function<int(void)> func)
{
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid > 0) {
        // parent process
        return pid;
    }
    //else(child process)
    try {
        _exit(func());
    }
    catch (...) {
        // jumping across scope border in forked process may not be a good idea.
    }
    _exit(-1);
}

static std::pair<pid_t,int> forkoutput(std::function<int(void)> func)
{
    int fd[2];
    if (pipe(fd) < 0) throw std::runtime_error("pipe() failed");

    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid > 0) {
        // parent process
        close(fd[0]);
        return {pid, fd[1]};
    }
    //else(child process)
    try {
        dup2(fd[0], STDIN_FILENO);
        close(fd[1]);
        _exit(func());
    }
    catch (...) {
        // jumping across scope border in forked process may not be a good idea.
    }
    _exit(-1);
}

std::string get_primary_packages_url(const std::string& base_url)
{
    std::string buf;
    std::shared_ptr<CURL> curl(curl_easy_init(), curl_easy_cleanup);
    curl_easy_setopt(curl.get(), CURLOPT_URL, (base_url + "repodata/repomd.xml").c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curl_callback_readtostr);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &buf);
    auto res = curl_easy_perform(curl.get());
    if (res != CURLE_OK) {
        if (res == CURLE_WRITE_ERROR) {
            throw std::runtime_error("CURLE_WRITE_ERROR: Content size limit exceeded?");
        } else {
            throw std::runtime_error(std::string(curl_easy_strerror(res)) + "(" + std::to_string(res) + ")");
        }
    }
    // collect HTTP status code
    long http_code = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_code);

    // collect Content-Type
    char *ct = nullptr;
    res = curl_easy_getinfo(curl.get(), CURLINFO_CONTENT_TYPE, &ct);
    if (res != CURLE_OK) throw std::runtime_error(curl_easy_strerror(res));
    std::optional<std::string> content_type = ct? std::make_optional(ct) : std::nullopt;

    if (http_code != 200) {
        throw std::runtime_error("HTTP status other than 200 OK received: status code=" + std::to_string(http_code));
    }
    if (content_type != "text/xml") {
        throw std::runtime_error("Not text/json: "  + content_type.value_or("N/A"));
    }

    std::shared_ptr<xmlParserCtxt> ctx(xmlNewParserCtxt(), xmlFreeParserCtxt);
    std::shared_ptr<xmlDoc> doc(xmlCtxtReadMemory(ctx.get(), buf.c_str(), buf.length(), NULL, NULL, 0), xmlFreeDoc);

    std::shared_ptr<xmlXPathContext> xpath_ctx(xmlXPathNewContext(doc.get()), xmlXPathFreeContext);
    xmlXPathRegisterNs(xpath_ctx.get(), BAD_CAST "repo", BAD_CAST "http://linux.duke.edu/metadata/repo");
    xmlXPathRegisterNs(xpath_ctx.get(), BAD_CAST "rpm", BAD_CAST "http://linux.duke.edu/metadata/rpm");

    auto href = get_single_attribute_element(xpath_ctx.get(), "//repo:data[@type='primary']/repo:location", "href");

    return base_url + href;
}

int get_packages_data(const std::string& base_url, int argc, char* argv[])
{
    auto primary_packages_url = get_primary_packages_url(base_url);

    auto gunzip = forkoutput([]() {
        return execlp("gunzip", "gunzip", "-c", NULL);
    });

    std::shared_ptr<CURL> curl(curl_easy_init(), curl_easy_cleanup);
    curl_easy_setopt(curl.get(), CURLOPT_URL, primary_packages_url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curl_callback_passtofd);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &gunzip.second);
    int curl_rst = curl_easy_perform(curl.get());
    close(gunzip.second);
    int wstatus;
    waitpid(gunzip.first, &wstatus, 0);

    return (curl_rst = CURLE_OK && WIFEXITED(wstatus))? WEXITSTATUS(wstatus) : -1;
}

struct Package {
    std::set<std::string> rpm_requires;
    std::string location;
    uint64_t time;
};

void install(const std::string& name, std::set<std::string>& rpms, const std::map<std::string,Package>& packages, const std::map<std::string,std::vector<std::string>>& providers,
    const std::set<std::string>& dependency_excludes)
{
    auto package = packages.find(name);
    if (package == packages.cend()) throw std::runtime_error("No such package:" + name);
    auto rpm = package->second.location;
    if (rpms.find(rpm) != rpms.end()) return;
    //else
    rpms.insert(rpm);
    for (const auto& i: package->second.rpm_requires) {
        if (dependency_excludes.find(i) != dependency_excludes.end()) continue;
        auto provider = providers.find(i);
        if (provider == providers.end()) throw std::runtime_error("No provider for " + i);
        //else
        install(provider->second[0], rpms, packages, providers, dependency_excludes);
    }
}

int download(const std::string& base_url, int argc, char* argv[])
{
    struct utsname un;
    if (uname(&un) < 0) throw std::runtime_error("uname() failed");
    std::string arch(un.machine);
    std::set<std::string> dependency_excludes;

    auto args = getopt(argc, argv, {
        {'a', "arch", [&arch](const std::string& optarg) {
            arch = optarg;
        }},
        {'x', "dependency-exclude", [&dependency_excludes](const std::string& optarg) {
            dependency_excludes.insert(optarg);
        }}
    });

    if (args.size() < 2) {
        std::cout << "Usage:" << std::endl;
        std::cout << "  " << argv[0] << " [options] <download_dir> <package1> [[package2]..]" << std::endl;
        return 1;
    }

    std::filesystem::path download_dir(args[0]);
    std::set<std::string> packages_to_install;
    for (auto i = args.begin() + 1; i != args.end(); i++) {
        packages_to_install.insert(*i);
    }

    std::shared_ptr<xmlParserCtxt> ctx(xmlNewParserCtxt(), xmlFreeParserCtxt);
    std::shared_ptr<xmlDoc> doc(xmlCtxtReadFd(ctx.get(), STDIN_FILENO, NULL, NULL, 0), xmlFreeDoc);

    std::shared_ptr<xmlXPathContext> xpath_ctx(xmlXPathNewContext(doc.get()), xmlXPathFreeContext);
    xmlXPathRegisterNs(xpath_ctx.get(), BAD_CAST "common", BAD_CAST "http://linux.duke.edu/metadata/common");
    xmlXPathRegisterNs(xpath_ctx.get(), BAD_CAST "rpm", BAD_CAST "http://linux.duke.edu/metadata/rpm");

    std::map<std::string,Package> packages;
    std::map<std::string,std::vector<std::string>> providers;

    for_each_node(xpath_ctx.get(), "//common:package[@type='rpm']", [&xpath_ctx,&arch,&packages,&providers](auto package_elem) {
        auto _arch = get_single_text_element(xpath_ctx.get(), package_elem, "common:arch");
        if (_arch != arch && _arch != "noarch") return;
        auto name = get_single_text_element(xpath_ctx.get(), package_elem, "common:name");
        auto location = get_single_attribute_element(xpath_ctx.get(), package_elem, "common:location", "href");
        auto time = std::stoul(get_single_attribute_element(xpath_ctx.get(), package_elem, "common:time", "file"));

        if (packages.find(name) != packages.end()) {
            if (packages[name].time >= time) return; // newer one already exists
        }

        //else
        packages[name] = {
            {},
            location,
            time
        };

        auto& package = packages[name];

        for_each_node(xpath_ctx.get(), package_elem, "common:format/rpm:requires/rpm:entry", [&package](xmlNodePtr entry) {
            package.rpm_requires.insert(get_single_attribute_element(entry, "name"));

        });

        for_each_node(xpath_ctx.get(), package_elem, "common:format/rpm:provides/rpm:entry", [&name,&providers](xmlNodePtr entry) {
            providers[get_single_attribute_element(entry, "name")].push_back(name);
        });
        for_each_node(xpath_ctx.get(), package_elem, "common:format/common:file", [&name,&providers](xmlNodePtr file) {
            providers[get_single_text_element(file)].push_back(name);
        });
    });

    std::set<std::string> rpms;
    for (const auto& i : packages_to_install) {
        install(i, rpms, packages, providers, dependency_excludes);
    }

    for (const auto& i : rpms) {
        auto url = base_url + i;
        auto wget = fork([&download_dir, &url]() {
            return execlp("wget", "wget", "-c", "-P", download_dir.c_str(), url.c_str(), NULL);
        });
        int wstatus;
        waitpid(wget, &wstatus, 0);
        if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) throw std::runtime_error("wget failed");
    }

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << std::endl;
        std::cout << "  " << argv[0] << " <base-url-contains-repodata-subdir> <subcommand> args..." << std::endl;
        return 1;
    }

    std::string base_url(argv[1]);
    if (!base_url.ends_with("/")) base_url += '/';

    std::map<std::string, std::function<int(const std::string&,int,char*[])>> subcommands = {
        {"get-packages-data", get_packages_data},
        {"download", download},
    };

    if (argc < 3) {
        std::cout << "subcommand required. Valid subcommands are:" << std::endl;
        for (auto sc:subcommands) {
            std::cout << sc.first << std::endl;
        }
        return 1;
    }

    if (subcommands.find(argv[2]) == subcommands.end()) {
        std::cout << "Subcommand " << argv[1] << " unknown. Valid subcommands are:" << std::endl;
        for (auto sc:subcommands) {
            std::cout << sc.first << std::endl;
        }
        return 1;
    }

    //else
    try {
        return subcommands[argv[2]](base_url, argc - 2, argv + 2);
    }
    catch (const std::runtime_error e) {
        std::cerr << e.what() << std::endl;
    }
    return -1;
}

// g++ -I /usr/include/libxml2 -std=c++20 -static-libgcc -static-libstdc++ -o rpmbootstrap rpmbootstrap.cpp -lxml2 -lcurl