/**
 * rpmbootstrap
 * 
 * Copyright (c) 2023 Tomoatsu Shimada <shimada@walbrix.com>
 * 
 * Released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include <string.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/mman.h>

#include <memory>
#include <set>
#include <filesystem>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <curl/curl.h>

#include <argparse/argparse.hpp>

static void for_each_node(xmlNodeSetPtr nodeset, std::function<void(xmlNodePtr)> func)
{
    if (!nodeset) return;
    for (int i = 0; i < nodeset->nodeNr; i++) {
        func(nodeset->nodeTab[i]);
    }
}

static void for_each_node(xmlXPathContextPtr ctx, const std::string& xpath, std::function<void(xmlNodePtr)> func)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathEval(BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    for_each_node(xpathobj->nodesetval, func);
}

static void for_each_node(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath, std::function<void(xmlNodePtr)> func)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathNodeEval(node, BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    for_each_node(xpathobj->nodesetval, func);
}

static std::string get_single_text_element(xmlNodePtr node)
{
    auto text = xmlNodeGetContent(node);
    if (!text) throw std::runtime_error("No text available with the node");
    std::string rst((const char*)text);
    xmlFree(text);
    return rst;
}

static xmlNodePtr get_single_element(xmlXPathContextPtr ctx, const std::string& xpath)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathEval(BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    if (!xpathobj->nodesetval) throw std::runtime_error("Nodeset is null");
    if (xpathobj->nodesetval->nodeNr == 0) throw std::runtime_error("Empty nodeset");
    return xpathobj->nodesetval->nodeTab[0];
}

static xmlNodePtr get_single_element(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath)
{
    std::shared_ptr<xmlXPathObject> xpathobj(xmlXPathNodeEval(node, BAD_CAST xpath.c_str(), ctx), xmlXPathFreeObject);
    if (xpathobj->type != XPATH_NODESET) throw std::runtime_error("XPath result is not a nodeset");
    if (!xpathobj->nodesetval) throw std::runtime_error("Nodeset is null");
    if (xpathobj->nodesetval->nodeNr == 0) throw std::runtime_error("Empty nodeset");
    return xpathobj->nodesetval->nodeTab[0];
}

static std::string get_single_text_element(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath)
{
    return get_single_text_element(get_single_element(ctx, node, xpath));
}

static std::string get_single_attribute_element(xmlNodePtr node, const std::string& attr)
{
    if (node->type != XML_ELEMENT_NODE)  throw std::runtime_error("Must be an element");
    auto prop = xmlGetProp(node, BAD_CAST attr.c_str());
    if (!prop) throw std::runtime_error("No attribute " + attr);
    std::string rst((const char*)prop);
    xmlFree(prop);
    return rst;
}

static std::string get_single_attribute_element(xmlXPathContextPtr ctx, const std::string& xpath, const std::string& attr)
{
    return get_single_attribute_element(get_single_element(ctx, xpath), attr);
}

static std::string get_single_attribute_element(xmlXPathContextPtr ctx, xmlNodePtr node, const std::string& xpath, const std::string& attr)
{
    return get_single_attribute_element(get_single_element(ctx, node, xpath), attr);
}

static size_t write_callback(char *buffer, size_t size, size_t nmemb, void *f)
{
    int fd  = *((int*)f);
    return write(fd, buffer, size * nmemb);
}

static void fetch(const std::string& url, const std::filesystem::path local_file)
{
    // TODO: retry
    auto fd = memfd_create(url.c_str(), 0);
    if (fd < 0) throw std::runtime_error("memfd_create() failed");
    std::shared_ptr<CURL> curl(curl_easy_init(), curl_easy_cleanup);
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &fd);
    int curl_rst = curl_easy_perform(curl.get());
    if (curl_rst != CURLE_OK) {
        close(fd);
        throw std::runtime_error("Error fetching " + url + ".");
    }
    //else
    long http_code = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        close(fd);
        throw std::runtime_error("Error fetching " + url + " (" + std::to_string(http_code) + ").");
    }

    auto tmpfile = std::filesystem::path("/proc") / std::to_string(getpid()) / "fd" / std::to_string(fd);
    try {
        std::filesystem::copy_file(tmpfile, local_file);
    }
    catch (const std::runtime_error& err) {
        close(fd);
        throw;
    }
    close(fd);
}

static std::string get_primary_xml_gz_url(const std::string& base_url, const std::filesystem::path& repomd_xml)
{
    std::shared_ptr<xmlDoc> doc(xmlReadFile(repomd_xml.c_str(), NULL, 0), xmlFreeDoc);
    if (!doc) throw std::runtime_error("Error parsing " + repomd_xml.string());
    std::shared_ptr<xmlXPathContext> xpath_ctx(xmlXPathNewContext(doc.get()), xmlXPathFreeContext);
    xmlXPathRegisterNs(xpath_ctx.get(), BAD_CAST "repo", BAD_CAST "http://linux.duke.edu/metadata/repo");
    xmlXPathRegisterNs(xpath_ctx.get(), BAD_CAST "rpm", BAD_CAST "http://linux.duke.edu/metadata/rpm");

    auto href = get_single_attribute_element(xpath_ctx.get(), "//repo:data[@type='primary']/repo:location", "href");

    return base_url + href;
}

static void decompress_gz(const std::filesystem::path& gzfile)
{
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    //else
    if (pid == 0) {
        _exit(execlp("gunzip", "gunzip", gzfile.c_str(), NULL));
    }
    //else
    int wstatus;
    waitpid(pid, &wstatus, 0);

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) throw std::runtime_error("Gunzip failed");
}

struct Package {
    std::set<std::string> rpm_requires;
    std::string location;
    uint64_t time;
};

typedef std::pair<std::map<std::string,Package>/*packages*/,std::map<std::string,std::vector<std::string>>/*providers*/> PackageDependency;

static PackageDependency load_package_dependency(const std::filesystem::path& primary_xml, const std::string& arch)
{
    std::shared_ptr<xmlDoc> doc(xmlReadFile(primary_xml.c_str(), NULL, 0), xmlFreeDoc);

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
            auto rpm_require = get_single_attribute_element(entry, "name");
            if (rpm_require[0] != '(') { // exclude entry like '(glibc-gconv-extra(x86-64) = 2.34-54.el9 if redhat-rpm-config)'
                package.rpm_requires.insert(rpm_require);
            }
        });

        for_each_node(xpath_ctx.get(), package_elem, "common:format/rpm:provides/rpm:entry", [&name,&providers](xmlNodePtr entry) {
            providers[get_single_attribute_element(entry, "name")].push_back(name);
        });
        for_each_node(xpath_ctx.get(), package_elem, "common:format/common:file", [&name,&providers](xmlNodePtr file) {
            providers[get_single_text_element(file)].push_back(name);
        });
    });
    return {packages,providers};
}

static void collect(const std::string& name, std::set<std::string>& rpms, const PackageDependency& package_dependency, 
    const std::set<std::string>& dependency_excludes)
{
    const auto& [packages, providers] = package_dependency;
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
        collect(provider->second[0], rpms, package_dependency, dependency_excludes);
    }
}

static std::vector<std::string> determine_rpms_to_install(const PackageDependency& package_dependency,
    const std::vector<std::string>& includes, const std::vector<std::string>& dependency_excludes)
{
    std::set<std::string> rpms;
    std::set<std::string> dependency_excludes_set(dependency_excludes.begin(), dependency_excludes.end());
    for (const auto& i : includes) {
        collect(i, rpms, package_dependency, dependency_excludes_set);
    }
    return std::vector(rpms.begin(), rpms.end());
}

static void install_rpms(const std::filesystem::path& root_dir, 
    const std::vector<std::filesystem::path>& local_rpm_files,
    bool nosignature = false)
{
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    //else
    if (pid == 0) {
        // "rpm -Uvh -r /root_dir work_dir/*.rpm"
        char** argv = (char**)malloc(sizeof(char*) * (local_rpm_files.size() + 6));
        argv[0] = strdup("rpm");
        argv[1] = strdup("-Uvh");
        argv[2] = strdup("--force");
        argv[3] = strdup("-r");
        argv[4] = strdup(std::filesystem::canonical(root_dir).c_str());
        int i = 5;
        if (nosignature) argv[i++] = strdup("--nosignature");
        for (const auto& local_rpm_file:local_rpm_files) {
            argv[i++] = strdup(local_rpm_file.c_str());
        }
        argv[i] = NULL;
        _exit(execvp("rpm", argv));
    }
    //else
    int wstatus;
    waitpid(pid, &wstatus, 0);

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) throw std::runtime_error("rpm failed");

}

static int _main(const std::string& base_url, const std::filesystem::path& root_dir, 
    const std::vector<std::string>& packages, const std::vector<std::string>& dependency_excludes = {},
    bool nosignature = false)
{
    if (!std::filesystem::is_directory(root_dir)) throw std::runtime_error(root_dir.string() + " is not a directory.");

    auto work_dir = (root_dir / "tmp" / "rpmbootstrap");
    std::filesystem::create_directories(work_dir);

    auto primary_xml = work_dir / "primary.xml";
    if (!std::filesystem::exists(primary_xml)) {
        auto primary_xml_gz = work_dir / "primary.xml.gz";
        if (!std::filesystem::exists(primary_xml_gz)) {
            auto repomd_xml = work_dir / "repomd.xml";
            if (!std::filesystem::exists(repomd_xml)) {
                auto remomd_xml_url = base_url + "repodata/repomd.xml";
                std::cout << "Fetching " << remomd_xml_url << "..." << std::endl;
                fetch(remomd_xml_url, repomd_xml);
            }
            auto primary_xml_gz_url = get_primary_xml_gz_url(base_url, repomd_xml);
            std::cout << "Fetching " << primary_xml_gz_url << "..." << std::endl;
            fetch(primary_xml_gz_url, primary_xml_gz);
        }
        decompress_gz(primary_xml_gz); // to produce primary_xml
    }

    struct utsname un;
    if (uname(&un) < 0) throw std::runtime_error("uname() failed");
    std::string arch(un.machine);

    auto package_dependency = load_package_dependency(primary_xml, arch);
    auto rpms_to_install = determine_rpms_to_install(package_dependency, packages, dependency_excludes);
    std::vector<std::filesystem::path> local_rpm_files;
    for (const auto& rpm : rpms_to_install) {
        auto local_rpm_file = work_dir / std::filesystem::path(rpm).filename();
        if (!std::filesystem::exists(local_rpm_file)) {
            auto rpm_url = base_url + rpm;
            std::cout << "Fetching " << rpm_url << "..." << std::endl;
            fetch(rpm_url, local_rpm_file);
        }
        local_rpm_files.push_back(local_rpm_file);
    }
    install_rpms(root_dir, local_rpm_files, nosignature); 
    std::cout << "Cleaning up working directory..." << std::endl;
    std::filesystem::remove_all(work_dir);
    std::cout << "Done." << std::endl;
    return 0;
}

#ifdef __VSCODE_ACTIVE_FILE__
#define __USE_REAL_MAIN__
#ifndef __USE_REAL_MAIN__
int main(int argc, char* argv[])
{
    return _main(
        "http://ftp.iij.ad.jp/pub/linux/centos-vault/6.10/os/x86_64/", "rpmbootstrap.tmp", 
        {"yum"}, 
        {}
    );    
}
#endif
#endif

#ifdef __USE_REAL_MAIN__
int main(int argc, char* argv[])
{
    argparse::ArgumentParser program(argv[0]);
    program.add_argument("-x", "--dependency-exclude").append();
    program.add_argument("--no-signature").default_value(false).implicit_value(true).help("Do not check package signature");
    program.add_argument("base-url").nargs(1).help("Base URL of distribution");
    program.add_argument("root_dir").nargs(1).help("Root directory to bootstrap");
    program.add_argument("packages").nargs(argparse::nargs_pattern::at_least_one).help("packages to install");

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << program;
        return 1;
    }

    std::string base_url = program.get("base-url");
    if (!base_url.ends_with("/")) base_url += "/";

    try {
        return _main(
            base_url, program.get("root_dir"), 
            program.get<std::vector<std::string>>("packages"), 
            program.get<std::vector<std::string>>("-x"),
            program.get<bool>("--no-signature")
        );
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }

    return 0;
}
#endif