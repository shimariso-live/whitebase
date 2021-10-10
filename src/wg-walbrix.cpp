#include <filesystem>
#include <cassert>
#include <fstream>

#include <iniparser4/iniparser.h>
#include <yajl/yajl_gen.h>

#include "crypt.h"
#include "yajl_value.h"

#ifndef NSS_MODULE
#include <memory.h>
#include <getopt.h>
#include <sys/wait.h>

#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <optional>
#include <variant>
#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf

#include "common.h"

#else // NSS_MODULE
#include <string.h>
#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

static const std::filesystem::path wg_conf_path("/etc/wireguard/wg-walbrix.conf"), data_dir("/var/lib/wg-walbrix");
static const std::filesystem::path public_dir = data_dir / "public", serial_dir = data_dir / "serial";

#ifndef NSS_MODULE
static const std::filesystem::path endpoint_hostname_file = data_dir / "endpoint_hostname";
static const std::string interface("wg-walbrix");
static const std::string network_prefix("fd00::/8");

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

    std::shared_ptr<struct option[]> clongopts(new struct option[longopts.size() + 1]);

    struct option* p = clongopts.get();
    for (const auto& lo:longopts) { 
        memcpy(p, &lo, sizeof(*p));
        p++;
    }
    memset(p, 0, sizeof(*p));
    int c;
    int longindex = 0;
    while ((c = getopt_long(argc, argv, shortopts.c_str(), clongopts.get(), &longindex)) >= 0) {
        const auto func = funcs.find(c == 0? clongopts.get()[longindex].name : std::string(1,(char)c));
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

    std::vector<std::string> non_option_args;
    for (int i = optind; i < argc; i++) {
        non_option_args.push_back(argv[i]);
    }

    return non_option_args;
}

static std::string make_urlunsafe(const std::string& urlsafe_base64str)
{
    std::string urlunsafe_str;
    for (auto c:urlsafe_base64str) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        urlunsafe_str += c;
    }
    return urlunsafe_str;
}

static std::string encrypt(const std::string& str, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/)
{
    auto [key, iv] = generate_key_and_iv_from_shared_key(cipher, privkey, pubkey);

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!EVP_EncryptInit_ex(ctx.get(), cipher, NULL, key.get(), iv.get())) throw std::runtime_error("EVP_EncryptInit_ex() failed");
    uint8_t buf[str.length() + EVP_CIPHER_block_size(cipher) - 1];
    int len, tmplen;
    if (!EVP_EncryptUpdate(ctx.get(), buf, &len, (const unsigned char*)str.c_str(), str.length())) {
        throw std::runtime_error("EVP_EncryptUpdate() failed");
    }
    if (!EVP_EncryptFinal_ex(ctx.get(), buf + len, &tmplen)) {
        throw std::runtime_error("EVP_EncryptFinal_ex() failed");
    }
    return base64_encode(buf, len + tmplen);
}

static std::string pubkey_bytes_to_address(const uint8_t* pubkey_bytes)
{
    char buf[4*8+7+1];
    sprintf(buf, "fd%02x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", 
        (int)pubkey_bytes[0], 
        (((int)pubkey_bytes[1]) << 8) | pubkey_bytes[2], 
        (((int)pubkey_bytes[3]) << 8) | pubkey_bytes[4],
        (((int)pubkey_bytes[5]) << 8) | pubkey_bytes[6], 
        (((int)pubkey_bytes[7]) << 8) | pubkey_bytes[8], 
        (((int)pubkey_bytes[9]) << 8) | pubkey_bytes[10], 
        (((int)pubkey_bytes[11]) << 8) | pubkey_bytes[12], 
        (((int)pubkey_bytes[13]) << 8) | pubkey_bytes[14] 
    );
    return buf;
}

static std::string pubkey_bytes_to_serial(const uint8_t* pubkey_bytes)
{
    const uint8_t* b = pubkey_bytes + 27;
    std::string serial;
    for (auto n:{
        (b[0] >> 3) & 0x1f,
        ((b[0] << 2) + (b[1] >> 6)) & 0x1f,
        (b[1] >> 1) & 0x1f,
        ((b[1] << 4) + (b[2] >> 4)) & 0x1f,
        ((b[2] << 1) + (b[3] >> 7)) & 0x1f,
        (b[3] >> 2) & 0x1f,
        ((b[3] << 3) + (b[4] >> 5)) & 0x1f,
        b[4] & 0x1f
    }) {
        serial += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[n];
    }
    return serial;
}

int init(int argc, char* argv[])
{
    auto usage = [argv]() {
        std::cout << "Usage:" << std::endl;
        std::cout << argv[0] << " <endpoint-hostname>" << std::endl;
        return 1;
    };

    auto args = getopt(argc, argv, {
        {'h', "help", [usage]() {
            exit(usage());
        }}
    });

    if (args.size() < 1) {
        return usage();
    }

    auto endpoint_hostname = args[0];
    std::filesystem::create_directories(serial_dir);
    std::filesystem::create_directories(public_dir);

    std::ofstream f(endpoint_hostname_file);
    if (!f) throw std::runtime_error(endpoint_hostname_file.string() + " cannot be opened for write");
    f << endpoint_hostname;

    return 0;
}

int authorize(int argc, char* argv[])
{
    auto usage = [argv]() {
        std::cout << "Usage:" << std::endl;
        std::cout << argv[0] << " [--serial=ABCD1234] [--force] <client-pubkey-in-base64>" << std::endl;
        return 1;
    };

    std::optional<std::string> serial;
    bool force = false;
    auto args = getopt(argc, argv, {
        {'h', "help", [usage]() {
            exit(usage());
        }},
        {'f', "force", [&force]() {
            force = true;
        }},
        {'s', "serial", (std::function<void(const std::string&)>)[&serial](const auto& optarg) {
            serial = optarg;
        }}
    });

    if (args.size() < 1) {
        return usage();
    }
    //else
    std::string endpoint_hostname;
    {
        std::ifstream f(endpoint_hostname_file);
        if (!f) throw std::runtime_error("Cannot open " + endpoint_hostname_file.string() + ". 'init' not done yet?");
        f >> endpoint_hostname;
    }

    auto peer_pubkey_b64 = args[0];
    auto peer_pubkey_bytes = base64_decode(peer_pubkey_b64);
    std::shared_ptr<EVP_PKEY> peer_pubkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey_bytes.first.get(), std::min(WG_KEY_LEN, peer_pubkey_bytes.second)), EVP_PKEY_free);
    if (!peer_pubkey) throw std::runtime_error("Invalid client public key " + peer_pubkey_b64);

    std::shared_ptr<dictionary> wg_conf(iniparser_load(wg_conf_path.c_str()), iniparser_freedict);
    if (!wg_conf) throw std::runtime_error("Couldn't open " + wg_conf_path.string());
    // else
    auto privkey_base64 = iniparser_getstring(wg_conf.get(), "interface:PrivateKey", NULL);
    if (!privkey_base64) throw std::runtime_error("PrivateKey is not defined in " + wg_conf_path.string());
    //else
    auto privkey_bytes = base64_decode(privkey_base64);
    auto privkey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey_bytes.first.get(), std::min(WG_KEY_LEN, privkey_bytes.second)), EVP_PKEY_free);
    if (!privkey) throw std::runtime_error("Private key is invalid(EVP_PKEY_new_raw_private_key failed).");

    unsigned char my_pubkey_bytes[WG_KEY_LEN];
    size_t my_pubkey_len = WG_KEY_LEN;
    if (!EVP_PKEY_get_raw_public_key(privkey.get(), my_pubkey_bytes, &my_pubkey_len)) {
        throw std::runtime_error("Unable to generate public key from private key(EVP_PKEY_get_raw_public_key failed)");
    }
    auto port = iniparser_getstring(wg_conf.get(), "interface:ListenPort", NULL);
    if (!port) throw std::runtime_error("ListenPort is not defined in " + wg_conf_path.string());;

    auto my_address = iniparser_getstring(wg_conf.get(), "interface:Address", NULL);
    if (!my_address) throw std::runtime_error("Address is not defined in " + wg_conf_path.string());;

    auto homedir_cstr = getenv("HOME");
    std::filesystem::path homedir(homedir_cstr? homedir_cstr : "/root");
    std::ifstream id_rsa_pub(homedir / ".ssh/id_rsa.pub");
    std::optional<std::string> sshkey = id_rsa_pub? [](auto& f){
        std::string s;
        return (std::getline(f, s) && s != "") ? std::make_optional(s) : std::nullopt;
    }(id_rsa_pub) : std::nullopt;

    if (!serial) {
        serial = pubkey_bytes_to_serial(peer_pubkey_bytes.first.get());
    }

    std::shared_ptr<yajl_gen_t> gen(yajl_gen_alloc(NULL), yajl_gen_free);
    yajl_gen_map_open(gen.get());
    yajl_gen_string(gen.get(), (const unsigned char*)"endpoint", 8);
    std::string endpoint = endpoint_hostname + ':' + port;
    yajl_gen_string(gen.get(), (const unsigned char*)endpoint.c_str(), endpoint.length());
    yajl_gen_string(gen.get(), (const unsigned char*)"peer-address", 12);
    yajl_gen_string(gen.get(), (const unsigned char*)my_address, strlen(my_address));
    yajl_gen_string(gen.get(), (const unsigned char*)"address", 7);
    auto address = pubkey_bytes_to_address(peer_pubkey_bytes.first.get());
    auto address_with_length = address + "/128";
    yajl_gen_string(gen.get(), (const unsigned char*)address_with_length.c_str(), address_with_length.length());
    if (sshkey) {
        yajl_gen_string(gen.get(), (const unsigned char*)"ssh-key", 7);
        yajl_gen_string(gen.get(), (const unsigned char*)sshkey.value().c_str(), sshkey.value().length());
    }
    if (serial) {
        yajl_gen_string(gen.get(), (const unsigned char*)"serial", 6);
        yajl_gen_string(gen.get(), (const unsigned char*)serial.value().c_str(), serial.value().length());
    }
    yajl_gen_map_close(gen.get());
    const uint8_t* buf;
    size_t len;
    yajl_gen_get_buf(gen.get(), &buf, &len);
    std::string json((const char*)buf, len);

    auto client_file =  public_dir / make_urlsafe(peer_pubkey_b64);
    if (!std::filesystem::exists(client_file) || force) {
        std::ofstream f(client_file);
        if (!f) throw std::runtime_error("client file couldn't be open for write");
        //else
        f << base64_encode(my_pubkey_bytes, my_pubkey_len) << ',' << encrypt(json, privkey.get(), peer_pubkey.get()) << std::endl;
    } else {
        throw std::runtime_error("Client file " + client_file.string() + " already exists.  Use --force to overwrite");
    }

    if (serial) {
        std::ofstream f(serial_dir / serial.value());
        if (!f) throw std::runtime_error("serial file couldn't be open for write");
        f << peer_pubkey_b64 << std::endl;
        f << address << std::endl;
    }

    std::cout << "Client authorized successfully." << std::endl;
    std::cout << "Serial: " << serial.value_or("N/A") << std::endl;
    std::cout << "Public Key: " << peer_pubkey_b64 << std::endl;
    std::cout << "Client file: " << client_file << std::endl;
    std::cout << "Address: " << address << std::endl;

    return 0;
}

static std::string determine_pubkey(const std::string& serial_or_pubkey_b64)
{
    if (std::filesystem::exists(public_dir / make_urlsafe(serial_or_pubkey_b64))) {
        return serial_or_pubkey_b64;
    }
    
    //else
    if (std::filesystem::exists(serial_dir / serial_or_pubkey_b64)) {
        std::ifstream f(serial_dir / serial_or_pubkey_b64);
        if (f) {
            std::string s;
            f >> s;
            return s;
        }
    }

    throw std::runtime_error(serial_or_pubkey_b64 + " is not a serial or pubkey");
}

int show(int argc, char* argv[])
{
    auto usage = [argv]() {
        std::cout << "Usage:" << std::endl;
        std::cout << argv[0] << " <serial|pubkey in base64>" << std::endl;
        return 1;
    };

    auto args = getopt(argc, argv, {
        {'h', "help", [usage]() {
            exit(usage());
        }}
    });

    if (args.size() < 1) {
        return usage();
    }

    auto peer_pubkey_b64 = determine_pubkey(args[0]);

    auto peer_pubkey_bytes = base64_decode(peer_pubkey_b64);
    std::shared_ptr<EVP_PKEY> peer_pubkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey_bytes.first.get(), std::min(WG_KEY_LEN, peer_pubkey_bytes.second)), EVP_PKEY_free);
    if (!peer_pubkey) throw std::runtime_error("Invalid client public key " + peer_pubkey_b64);

    std::shared_ptr<dictionary> wg_conf(iniparser_load(wg_conf_path.c_str()), iniparser_freedict);
    if (!wg_conf) throw std::runtime_error("Couldn't open " + wg_conf_path.string());
    // else
    auto privkey_base64 = iniparser_getstring(wg_conf.get(), "interface:PrivateKey", NULL);
    if (!privkey_base64) throw std::runtime_error("PrivateKey is not defined in " + wg_conf_path.string());
    //else
    auto privkey_bytes = base64_decode(privkey_base64);
    auto privkey = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey_bytes.first.get(), std::min(WG_KEY_LEN, privkey_bytes.second)), EVP_PKEY_free);
    if (!privkey) throw std::runtime_error("Private key is invalid(EVP_PKEY_new_raw_private_key failed).");

    auto client_file = public_dir / make_urlsafe(peer_pubkey_b64);
    std::ifstream f(client_file);
    if (!f) throw std::runtime_error(client_file.string() + " couldn't be opened");
    //else
    std::string line;
    f >> line;
    auto comma_pos = line.find_first_of(',');
    if (comma_pos != line.npos) line.erase(line.begin(), line.begin() + comma_pos + 1);

    std::cout << decrypt(line, privkey.get(), peer_pubkey.get()) << std::endl;
    return 0;
}

int _delete(int argc, char* argv[])
{
    auto usage = [argv]() {
        std::cout << "Usage:" << std::endl;
        std::cout << argv[0] << " <serial|pubkey in base64>" << std::endl;
        return 1;
    };

    auto args = getopt(argc, argv, {
        {'h', "help", [usage]() {
            exit(usage());
        }}
    });

    if (args.size() < 1) {
        return usage();
    }

    auto peer_pubkey_b64 = determine_pubkey(args[0]);
    auto client_file = public_dir / make_urlsafe(peer_pubkey_b64);

    std::filesystem::remove(client_file);

    return 0;
}

int load(int argc, char* argv[])
{
    std::shared_ptr<dictionary> wg_conf(iniparser_load(wg_conf_path.c_str()), iniparser_freedict);
    if (!wg_conf) throw std::runtime_error("Couldn't open " + wg_conf_path.string());

    auto privkey_base64 = iniparser_getstring(wg_conf.get(), "interface:PrivateKey", NULL);
    if (!privkey_base64) throw std::runtime_error("PrivateKey is not defined in " + wg_conf_path.string());
    auto my_address = iniparser_getstring(wg_conf.get(), "interface:Address", NULL);
    if (!my_address) throw std::runtime_error("Address is not defined in " + wg_conf_path.string());

    check_call({"ip", "route", "replace", network_prefix, "dev", interface});

    auto [pid, in] = forkinput([]() {
        exec({"wg", "show", interface, "peers"});
        //exec({"ls", "-1", "/"});
        return -1;
    });

    std::set<std::string> present_peers;
    {
        __gnu_cxx::stdio_filebuf<char> filebuf(in, std::ios::in);
        std::istream f(&filebuf);
        std::string line;
        while (std::getline(f, line)) {
            if (line != "") present_peers.insert(line);
        }
    }

    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) throw std::runtime_error("wg command failed");

    for (const auto& d : std::filesystem::directory_iterator(public_dir)) {
        if (!d.is_regular_file()) continue;
        auto pubkey_b64 = make_urlunsafe(d.path().filename().string());
        if (present_peers.find(pubkey_b64) == present_peers.end()) {
            auto pubkey_bytes = base64_decode(pubkey_b64);
            auto address = pubkey_bytes_to_address(pubkey_bytes.first.get());
            check_call({"wg", "set", interface, "peer", pubkey_b64, "allowed-ips", address + "/128"});
        } else {
            present_peers.erase(pubkey_b64);
        }
    }

    for (const auto& p:present_peers) {
        check_call({"wg", "set", interface, "peer", p, "remove"});
    }

    return 0;
}

int main(int argc, char* argv[])
{
    std::map<std::string, std::function<int(int,char*[])>> subcommands = {
        {"init", init},
        {"authorize", authorize},
        {"show", show},
        {"delete", _delete},
        {"load", load}
    };

    if (argc < 2) {
        std::cout << "subcommand required. Valid subcommands are:" << std::endl;
        for (auto sc:subcommands) {
            std::cout << sc.first << std::endl;
        }
        return 1;
    }

    if (subcommands.find(argv[1]) == subcommands.end()) {
        std::cout << "Subcommand " << argv[1] << " unknown. Valid subcommands are:" << std::endl;
        for (auto sc:subcommands) {
            std::cout << sc.first << std::endl;
        }
        return 1;
    }

    //else
    try {
        return subcommands[argv[1]](argc - 1, argv + 1);
    }
    catch (const std::runtime_error e) {
        std::cerr << e.what() << std::endl;
    }
    return -1;
}

#else // NSS_MODULE
static struct in6_addr lookup(const std::string& hostname)
{
    if (!std::filesystem::exists(serial_dir / hostname)) throw NSS_STATUS_NOTFOUND;

    std::string address;

    {
        std::ifstream f(serial_dir / hostname);
        if (!f) throw NSS_STATUS_NOTFOUND;

        f >> address; // skip pubkey
        f >> address;
    }

    if (address == "") throw NSS_STATUS_NOTFOUND;

    struct in6_addr addr;
    if (inet_pton(AF_INET6, address.c_str(), &addr) != 1) {
        throw NSS_STATUS_NOTFOUND;
    }
    //else
    return addr;
}

#define ALIGN(a) (((a+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))

static enum nss_status fill_in_hostent(
				const char *hn,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
				int32_t *ttlp,
                char **canonp,
				const struct in6_addr& addr) {

	size_t alen = sizeof(in6_addr);

	size_t l = strlen(hn);
	size_t ms = ALIGN(l+1)+sizeof(char*)+ALIGN(alen)+sizeof(char*)*2;
	if (buflen < ms) {
		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	}

	/* First, fill in hostname */
	char* r_name = buffer;
	memcpy(r_name, hn, l+1);
	size_t idx = ALIGN(l+1);

	/* Second, create aliases array */
	char* r_aliases = buffer + idx;
	*(char**) r_aliases = NULL;
	idx += sizeof(char*);

	/* Third, add address */
	char* r_addr = buffer + idx;
	*(struct in6_addr*) r_addr = addr;
	idx += ALIGN(alen);

	/* Fourth, add address pointer array */
	char* r_addr_list = buffer + idx;
	((char**) r_addr_list)[0] = r_addr;
	((char**) r_addr_list)[1] = NULL;
	idx += sizeof(char*)*2;

	/* Verify the size matches */
	assert(idx == ms);

	result->h_name = r_name;
	result->h_aliases = (char**) r_aliases;
	result->h_addrtype = AF_INET6;
	result->h_length = alen;
	result->h_addr_list = (char**) r_addr_list;

	if (ttlp) *ttlp = 0;
	if (canonp) *canonp = r_name;

	return NSS_STATUS_SUCCESS;
}

extern "C" {
enum nss_status _nss_wg_walbrix_gethostbyname3_r(
                const char *name,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp) {
	//std::cout << "_nss_openvpn_gethostbyname3_r" << std::endl;

	if (af == AF_UNSPEC) af = AF_INET6;

	if (af != AF_INET6) {
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_DATA;
		return NSS_STATUS_UNAVAIL;
	}

	try {
		auto addr = lookup(name);
		return fill_in_hostent(name, host, buffer, buflen, errnop, h_errnop, ttlp, canonp, addr);
	}
	catch (enum nss_status& st) {
		if (st == NSS_STATUS_NOTFOUND) {
			*errnop = ENOENT;
			*h_errnop = HOST_NOT_FOUND;
		} else if (st == NSS_STATUS_TRYAGAIN) {
			*errnop = EINVAL;
			*h_errnop = NO_RECOVERY;
		} else {
			*errnop = EINVAL;
			*h_errnop = NO_RECOVERY;
		}
		return st;
	}
}

enum nss_status _nss_wg_walbrix_gethostbyname2_r(
                const char *name,
                 int af,
                 struct hostent *host,
                char *buffer, size_t buflen,
                 int *errnop, int *h_errnop) {
 
         return _nss_wg_walbrix_gethostbyname3_r(
                         name,
                         af,
                         host,
                         buffer, buflen,
                         errnop, h_errnop,
                         NULL,
                         NULL);
}

enum nss_status _nss_wg_walbrix_gethostbyname_r(
	const char *name,
	struct hostent* host,
	char *buffer, size_t buflen,
	int *errnop, int *h_errnop
	) {

	//std::cout << "_nss_wg_walbrix_gethostbyname_r" << std::endl;

	try {
		auto addr = lookup(name);
		return fill_in_hostent(name, host, buffer, buflen, errnop, h_errnop, NULL, NULL, addr);
	}
	catch (enum nss_status& st) {
		if (st == NSS_STATUS_NOTFOUND) {
			*errnop = ENOENT;
			*h_errnop = HOST_NOT_FOUND;
		} else if (st == NSS_STATUS_TRYAGAIN) {
			*errnop = EINVAL;
			*h_errnop = NO_RECOVERY;
		} else {
			*errnop = EINVAL;
			*h_errnop = NO_RECOVERY;
		}
		return st;
	}

}
} // extern "C"
#endif

/*
#etc/systemd/system/wg-walbrix.service
[Unit]
Description=Registration service for wg-walbrix
After=network.target wg-quick@wg-walbrix.service
PartOf=wg-quick@wg-walbrix.service

[Service]
ExecStart=/usr/local/bin/wg-walbrix load
Type=simple

[Install]
WantedBy=multi-user.target
*/

// g++ -std=c++2a -o wg-walbrix-authorize wg-walbrix-authorize.cpp -lssl -lcrypto -liniparser4 -lyajl
