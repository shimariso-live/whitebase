#include <vector>

int wg_genkey(const std::vector<std::string>& args);
int wg_pubkey(const std::vector<std::string>&);
int wg_getconfig(bool accept_ssh_key = false);
int wg_getconfig(const std::vector<std::string>& args);
int wg_notify(const std::vector<std::string>& args);
std::optional<std::string> get_pubkey_b64();
std::string get_authorization_url(const std::string& pubkey_b64);