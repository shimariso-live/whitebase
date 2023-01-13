#include <memory>

#include <openssl/evp.h>

static const size_t WG_KEY_LEN = 32;
static const auto cipher = EVP_des_ede3_cbc();
std::string base64_encode(const uint8_t* bytes, size_t len);
std::string make_urlsafe(const std::string& base64str);
std::pair<std::shared_ptr<uint8_t[]>,size_t> base64_decode(const std::string& base64);
std::pair<std::shared_ptr<uint8_t[]>, std::shared_ptr<uint8_t[]>> generate_key_and_iv_from_shared_key(const EVP_CIPHER* cipher, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/);
std::string decrypt(const std::string& encrypted_b64, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/);