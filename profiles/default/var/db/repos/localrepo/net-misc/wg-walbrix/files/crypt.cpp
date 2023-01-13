#include "crypt.h"

#include <iostream>
#include <openssl/err.h>

std::string base64_encode(const uint8_t* bytes, size_t len)
{
    char encoded[4*((len+2)/3)];
    if (!EVP_EncodeBlock((unsigned char*)encoded, bytes, len)) throw std::runtime_error("EVP_EncodeBlock() failed");
    //else
    return encoded;
}

std::string make_urlsafe(const std::string& base64str)
{
    std::string urlsafe_str;
    for (auto c:base64str) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
        urlsafe_str += c;
    }
    return urlsafe_str;
}

std::pair<std::shared_ptr<uint8_t[]>,size_t> base64_decode(const std::string& base64)
{
    std::shared_ptr<uint8_t[]> decoded(new uint8_t[3*base64.length()/4]);
    std::shared_ptr<EVP_ENCODE_CTX> ctx(EVP_ENCODE_CTX_new(), EVP_ENCODE_CTX_free);
    EVP_DecodeInit(ctx.get());
    int outl, outl2;
    EVP_DecodeUpdate(ctx.get(), decoded.get(), &outl, (const unsigned char*)base64.c_str(), base64.length());
    EVP_DecodeFinal(ctx.get(), decoded.get() + outl, &outl2);
    return {decoded, (size_t)outl + outl2};
}

std::pair<std::shared_ptr<uint8_t[]>, std::shared_ptr<uint8_t[]>> generate_key_and_iv_from_shared_key(const EVP_CIPHER* cipher, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/)
{
    std::shared_ptr<EVP_PKEY_CTX> pkey_ctx(EVP_PKEY_CTX_new(privkey, EVP_PKEY_get0_engine(privkey)), EVP_PKEY_CTX_free);
    EVP_PKEY_derive_init(pkey_ctx.get());
    EVP_PKEY_derive_set_peer(pkey_ctx.get(), pubkey);
    size_t skeylen;
    EVP_PKEY_derive(pkey_ctx.get(), NULL, &skeylen);
    std::shared_ptr<uint8_t[]> shared_key_bytes(new uint8_t[skeylen]);
    EVP_PKEY_derive(pkey_ctx.get(), shared_key_bytes.get(), &skeylen);

    std::shared_ptr<uint8_t[]> key(new uint8_t[EVP_CIPHER_key_length(cipher)]), iv(new uint8_t[EVP_CIPHER_iv_length(cipher)]);
    if (EVP_BytesToKey(cipher, EVP_md5(), nullptr, shared_key_bytes.get(), skeylen, 1, key.get(), iv.get()) == 0) {
        throw std::runtime_error("EVP_BytesToKey() failed");
    }
    //else
    return {key, iv};
}

std::string decrypt(const std::string& encrypted_b64, EVP_PKEY* privkey/*mine*/, EVP_PKEY* pubkey/*peer's*/)
{
    auto encrypted_bytes = base64_decode(encrypted_b64);

    auto [key, iv] = generate_key_and_iv_from_shared_key(cipher, privkey, pubkey);

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!EVP_DecryptInit_ex(ctx.get(), cipher, NULL, key.get(), iv.get())) throw std::runtime_error("EVP_DecryptInit_ex() failed");

    uint8_t buf[encrypted_bytes.second + EVP_CIPHER_block_size(cipher)];
    int len;
    if (!EVP_DecryptUpdate(ctx.get(), buf, &len, encrypted_bytes.first.get(), encrypted_bytes.second)) {
        throw std::runtime_error("EVP_DecryptUpdate() failed");
    }
    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx.get(), buf + len, &tmplen)) {
        auto err = ERR_get_error();
        char buf[120];
        ERR_error_string(err, buf);
        throw std::runtime_error("EVP_DecryptFinal_ex() failed: " + std::string(buf));
    }
    return std::string((const char*)buf, len + tmplen);
}
