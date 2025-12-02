#include "securecomm/crypto.hpp"
#include <sodium.h>
#include <stdexcept>
#include <optional>

namespace securecomm {

AEAD::AEAD() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

AEAD::~AEAD() {
    sodium_memzero(key_.data(), key_.size());
}

void AEAD::set_key(const std::vector<uint8_t>& key) {
    if (key.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("AEAD key must be 32 bytes");
    }
    key_ = key;
}

std::vector<uint8_t> AEAD::encrypt(const std::vector<uint8_t>& plaintext,
                                   const std::vector<uint8_t>& aad) const {
    if (key_.empty()) throw std::runtime_error("AEAD key not set");

    std::vector<uint8_t> nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long clen;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &clen,
            plaintext.data(), plaintext.size(),
            aad.data(), aad.size(),
            nullptr, nonce.data(), key_.data()) != 0) {
        throw std::runtime_error("AEAD encryption failed");
    }

    ciphertext.insert(ciphertext.begin(), nonce.begin(), nonce.end());
    return ciphertext;
}

std::optional<std::vector<uint8_t>> AEAD::decrypt(const std::vector<uint8_t>& ciphertext,
                                                   const std::vector<uint8_t>& aad) const {
    if (key_.empty()) return std::nullopt;
    if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_NPUBBYTES + crypto_aead_chacha20poly1305_ietf_ABYTES)
        return std::nullopt;

    const size_t nonce_len = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + nonce_len);
    std::vector<uint8_t> ctext(ciphertext.begin() + nonce_len, ciphertext.end());

    std::vector<uint8_t> plaintext(ctext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plen;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plen,
            nullptr,
            ctext.data(), ctext.size(),
            aad.data(), aad.size(),
            nonce.data(), key_.data()) != 0) {
        return std::nullopt;
    }

    plaintext.resize(plen);
    return plaintext;
}

} 
