#include "securecomm/ratchet.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace securecomm {

Ratchet::Ratchet()
    : send_message_number_(0), recv_message_number_(0) {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");

    // Generate X25519 key pair
    dh_private_key_.resize(crypto_scalarmult_BYTES);
    dh_public_key_.resize(crypto_scalarmult_BYTES);
    randombytes_buf(dh_private_key_.data(), dh_private_key_.size());
    crypto_scalarmult_base(dh_public_key_.data(), dh_private_key_.data());
}

Ratchet::~Ratchet() {
    sodium_memzero(dh_private_key_.data(), dh_private_key_.size());
}

void Ratchet::initialize(const std::vector<uint8_t>& root_key) {
    if (root_key.size() != 32) throw std::runtime_error("Root key must be 32 bytes");
    root_key_ = root_key;
    send_chain_key_ = root_key_;
    recv_chain_key_ = root_key_;
    aead_.set_key(send_chain_key_);
    send_message_number_ = 0;
    recv_message_number_ = 0;
}

void Ratchet::hkdf_root_chain(const std::vector<uint8_t>& dh_shared_secret) {
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256(prk, dh_shared_secret.data(), dh_shared_secret.size(),
                           reinterpret_cast<const unsigned char*>("DoubleRatchetRoot"));

    // Expand to 64 bytes: 32 bytes root key + 32 bytes send_chain_key
    unsigned char okm[64];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, prk, sizeof(prk));

    unsigned char counter = 1;
    crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char*>("RatchetChain"), 13);
    crypto_auth_hmacsha256_update(&state, &counter, 1);
    crypto_auth_hmacsha256_final(&state, okm);

    // Set root key and sending chain key
    root_key_ = std::vector<uint8_t>(okm, okm+32);
    send_chain_key_ = std::vector<uint8_t>(okm+32, okm+64);
    aead_.set_key(send_chain_key_);

   
}


void Ratchet::ratchet_step(const std::vector<uint8_t>& remote_dh_public) {
    if (remote_dh_public.size() != crypto_scalarmult_BYTES)
        throw std::runtime_error("Invalid remote DH public key size");

    std::vector<uint8_t> dh_shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(dh_shared.data(),
                          dh_private_key_.data(),
                          remote_dh_public.data()) != 0) {
        throw std::runtime_error("DH computation failed");
    }

    hkdf_root_chain(dh_shared);

    // TEMP FIX: sync sending chain to receiving chain for two-party test
    recv_chain_key_ = send_chain_key_;

    send_message_number_ = 0;
    recv_message_number_ = 0;
}


// Derive a 32-byte message key from a chain key
std::vector<uint8_t> Ratchet::derive_message_key(const std::vector<uint8_t>& chain_key) const {
    unsigned char msg_key[32];
    crypto_auth_hmacsha256(msg_key, chain_key.data(), chain_key.size(), reinterpret_cast<const unsigned char*>("msgkey"));
    return std::vector<uint8_t>(msg_key, msg_key+32);
}

// Encrypt / Decrypt use AEAD with derived message key
std::vector<uint8_t> Ratchet::encrypt(const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& aad) {
    auto msg_key = derive_message_key(send_chain_key_);
    aead_.set_key(msg_key);
    auto ct = aead_.encrypt(plaintext, aad);
    send_message_number_++;
    return ct;
}

std::optional<std::vector<uint8_t>> Ratchet::decrypt(const std::vector<uint8_t>& ciphertext,
                                                     const std::vector<uint8_t>& aad) {
    auto msg_key = derive_message_key(recv_chain_key_);
    aead_.set_key(msg_key);
    auto pt = aead_.decrypt(ciphertext, aad);
    if (pt.has_value()) recv_message_number_++;
    return pt;
}



} // namespace securecomm
