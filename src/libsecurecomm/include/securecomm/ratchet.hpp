#pragma once

#include "crypto.hpp"
#include <vector>
#include <cstdint>
#include <optional>
#include <map>

namespace securecomm {

class Ratchet {
public:
    Ratchet();
    ~Ratchet();

    // Initialize the ratchet with a 32-byte root key
    void initialize(const std::vector<uint8_t>& root_key);

    // Perform a ratchet step using the remote's DH public key (called when we see a new remote DH)
    void ratchet_step(const std::vector<uint8_t>& remote_dh_public);

    // Encrypt a plaintext message. The returned blob includes header+AEAD ciphertext.
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& aad = {});

    // Decrypt a wire message produced by encrypt(). Returns plaintext or nullopt on failure.
    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& wire_blob,
                                                const std::vector<uint8_t>& aad = {});

    // Export/import state for persistence (basic)
    std::vector<uint8_t> export_state() const;
    void import_state(const std::vector<uint8_t>& state);

    // Access public key for DH exchange
    const std::vector<uint8_t>& dh_public_key() const { return dh_public_key_; }

private:
    // Root & chain keys (32 bytes)
    std::vector<uint8_t> root_key_;
    std::vector<uint8_t> send_chain_key_;
    std::vector<uint8_t> recv_chain_key_;

    // Message counters
    uint32_t send_message_number_;
    uint32_t recv_message_number_;

    // Last seen remote public key (used to avoid recomputing recv chain repeatedly)
    std::vector<uint8_t> last_remote_pub_;

    // X25519 keypair
    std::vector<uint8_t> dh_private_key_;
    std::vector<uint8_t> dh_public_key_;

    // Skipped message keys (message_number -> message_key)
    std::map<uint32_t, std::vector<uint8_t>> skipped_message_keys_;

    // AEAD wrapper (I am doing AES-less; using ChaCha20-Poly1305 via libsodium)
    AEAD aead_;

    // Helpers (I am doing the following KDF/HKDF helpers)
    std::vector<uint8_t> derive_message_key(const std::vector<uint8_t>& chain_key) const;
    std::vector<uint8_t> advance_chain_key(const std::vector<uint8_t>& chain_key) const;

    void hkdf_root_chain(const std::vector<uint8_t>& dh_shared_secret);

    std::vector<uint8_t> dh_compute(const std::vector<uint8_t>& remote_public) const;

    // Small helpers to serialize uint32 BE
    static void push_u32_be(std::vector<uint8_t>& out, uint32_t v);
    static uint32_t read_u32_be(const std::vector<uint8_t>& in, size_t& offset);
};

} 
