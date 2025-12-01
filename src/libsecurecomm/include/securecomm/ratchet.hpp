#pragma once

#include "crypto.hpp"
#include <vector>
#include <cstdint>
#include <optional>

namespace securecomm {


class Ratchet {
public:
    Ratchet();
    ~Ratchet();

    // Initialize the ratchet with a 32-byte root key
    void initialize(const std::vector<uint8_t>& root_key);

    // Perform a DH ratchet step using the remote's public key
    void ratchet_step(const std::vector<uint8_t>& remote_dh_public);

    // Encrypt a plaintext message
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& aad = {});

 
    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& aad = {});

    std::vector<uint8_t> export_state() const;
    void import_state(const std::vector<uint8_t>& state);

    const std::vector<uint8_t>& dh_public_key() const { return dh_public_key_; }

private:
    std::vector<uint8_t> root_key_;         // 32 bytes
    std::vector<uint8_t> send_chain_key_;   // 32 bytes
    std::vector<uint8_t> recv_chain_key_;   // 32 bytes
    uint32_t send_message_number_;
    uint32_t recv_message_number_;

    std::vector<uint8_t> dh_private_key_;   // X25519 private key
    std::vector<uint8_t> dh_public_key_;    // X25519 public key

    AEAD aead_;

    // Helpers
    std::vector<uint8_t> derive_message_key(const std::vector<uint8_t>& chain_key) const;
    void hkdf_root_chain(const std::vector<uint8_t>& dh_shared_secret);
};

} // namespace securecomm
