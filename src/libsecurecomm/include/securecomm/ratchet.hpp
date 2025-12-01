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

    // Initialize the ratchet with shared secret / root key
    void initialize(const std::vector<uint8_t>& root_key);

    // Encrypt a plaintext message, return ciphertext
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& aad = {});

    // Decrypt a ciphertext message, return plaintext or nullopt on failure
    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& aad = {});

    // Serialize ratchet state to bytes
    std::vector<uint8_t> export_state() const;

    // Import ratchet state from bytes
    void import_state(const std::vector<uint8_t>& state);

private:
    std::vector<uint8_t> root_key_;
    std::vector<uint8_t> send_chain_key_;
    std::vector<uint8_t> recv_chain_key_;
    uint32_t send_message_number_;
    uint32_t recv_message_number_;

    AEAD aead_;
};

} 
