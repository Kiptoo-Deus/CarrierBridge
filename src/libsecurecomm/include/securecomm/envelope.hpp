#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>

namespace securecomm {

struct Envelope {
    uint32_t version;
    std::vector<uint8_t> ciphertext; // encrypted payload
    std::vector<uint8_t> signature;  // signature by sender's device key
    std::vector<uint8_t> aad;        

    // Serialize to bytes for transport
    std::vector<uint8_t> serialize() const;
    static Envelope deserialize(const std::vector<uint8_t>&);
};

} 
