#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>

namespace securecomm {

class Envelope {
public:
    // Data fields (POD-like for easy access)
    std::vector<uint8_t> session_id;        // group or 1:1 session identifier
    uint32_t message_index = 0;             // ratchet send counter
    uint32_t previous_counter = 0;          // ratchet recv counter
    uint64_t timestamp = 0;                 // ms since epoch
    std::string sender_device_id;           // device identifier
    std::vector<uint8_t> associated_data;   // AAD for AEAD (header)
    std::vector<uint8_t> ciphertext;        // encrypted payload
    
    // For backward compatibility with existing tests
    uint32_t version = 1;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> aad;  // This is different from associated_data above
    
    // Serialization methods
    std::vector<uint8_t> serialize() const;
    static Envelope deserialize(const std::vector<uint8_t>& input);
    
    // Helper methods for serialization
    static void push_u32(std::vector<uint8_t>& out, uint32_t v);
    static uint32_t read_u32(const std::vector<uint8_t>& in, size_t& offset);
    
    // Convert between old and new formats if needed
    void migrate_from_old_format();
    void migrate_to_old_format() const;
};

} // namespace securecomm