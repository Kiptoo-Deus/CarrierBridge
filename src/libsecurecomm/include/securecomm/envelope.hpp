#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace securecomm {

struct Envelope {
    std::vector<uint8_t> session_id;
    uint32_t message_index = 0;
    uint32_t previous_counter = 0;
    uint64_t timestamp = 0;
    std::string sender_device_id;
    std::vector<uint8_t> associated_data;
    std::vector<uint8_t> ciphertext;
};

} // namespace securecomm
