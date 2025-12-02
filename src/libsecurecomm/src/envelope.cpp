#include "securecomm/envelope.hpp"
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace securecomm {

void Envelope::push_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back((v >> 24) & 0xFF);
    out.push_back((v >> 16) & 0xFF);
    out.push_back((v >> 8) & 0xFF);
    out.push_back(v & 0xFF);
}

uint32_t Envelope::read_u32(const std::vector<uint8_t>& in, size_t& offset) {
    if (offset + 4 > in.size())
        throw std::runtime_error("Envelope: invalid length");
    uint32_t v =
        (static_cast<uint32_t>(in[offset]) << 24) |
        (static_cast<uint32_t>(in[offset+1]) << 16) |
        (static_cast<uint32_t>(in[offset+2]) << 8) |
        static_cast<uint32_t>(in[offset+3]);
    offset += 4;
    return v;
}

std::vector<uint8_t> Envelope::serialize() const {
    std::vector<uint8_t> out;

    // Version 1: New format with all fields
    push_u32(out, version);

    // Session ID
    push_u32(out, static_cast<uint32_t>(session_id.size()));
    out.insert(out.end(), session_id.begin(), session_id.end());

    // Message indices
    push_u32(out, message_index);
    push_u32(out, previous_counter);
    
    // Timestamp
    for (int i = 7; i >= 0; --i) {
        out.push_back((timestamp >> (8 * i)) & 0xFF);
    }

    // Sender device ID
    push_u32(out, static_cast<uint32_t>(sender_device_id.size()));
    out.insert(out.end(), sender_device_id.begin(), sender_device_id.end());

    // Associated data (for ratchet)
    push_u32(out, static_cast<uint32_t>(associated_data.size()));
    out.insert(out.end(), associated_data.begin(), associated_data.end());

    // Ciphertext
    push_u32(out, static_cast<uint32_t>(ciphertext.size()));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    // Signature (for backward compatibility)
    push_u32(out, static_cast<uint32_t>(signature.size()));
    out.insert(out.end(), signature.begin(), signature.end());

    // AAD (for backward compatibility - different from associated_data)
    push_u32(out, static_cast<uint32_t>(aad.size()));
    out.insert(out.end(), aad.begin(), aad.end());

    return out;
}

Envelope Envelope::deserialize(const std::vector<uint8_t>& input) {
    Envelope env;
    size_t offset = 0;

    env.version = read_u32(input, offset);

    // Session ID
    uint32_t sid_len = read_u32(input, offset);
    env.session_id.assign(input.begin() + offset, input.begin() + offset + sid_len);
    offset += sid_len;

    // Message indices
    env.message_index = read_u32(input, offset);
    env.previous_counter = read_u32(input, offset);

    // Timestamp
    env.timestamp = 0;
    for (int i = 0; i < 8; ++i) {
        env.timestamp = (env.timestamp << 8) | input[offset++];
    }

    // Sender device ID
    uint32_t sender_len = read_u32(input, offset);
    env.sender_device_id.assign(
        reinterpret_cast<const char*>(input.data() + offset), 
        sender_len
    );
    offset += sender_len;

    // Associated data
    uint32_t ad_len = read_u32(input, offset);
    env.associated_data.assign(input.begin() + offset, input.begin() + offset + ad_len);
    offset += ad_len;

    // Ciphertext
    uint32_t ct_len = read_u32(input, offset);
    env.ciphertext.assign(input.begin() + offset, input.begin() + offset + ct_len);
    offset += ct_len;

    // Signature
    uint32_t sig_len = read_u32(input, offset);
    env.signature.assign(input.begin() + offset, input.begin() + offset + sig_len);
    offset += sig_len;

    // AAD
    uint32_t aad_len = read_u32(input, offset);
    env.aad.assign(input.begin() + offset, input.begin() + offset + aad_len);
    offset += aad_len;

    return env;
}

void Envelope::migrate_from_old_format() {
    // If coming from old format where aad was used instead of associated_data
    if (associated_data.empty() && !aad.empty()) {
        associated_data = aad;
    }
}

void Envelope::migrate_to_old_format() const {
    // If needed to convert back to old format
    // This would create a new envelope with old structure
}

} // namespace securecomm