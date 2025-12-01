#include "securecomm/envelope.hpp"

#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <iterator>

namespace securecomm {


static void push_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}


static uint32_t read_u32(const std::vector<uint8_t>& in, size_t& offset) {
    if (offset + 4 > in.size()) throw std::runtime_error("read_u32: out of bounds");
    uint32_t v = (static_cast<uint32_t>(in[offset]) << 24) |
                 (static_cast<uint32_t>(in[offset+1]) << 16) |
                 (static_cast<uint32_t>(in[offset+2]) << 8) |
                 (static_cast<uint32_t>(in[offset+3]));
    offset += 4;
    return v;
}

std::vector<uint8_t> Envelope::serialize() const {
    std::vector<uint8_t> out;
    push_u32(out, version);
    push_u32(out, static_cast<uint32_t>(ciphertext.size()));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    push_u32(out, static_cast<uint32_t>(signature.size()));
    out.insert(out.end(), signature.begin(), signature.end());
    push_u32(out, static_cast<uint32_t>(aad.size()));
    out.insert(out.end(), aad.begin(), aad.end());
    return out;
}

Envelope Envelope::deserialize(const std::vector<uint8_t>& input) {
    size_t offset = 0;
    Envelope env{};
    env.version = read_u32(input, offset);

    uint32_t c_len = read_u32(input, offset);
    if (offset + c_len > input.size()) throw std::runtime_error("ciphertext length overflow");
    env.ciphertext.assign(input.begin() + offset, input.begin() + offset + c_len);
    offset += c_len;

    uint32_t s_len = read_u32(input, offset);
    if (offset + s_len > input.size()) throw std::runtime_error("signature length overflow");
    env.signature.assign(input.begin() + offset, input.begin() + offset + s_len);
    offset += s_len;

    uint32_t a_len = read_u32(input, offset);
    if (offset + a_len > input.size()) throw std::runtime_error("aad length overflow");
    env.aad.assign(input.begin() + offset, input.begin() + offset + a_len);
    offset += a_len;

    if (offset != input.size()) {
        throw std::runtime_error("trailing bytes present in envelope deserialize");
    }

    return env;
}

} 
