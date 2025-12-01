#include "securecomm/ratchet.hpp"
#include <stdexcept>

namespace securecomm {

Ratchet::Ratchet()
    : send_message_number_(0), recv_message_number_(0) {}

Ratchet::~Ratchet() {}

void Ratchet::initialize(const std::vector<uint8_t>& root_key) {
    if (root_key.size() != 32) throw std::runtime_error("Root key must be 32 bytes");
    root_key_ = root_key;
    send_chain_key_ = root_key_;
    recv_chain_key_ = root_key_;
    aead_.set_key(send_chain_key_);
    send_message_number_ = 0;
    recv_message_number_ = 0;
}

std::vector<uint8_t> Ratchet::encrypt(const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& aad) {
    
    return aead_.encrypt(plaintext, aad);
}

std::optional<std::vector<uint8_t>> Ratchet::decrypt(const std::vector<uint8_t>& ciphertext,
                                                     const std::vector<uint8_t>& aad) {
    return aead_.decrypt(ciphertext, aad);
}

std::vector<uint8_t> Ratchet::export_state() const {
    std::vector<uint8_t> state;
    state.insert(state.end(), root_key_.begin(), root_key_.end());
    state.insert(state.end(), send_chain_key_.begin(), send_chain_key_.end());
    state.insert(state.end(), recv_chain_key_.begin(), recv_chain_key_.end());

    state.push_back(static_cast<uint8_t>(send_message_number_ >> 24));
    state.push_back(static_cast<uint8_t>(send_message_number_ >> 16));
    state.push_back(static_cast<uint8_t>(send_message_number_ >> 8));
    state.push_back(static_cast<uint8_t>(send_message_number_));

    state.push_back(static_cast<uint8_t>(recv_message_number_ >> 24));
    state.push_back(static_cast<uint8_t>(recv_message_number_ >> 16));
    state.push_back(static_cast<uint8_t>(recv_message_number_ >> 8));
    state.push_back(static_cast<uint8_t>(recv_message_number_));

    return state;
}

void Ratchet::import_state(const std::vector<uint8_t>& state) {
    if (state.size() < 3 * 32 + 8) throw std::runtime_error("Invalid ratchet state size");
    size_t offset = 0;
    root_key_ = std::vector<uint8_t>(state.begin() + offset, state.begin() + offset + 32); offset += 32;
    send_chain_key_ = std::vector<uint8_t>(state.begin() + offset, state.begin() + offset + 32); offset += 32;
    recv_chain_key_ = std::vector<uint8_t>(state.begin() + offset, state.begin() + offset + 32); offset += 32;

    send_message_number_ = (state[offset] << 24) | (state[offset+1] << 16) | (state[offset+2] << 8) | state[offset+3]; offset +=4;
    recv_message_number_ = (state[offset] << 24) | (state[offset+1] << 16) | (state[offset+2] << 8) | state[offset+3]; offset +=4;

    aead_.set_key(send_chain_key_);
}

} 
