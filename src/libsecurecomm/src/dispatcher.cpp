#include "securecomm/dispatcher.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>
#include <chrono>
#include <iostream>

namespace securecomm {

Dispatcher::Dispatcher(TransportPtr transport)
    : transport_(transport) {
    std::cout << "[Dispatcher] Constructor for transport: " << transport.get() << std::endl;
    if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
    transport_->set_on_message([this](const std::vector<uint8_t>& b){ on_raw_message(b); });
}

Dispatcher::~Dispatcher() {
    std::cout << "[Dispatcher] Destructor" << std::endl;
    stop();
}

void Dispatcher::start() {
    std::cout << "[Dispatcher] start()" << std::endl;
    transport_->start();
}

void Dispatcher::stop() {
    std::cout << "[Dispatcher] stop()" << std::endl;
    transport_->stop();
}

void Dispatcher::register_device(const std::string& device_id) {
    std::cout << "[Dispatcher] register_device: " << device_id << std::endl;
    std::lock_guard<std::mutex> lk(mutex_);
    device_id_ = device_id;
}

void Dispatcher::create_session_with(const std::string& remote_device_id, const std::vector<uint8_t>& root_key) {
    std::cout << "[Dispatcher] create_session_with: " << remote_device_id 
              << ", root_key size: " << root_key.size() << std::endl;
    std::lock_guard<std::mutex> lk(mutex_);
    SessionState& s = sessions_[remote_device_id];
    
    // Compute a deterministic session_id from device IDs and root key
    // This ensures both parties have the same session_id
    std::vector<uint8_t> session_id_input;
    if (device_id_ < remote_device_id) {
        session_id_input.insert(session_id_input.end(), device_id_.begin(), device_id_.end());
        session_id_input.insert(session_id_input.end(), remote_device_id.begin(), remote_device_id.end());
    } else {
        session_id_input.insert(session_id_input.end(), remote_device_id.begin(), remote_device_id.end());
        session_id_input.insert(session_id_input.end(), device_id_.begin(), device_id_.end());
    }
    session_id_input.insert(session_id_input.end(), root_key.begin(), root_key.end());
    
    // Hash to get deterministic 16-byte session ID
    unsigned char session_id_bytes[16];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, root_key.data(), root_key.size());
    crypto_auth_hmacsha256_update(&st, session_id_input.data(), session_id_input.size());
    unsigned char hash_output[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_final(&st, hash_output);
    memcpy(session_id_bytes, hash_output, 16);
    std::vector<uint8_t> session_id(session_id_bytes, session_id_bytes + 16);
    
    s.ratchet.initialize(root_key, session_id);
    // Don't do ratchet_step here - it will happen on first message exchange
    // The ratchet_step should use the remote party's public key, which we get from the first message header
    s.initialized = true;
    std::cout << "[Dispatcher] Session created for: " << remote_device_id << std::endl;
}

void Dispatcher::send_message_to_device(const std::string& remote_device_id, const std::vector<uint8_t>& plaintext) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = sessions_.find(remote_device_id);
    if (it == sessions_.end() || !it->second.initialized) {
        std::cout << "[Dispatcher] ERROR: Session with " << remote_device_id << " not initialized" << std::endl;
        throw std::runtime_error("session not initialized");
    }
    
    std::cout << "[Dispatcher] Sending message to " << remote_device_id 
              << ", plaintext size: " << plaintext.size() << std::endl;
    
    Envelope env = it->second.ratchet.encrypt_envelope(plaintext);
    env.sender_device_id = device_id_;
    
    std::cout << "[Dispatcher] Encrypted envelope. Session ID size: " << env.session_id.size()
              << ", Ciphertext size: " << env.ciphertext.size() << std::endl;
    
    auto bytes = serialize_envelope(env);
    std::cout << "[Dispatcher] Serialized envelope size: " << bytes.size() << std::endl;
    
    transport_->send(bytes);
    std::cout << "[Dispatcher] Message sent to transport" << std::endl;
}

void Dispatcher::send_group_message(const std::vector<uint8_t>& group_id, const std::string& sender_id, const std::vector<uint8_t>& plaintext) {
    std::cout << "[Dispatcher] send_group_message to group_id size: " << group_id.size() 
              << ", sender: " << sender_id << std::endl;
    Envelope env = mls_.encrypt_group_message(group_id, sender_id, plaintext);
    env.sender_device_id = device_id_;
    auto bytes = serialize_envelope(env);
    transport_->send(bytes);
}

void Dispatcher::set_on_inbound(OnInboundMessage cb) {
    std::cout << "[Dispatcher] set_on_inbound callback" << std::endl;
    std::lock_guard<std::mutex> lk(mutex_);
    on_inbound_ = cb;
}

void Dispatcher::on_raw_message(const std::vector<uint8_t>& bytes) {
    std::cout << "[Dispatcher] on_raw_message received, bytes size: " << bytes.size() << std::endl;
    
    auto env_opt = deserialize_envelope(bytes);
    if (!env_opt.has_value()) {
        std::cout << "[Dispatcher] Failed to deserialize envelope" << std::endl;
        return;
    }
    
    Envelope env = env_opt.value();
    std::cout << "[Dispatcher] Envelope deserialized. Sender: " << env.sender_device_id 
              << ", My device ID: " << device_id_ 
              << ", Session ID size: " << env.session_id.size() << std::endl;

    // Determine if group or direct
    if (!env.session_id.empty() && mls_.get_group_epoch(env.session_id) != 0) {
        std::cout << "[Dispatcher] Group message detected" << std::endl;
        // group
        auto pt = mls_.decrypt_group_message(env.session_id, device_id_, env);
        if (pt.has_value()) {
            std::cout << "[Dispatcher] Group message decrypted successfully" << std::endl;
            if (on_inbound_) on_inbound_(env);
        } else {
            std::cout << "[Dispatcher] Failed to decrypt group message" << std::endl;
        }
        return;
    }

    // direct: find session by sender device id
    std::string sender = env.sender_device_id;
    std::cout << "[Dispatcher] Direct message from: " << sender << std::endl;
    
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = sessions_.find(sender);
    if (it == sessions_.end()) {
        std::cout << "[Dispatcher] No session found for sender: " << sender << std::endl;
        return;
    }
    
    std::cout << "[Dispatcher] Found session, attempting decryption..." << std::endl;
    auto pt = it->second.ratchet.decrypt_envelope(env);
    if (pt.has_value()) {
        std::cout << "[Dispatcher] Message decrypted successfully! Plaintext size: " << pt.value().size() << std::endl;
        if (on_inbound_) {
            // Create a new envelope with the decrypted plaintext for the callback
            Envelope decrypted_env = env;
            decrypted_env.ciphertext = pt.value(); // Replace ciphertext with plaintext for demo
            on_inbound_(decrypted_env);
        }
    } else {
        std::cout << "[Dispatcher] Failed to decrypt message" << std::endl;
    }
}

std::vector<uint8_t> Dispatcher::serialize_envelope(const Envelope& env) {
    std::vector<uint8_t> out;
    // session id length + session id
    uint32_t sid_len = static_cast<uint32_t>(env.session_id.size());
    out.push_back((sid_len >> 24) & 0xFF);
    out.push_back((sid_len >> 16) & 0xFF);
    out.push_back((sid_len >> 8) & 0xFF);
    out.push_back((sid_len) & 0xFF);
    out.insert(out.end(), env.session_id.begin(), env.session_id.end());

    // message_index, previous_counter, timestamp
    uint32_t mi = env.message_index;
    out.push_back((mi >> 24) & 0xFF);
    out.push_back((mi >> 16) & 0xFF);
    out.push_back((mi >> 8) & 0xFF);
    out.push_back((mi) & 0xFF);

    uint32_t pc = env.previous_counter;
    out.push_back((pc >> 24) & 0xFF);
    out.push_back((pc >> 16) & 0xFF);
    out.push_back((pc >> 8) & 0xFF);
    out.push_back((pc) & 0xFF);

    uint64_t ts = env.timestamp;
    for (int i = 7; i >= 0; --i) out.push_back((ts >> (8*i)) & 0xFF);

    // sender_device_id length + bytes
    uint32_t idlen = static_cast<uint32_t>(env.sender_device_id.size());
    out.push_back((idlen >> 24) & 0xFF);
    out.push_back((idlen >> 16) & 0xFF);
    out.push_back((idlen >> 8) & 0xFF);
    out.push_back((idlen) & 0xFF);
    out.insert(out.end(), env.sender_device_id.begin(), env.sender_device_id.end());

    // aad len + aad, ct len + ct
    uint32_t aadlen = static_cast<uint32_t>(env.associated_data.size());
    out.push_back((aadlen >> 24) & 0xFF);
    out.push_back((aadlen >> 16) & 0xFF);
    out.push_back((aadlen >> 8) & 0xFF);
    out.push_back((aadlen) & 0xFF);
    out.insert(out.end(), env.associated_data.begin(), env.associated_data.end());

    uint32_t ctlen = static_cast<uint32_t>(env.ciphertext.size());
    out.push_back((ctlen >> 24) & 0xFF);
    out.push_back((ctlen >> 16) & 0xFF);
    out.push_back((ctlen >> 8) & 0xFF);
    out.push_back((ctlen) & 0xFF);
    out.insert(out.end(), env.ciphertext.begin(), env.ciphertext.end());

    return out;
}

std::optional<Envelope> Dispatcher::deserialize_envelope(const std::vector<uint8_t>& bytes) {
    size_t off = 0;
    if (bytes.size() < 4) return std::nullopt;
    auto read_u32 = [&](uint32_t& out)->bool {
        if (off + 4 > bytes.size()) return false;
        out = (uint32_t(bytes[off])<<24) | (uint32_t(bytes[off+1])<<16) | (uint32_t(bytes[off+2])<<8) | uint32_t(bytes[off+3]);
        off +=4;
        return true;
    };
    Envelope env;
    uint32_t sid_len;
    if (!read_u32(sid_len)) return std::nullopt;
    if (off + sid_len > bytes.size()) return std::nullopt;
    env.session_id = std::vector<uint8_t>(bytes.begin()+off, bytes.begin()+off+sid_len);
    off += sid_len;

    uint32_t mi; if (!read_u32(mi)) return std::nullopt; env.message_index = mi;
    uint32_t pc; if (!read_u32(pc)) return std::nullopt; env.previous_counter = pc;
    if (off + 8 > bytes.size()) return std::nullopt;
    uint64_t ts = 0;
    for (int i=0;i<8;i++) { ts = (ts<<8) | bytes[off++]; }
    env.timestamp = ts;

    uint32_t idlen; if (!read_u32(idlen)) return std::nullopt;
    if (off + idlen > bytes.size()) return std::nullopt;
    env.sender_device_id = std::string(bytes.begin()+off, bytes.begin()+off+idlen);
    off += idlen;

    uint32_t aadlen; if (!read_u32(aadlen)) return std::nullopt;
    if (off + aadlen > bytes.size()) return std::nullopt;
    env.associated_data = std::vector<uint8_t>(bytes.begin()+off, bytes.begin()+off+aadlen);
    off += aadlen;

    uint32_t ctlen; if (!read_u32(ctlen)) return std::nullopt;
    if (off + ctlen > bytes.size()) return std::nullopt;
    env.ciphertext = std::vector<uint8_t>(bytes.begin()+off, bytes.begin()+off+ctlen);
    off += ctlen;

    return env;
}

} // namespace securecomm