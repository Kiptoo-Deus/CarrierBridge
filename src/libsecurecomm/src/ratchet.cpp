#include "securecomm/ratchet.hpp"
#include "securecomm/envelope.hpp"

#include <sodium.h>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <chrono>

namespace securecomm {

void Ratchet::push_u32_be(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint32_t Ratchet::read_u32_be(const std::vector<uint8_t>& in, size_t& offset) {
    if (offset + 4 > in.size()) throw std::runtime_error("read_u32_be: out of bounds");
    uint32_t v = (static_cast<uint32_t>(in[offset]) << 24) |
                 (static_cast<uint32_t>(in[offset+1]) << 16) |
                 (static_cast<uint32_t>(in[offset+2]) << 8) |
                 (static_cast<uint32_t>(in[offset+3]));
    offset += 4;
    return v;
}

std::vector<uint8_t> Ratchet::derive_message_key(const std::vector<uint8_t>& chain_key) const {
    unsigned char out[crypto_auth_hmacsha256_BYTES];
    const unsigned char label[] = { 'm','s','g' };
    crypto_auth_hmacsha256(out, label, sizeof(label), chain_key.data());
    return std::vector<uint8_t>(out, out + crypto_auth_hmacsha256_BYTES);
}

std::vector<uint8_t> Ratchet::advance_chain_key(const std::vector<uint8_t>& chain_key) const {
    unsigned char out[crypto_auth_hmacsha256_BYTES];
    const unsigned char label[] = { 'c','k' };
    crypto_auth_hmacsha256(out, label, sizeof(label), chain_key.data());
    return std::vector<uint8_t>(out, out + crypto_auth_hmacsha256_BYTES);
}

static void hkdf_extract(uint8_t out_prk[crypto_auth_hmacsha256_BYTES],
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len) {
    uint8_t zero_key[crypto_auth_hmacsha256_KEYBYTES];
    memset(zero_key, 0, sizeof(zero_key));

    const uint8_t *actual_salt = salt;
    size_t actual_salt_len = salt_len;
    if (salt == nullptr || salt_len == 0) {
        actual_salt = zero_key;
        actual_salt_len = sizeof(zero_key);
    }

    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, actual_salt, actual_salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, out_prk);
}

static void hkdf_expand(uint8_t *okm, size_t okm_len,
                        const uint8_t prk[crypto_auth_hmacsha256_BYTES],
                        const uint8_t *info, size_t info_len) {
    uint8_t previous[crypto_auth_hmacsha256_BYTES];
    size_t generated = 0;
    uint8_t counter = 1;
    memset(previous, 0, sizeof(previous));

    while (generated < okm_len) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, crypto_auth_hmacsha256_BYTES);

        if (counter > 1) {
            crypto_auth_hmacsha256_update(&st, previous, sizeof(previous));
        }

        if (info != nullptr && info_len > 0) {
            crypto_auth_hmacsha256_update(&st, info, info_len);
        }

        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, previous);

        size_t to_copy = std::min(okm_len - generated, (size_t)crypto_auth_hmacsha256_BYTES);
        memcpy(okm + generated, previous, to_copy);
        generated += to_copy;
        counter++;
    }

    sodium_memzero(previous, sizeof(previous));
}

void Ratchet::hkdf_root_chain(const std::vector<uint8_t>& dh_shared_secret) {
    uint8_t prk[crypto_auth_hmacsha256_BYTES];
    hkdf_extract(prk,
                 root_key_.empty() ? nullptr : root_key_.data(),
                 root_key_.size(),
                 dh_shared_secret.data(), dh_shared_secret.size());

    const unsigned char info[] = { 'R','a','t','c','h','e','t','C','h','a','i','n' };
    uint8_t okm[32];
    hkdf_expand(okm, sizeof(okm), prk, info, sizeof(info));

    root_key_ = std::vector<uint8_t>(prk, prk + crypto_auth_hmacsha256_BYTES);
    send_chain_key_ = std::vector<uint8_t>(okm, okm + sizeof(okm));

    aead_.set_key(send_chain_key_);

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(okm, sizeof(okm));
}

std::vector<uint8_t> Ratchet::dh_compute(const std::vector<uint8_t>& remote_public) const {
    if (remote_public.size() != crypto_scalarmult_BYTES)
        throw std::runtime_error("dh_compute: invalid public key size");
    std::vector<uint8_t> dh_shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(dh_shared.data(), dh_private_key_.data(), remote_public.data()) != 0)
        throw std::runtime_error("dh_compute failed");
    return dh_shared;
}

Ratchet::Ratchet()
    : send_message_number_(0), recv_message_number_(0) {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");

    dh_private_key_.resize(crypto_scalarmult_BYTES);
    dh_public_key_.resize(crypto_scalarmult_BYTES);
    randombytes_buf(dh_private_key_.data(), dh_private_key_.size());
    crypto_scalarmult_base(dh_public_key_.data(), dh_private_key_.data());
}

Ratchet::~Ratchet() {
    sodium_memzero(dh_private_key_.data(), dh_private_key_.size());
    sodium_memzero(dh_public_key_.data(), dh_public_key_.size());
}

// Initialize
void Ratchet::initialize(const std::vector<uint8_t>& root_key,
                         const std::vector<uint8_t>& session_id) {
    if (root_key.size() != 32) throw std::runtime_error("Root key must be 32 bytes");
    root_key_ = root_key;
    send_chain_key_ = root_key_;
    recv_chain_key_ = root_key_;
    send_message_number_ = 0;
    recv_message_number_ = 0;
    aead_.set_key(send_chain_key_);
    session_id_ = session_id;
    last_remote_pub_.clear();
}

void Ratchet::ratchet_step(const std::vector<uint8_t>& remote_dh_public) {
    if (remote_dh_public.size() != crypto_scalarmult_BYTES) throw std::runtime_error("ratchet_step: invalid size");
    auto dh_shared = dh_compute(remote_dh_public);


    hkdf_root_chain(dh_shared);

    recv_chain_key_ = send_chain_key_;
    aead_.set_key(recv_chain_key_);

    send_message_number_ = 0;
    recv_message_number_ = 0;

    last_remote_pub_ = remote_dh_public;
    sodium_memzero(dh_shared.data(), dh_shared.size());
}

Envelope Ratchet::encrypt_envelope(const std::vector<uint8_t>& plaintext) {
    Envelope env;
    if (session_id_.empty()) {
        session_id_.resize(16);
        randombytes_buf(session_id_.data(), session_id_.size());
    }
    env.session_id = session_id_;
    std::vector<uint8_t> header;
    push_u32_be(header, send_message_number_);
    header.insert(header.end(), dh_public_key_.begin(), dh_public_key_.end());

    auto msg_key = derive_message_key(send_chain_key_);
    aead_.set_key(msg_key);
    auto ct = aead_.encrypt(plaintext, header);

    env.message_index = send_message_number_;
    env.previous_counter = recv_message_number_;
    env.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
    env.sender_device_id = "device-0"; 
    env.associated_data = header;
    env.ciphertext = ct;
    send_chain_key_ = advance_chain_key(send_chain_key_);
    send_message_number_++;
    sodium_memzero(msg_key.data(), msg_key.size());

    return env;
}

std::optional<std::vector<uint8_t>> Ratchet::decrypt_envelope(const Envelope& env) {
    if (!session_id_.empty() && env.session_id != session_id_) {
        return std::nullopt;
    } else if (session_id_.empty()) {
        session_id_ = env.session_id;
    }
    const std::vector<uint8_t> &header = env.associated_data;
    size_t off = 0;
    try {
        uint32_t msg_num = read_u32_be(header, off);
        if (off + crypto_scalarmult_BYTES > header.size()) return std::nullopt;
        std::vector<uint8_t> remote_pub(header.begin() + off, header.begin() + off + crypto_scalarmult_BYTES);
        if (last_remote_pub_.empty() || remote_pub != last_remote_pub_) {
            auto dh_shared = dh_compute(remote_pub);
            hkdf_root_chain(dh_shared);
            recv_chain_key_ = send_chain_key_;
            aead_.set_key(recv_chain_key_);
            recv_message_number_ = 0;
            last_remote_pub_ = remote_pub;
            sodium_memzero(dh_shared.data(), dh_shared.size());
        }
        while (recv_message_number_ < msg_num) {
            auto sk = derive_message_key(recv_chain_key_);
            skipped_message_keys_.emplace(recv_message_number_, sk);
            recv_chain_key_ = advance_chain_key(recv_chain_key_);
            recv_message_number_++;
        }
        auto sit = skipped_message_keys_.find(msg_num);
        if (sit != skipped_message_keys_.end()) {
            aead_.set_key(sit->second);
            auto pt_opt = aead_.decrypt(env.ciphertext, header);
            if (pt_opt.has_value()) {
                skipped_message_keys_.erase(sit);
                return pt_opt;
            } else {
                return std::nullopt;
            }
        }
        auto msg_key = derive_message_key(recv_chain_key_);
        aead_.set_key(msg_key);
        auto pt_opt = aead_.decrypt(env.ciphertext, header);
        if (!pt_opt.has_value()) return std::nullopt;
        recv_chain_key_ = advance_chain_key(recv_chain_key_);
        recv_message_number_ = msg_num + 1;

        sodium_memzero(msg_key.data(), msg_key.size());
        return pt_opt;
    } catch (...) {
        return std::nullopt;
    }
}
std::vector<uint8_t> Ratchet::encrypt(const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& aad) {
    auto env = encrypt_envelope(plaintext);
    std::vector<uint8_t> out;
    out.insert(out.end(), env.associated_data.begin(), env.associated_data.end());
    out.insert(out.end(), env.ciphertext.begin(), env.ciphertext.end());
    return out;
}

std::optional<std::vector<uint8_t>> Ratchet::decrypt(const std::vector<uint8_t>& ciphertext,
                                                     const std::vector<uint8_t>& aad) {
    if (ciphertext.size() < 4 + crypto_scalarmult_BYTES) return std::nullopt;
    std::vector<uint8_t> header(ciphertext.begin(), ciphertext.begin() + 4 + crypto_scalarmult_BYTES);
    std::vector<uint8_t> ct(ciphertext.begin() + 4 + crypto_scalarmult_BYTES, ciphertext.end());
    Envelope env;
    env.session_id = session_id_;
    env.associated_data = header;
    env.ciphertext = ct;
    return decrypt_envelope(env);
}
std::vector<uint8_t> Ratchet::export_state() const {
    std::vector<uint8_t> s;
    s.insert(s.end(), root_key_.begin(), root_key_.end());
    s.insert(s.end(), send_chain_key_.begin(), send_chain_key_.end());
    s.insert(s.end(), recv_chain_key_.begin(), recv_chain_key_.end());
    push_u32_be(s, send_message_number_);
    push_u32_be(s, recv_message_number_);
    s.insert(s.end(), dh_private_key_.begin(), dh_private_key_.end());
    s.insert(s.end(), dh_public_key_.begin(), dh_public_key_.end());
    return s;
}

void Ratchet::import_state(const std::vector<uint8_t>& state) {
    size_t need = 32 + 32 + 32 + 4 + 4 + crypto_scalarmult_BYTES + crypto_scalarmult_BYTES;
    if (state.size() < need) throw std::runtime_error("import_state: too small");
    size_t off = 0;
    root_key_ = std::vector<uint8_t>(state.begin()+off, state.begin()+off+32); off += 32;
    send_chain_key_ = std::vector<uint8_t>(state.begin()+off, state.begin()+off+32); off += 32;
    recv_chain_key_ = std::vector<uint8_t>(state.begin()+off, state.begin()+off+32); off += 32;
    send_message_number_ = read_u32_be(state, off);
    recv_message_number_ = read_u32_be(state, off);
    dh_private_key_ = std::vector<uint8_t>(state.begin()+off, state.begin()+off+crypto_scalarmult_BYTES); off += crypto_scalarmult_BYTES;
    dh_public_key_ = std::vector<uint8_t>(state.begin()+off, state.begin()+off+crypto_scalarmult_BYTES); off += crypto_scalarmult_BYTES;
    aead_.set_key(send_chain_key_);
    last_remote_pub_.clear();
}

} // namespace securecomm
