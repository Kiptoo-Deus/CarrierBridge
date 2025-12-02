#include "securecomm/x3dh.hpp"
#include "securecomm/envelope.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace securecomm {

void X3DH::generate_identity_keypair(std::vector<uint8_t>& pub, std::vector<uint8_t>& priv) {
    priv.resize(crypto_scalarmult_BYTES);
    pub.resize(crypto_scalarmult_BYTES);
    randombytes_buf(priv.data(), priv.size());
    if (crypto_scalarmult_base(pub.data(), priv.data()) != 0)
        throw std::runtime_error("X3DH: failed to generate public key");
}

void X3DH::generate_signed_prekey(const std::vector<uint8_t>& ik_priv,
                                  std::vector<uint8_t>& spk_pub,
                                  std::vector<uint8_t>& spk_priv) {
    spk_priv.resize(crypto_scalarmult_BYTES);
    spk_pub.resize(crypto_scalarmult_BYTES);
    randombytes_buf(spk_priv.data(), spk_priv.size());
    if (crypto_scalarmult_base(spk_pub.data(), spk_priv.data()) != 0)
        throw std::runtime_error("X3DH: failed to generate SPK");
}

void X3DH::generate_one_time_prekey(std::vector<uint8_t>& opk_pub,
                                    std::vector<uint8_t>& opk_priv) {
    opk_priv.resize(crypto_scalarmult_BYTES);
    opk_pub.resize(crypto_scalarmult_BYTES);
    randombytes_buf(opk_priv.data(), opk_priv.size());
    if (crypto_scalarmult_base(opk_pub.data(), opk_priv.data()) != 0)
        throw std::runtime_error("X3DH: failed to generate OPK");
}
static std::vector<uint8_t> x3dh_compute_root_initiator(
    const std::vector<uint8_t>& alice_ik_priv,
    const std::vector<uint8_t>& alice_eph_priv,
    const std::vector<uint8_t>& bob_ik_pub,
    const std::vector<uint8_t>& bob_spk_pub,
    const std::vector<uint8_t>& bob_opk_pub) {

    std::vector<uint8_t> dh1(crypto_scalarmult_BYTES), dh2(crypto_scalarmult_BYTES), dh3(crypto_scalarmult_BYTES), dh4(crypto_scalarmult_BYTES);

    if (crypto_scalarmult(dh1.data(), alice_ik_priv.data(), bob_spk_pub.data()) != 0) throw std::runtime_error("DH1 failed");
    if (crypto_scalarmult(dh2.data(), alice_eph_priv.data(), bob_ik_pub.data()) != 0) throw std::runtime_error("DH2 failed");
    if (crypto_scalarmult(dh3.data(), alice_eph_priv.data(), bob_spk_pub.data()) != 0) throw std::runtime_error("DH3 failed");
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), dh1.begin(), dh1.end());
    combined.insert(combined.end(), dh2.begin(), dh2.end());
    combined.insert(combined.end(), dh3.begin(), dh3.end());

    if (!bob_opk_pub.empty()) {
        if (crypto_scalarmult(dh4.data(), alice_eph_priv.data(), bob_opk_pub.data()) != 0) throw std::runtime_error("DH4 failed");
        combined.insert(combined.end(), dh4.begin(), dh4.end());
    }
    unsigned char prk[32];
    crypto_auth_hmacsha256(prk, combined.data(), combined.size(), reinterpret_cast<const unsigned char*>("X3DHRootKey"));
    return std::vector<uint8_t>(prk, prk + 32);
}

static std::vector<uint8_t> x3dh_compute_root_responder(
    const std::vector<uint8_t>& bob_ik_priv,
    const std::vector<uint8_t>& bob_spk_priv,
    const std::vector<uint8_t>& alice_ik_pub,
    const std::vector<uint8_t>& alice_eph_pub,
    const std::vector<uint8_t>& bob_opk_priv) {

    std::vector<uint8_t> dh1(crypto_scalarmult_BYTES), dh2(crypto_scalarmult_BYTES), dh3(crypto_scalarmult_BYTES), dh4(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(dh1.data(), bob_spk_priv.data(), alice_ik_pub.data()) != 0) throw std::runtime_error("DH1 failed");
    if (crypto_scalarmult(dh2.data(), bob_ik_priv.data(), alice_eph_pub.data()) != 0) throw std::runtime_error("DH2 failed");
    if (crypto_scalarmult(dh3.data(), bob_spk_priv.data(), alice_eph_pub.data()) != 0) throw std::runtime_error("DH3 failed");

    std::vector<uint8_t> combined;
    combined.insert(combined.end(), dh1.begin(), dh1.end());
    combined.insert(combined.end(), dh2.begin(), dh2.end());
    combined.insert(combined.end(), dh3.begin(), dh3.end());

    if (!bob_opk_priv.empty()) {
        if (crypto_scalarmult(dh4.data(), bob_opk_priv.data(), alice_eph_pub.data()) != 0) throw std::runtime_error("DH4 failed");
        combined.insert(combined.end(), dh4.begin(), dh4.end());
    }

    unsigned char prk[32];
    crypto_auth_hmacsha256(prk, combined.data(), combined.size(), reinterpret_cast<const unsigned char*>("X3DHRootKey"));
    return std::vector<uint8_t>(prk, prk + 32);
}

Envelope X3DH::initiate_handshake(const std::vector<uint8_t>& initiator_ik_priv,
                                  const std::vector<uint8_t>& initiator_eph_priv,
                                  const std::vector<uint8_t>& responder_ik_pub,
                                  const std::vector<uint8_t>& responder_spk_pub,
                                  const std::vector<uint8_t>& responder_opk_pub) {
    Envelope env;
    auto root = x3dh_compute_root_initiator(initiator_ik_priv, initiator_eph_priv,
                                            responder_ik_pub, responder_spk_pub, responder_opk_pub);
    env.session_id.resize(16);
    randombytes_buf(env.session_id.data(), env.session_id.size());
    env.message_index = 0;
    env.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
    env.ciphertext = root;
    env.sender_device_id = "initiator";
    return env;
}

Envelope X3DH::respond_handshake(const std::vector<uint8_t>& responder_ik_priv,
                                 const std::vector<uint8_t>& responder_spk_priv,
                                 const std::vector<uint8_t>& initiator_ik_pub,
                                 const std::vector<uint8_t>& initiator_eph_pub,
                                 const std::vector<uint8_t>& responder_opk_priv) {
    Envelope env;
    auto root = x3dh_compute_root_responder(responder_ik_priv, responder_spk_priv,
                                            initiator_ik_pub, initiator_eph_pub, responder_opk_priv);

    env.session_id.resize(16);
    randombytes_buf(env.session_id.data(), env.session_id.size());
    env.message_index = 0;
    env.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
    env.ciphertext = root;
    env.sender_device_id = "responder";
    return env;
}

} // namespace securecomm
