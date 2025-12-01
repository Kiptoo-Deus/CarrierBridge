#include "securecomm/x3dh.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace securecomm {

// Generate long-term identity keypair (X25519)
void X3DH::generate_identity_keypair(std::vector<uint8_t>& pub, std::vector<uint8_t>& priv) {
    priv.resize(crypto_scalarmult_BYTES);
    pub.resize(crypto_scalarmult_BYTES);
    randombytes_buf(priv.data(), priv.size());
    if (crypto_scalarmult_base(pub.data(), priv.data()) != 0)
        throw std::runtime_error("X3DH: failed to generate public key");
}

// Generate a signed prekey (Bob)
void X3DH::generate_signed_prekey(const std::vector<uint8_t>& ik_priv,
                                  std::vector<uint8_t>& spk_pub,
                                  std::vector<uint8_t>& spk_priv) {
    spk_priv.resize(crypto_scalarmult_BYTES);
    spk_pub.resize(crypto_scalarmult_BYTES);
    randombytes_buf(spk_priv.data(), spk_priv.size());
    if (crypto_scalarmult_base(spk_pub.data(), spk_priv.data()) != 0)
        throw std::runtime_error("X3DH: failed to generate SPK");
}

// Generate a one-time prekey
void X3DH::generate_one_time_prekey(std::vector<uint8_t>& opk_pub,
                                    std::vector<uint8_t>& opk_priv) {
    opk_priv.resize(crypto_scalarmult_BYTES);
    opk_pub.resize(crypto_scalarmult_BYTES);
    randombytes_buf(opk_priv.data(), opk_priv.size());
    if (crypto_scalarmult_base(opk_pub.data(), opk_priv.data()) != 0)
        throw std::runtime_error("X3DH: failed to generate OPK");
}

std::vector<uint8_t> X3DH::compute_shared_secret(
    const std::vector<uint8_t>& ik_priv,
    const std::vector<uint8_t>& spk_priv,
    const std::vector<uint8_t>& remote_ik_pub,
    const std::vector<uint8_t>& remote_spk_pub,
    const std::vector<uint8_t>& remote_opk,
    bool initiator) {

    std::vector<uint8_t> dh1(crypto_scalarmult_BYTES);
    std::vector<uint8_t> dh2(crypto_scalarmult_BYTES);
    std::vector<uint8_t> dh3(crypto_scalarmult_BYTES);
    std::vector<uint8_t> dh4(crypto_scalarmult_BYTES);

    if (initiator) {
        // Alice
        if (crypto_scalarmult(dh1.data(), ik_priv.data(), remote_spk_pub.data()) != 0)
            throw std::runtime_error("DH1 failed");
        if (crypto_scalarmult(dh2.data(), spk_priv.data(), remote_ik_pub.data()) != 0)
            throw std::runtime_error("DH2 failed");
        if (crypto_scalarmult(dh3.data(), spk_priv.data(), remote_spk_pub.data()) != 0)
            throw std::runtime_error("DH3 failed");
        if (!remote_opk.empty())
            if (crypto_scalarmult(dh4.data(), spk_priv.data(), remote_opk.data()) != 0)
                throw std::runtime_error("DH4 failed");
    } else {
        // Bob
        if (crypto_scalarmult(dh1.data(), remote_spk_pub.data(), ik_priv.data()) != 0)
            throw std::runtime_error("DH1 failed (Bob)");
        if (crypto_scalarmult(dh2.data(), remote_ik_pub.data(), spk_priv.data()) != 0)
            throw std::runtime_error("DH2 failed (Bob)");
        if (crypto_scalarmult(dh3.data(), remote_spk_pub.data(), spk_priv.data()) != 0)
            throw std::runtime_error("DH3 failed (Bob)");
        if (!remote_opk.empty())
            if (crypto_scalarmult(dh4.data(), remote_opk.data(), spk_priv.data()) != 0)
                throw std::runtime_error("DH4 failed (Bob)");
    }

    // Concatenate all DH outputs
    std::vector<uint8_t> root;
    root.insert(root.end(), dh1.begin(), dh1.end());
    root.insert(root.end(), dh2.begin(), dh2.end());
    root.insert(root.end(), dh3.begin(), dh3.end());
    if (!dh4.empty()) root.insert(root.end(), dh4.begin(), dh4.end());

    // Derive final 32-byte root key
    unsigned char prk[32];
    crypto_auth_hmacsha256(prk, root.data(), root.size(),
                            reinterpret_cast<const unsigned char*>("X3DHRootKey"));

    return std::vector<uint8_t>(prk, prk + 32);
}

