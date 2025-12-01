#include "securecomm/x3dh.hpp"
#include <sodium.h>
#include <iostream>
#include <cassert>

using namespace securecomm;

int main() {
    if (sodium_init() < 0) return 1;

    // Generate Alice's long-term identity key
    std::vector<uint8_t> alice_ik_pub, alice_ik_priv;
    X3DH::generate_identity_keypair(alice_ik_pub, alice_ik_priv);

    // Generate Bob's long-term identity key
    std::vector<uint8_t> bob_ik_pub, bob_ik_priv;
    X3DH::generate_identity_keypair(bob_ik_pub, bob_ik_priv);

    // Bob's signed pre-key
    std::vector<uint8_t> bob_spk_pub, bob_spk_priv;
    X3DH::generate_signed_prekey(bob_ik_priv, bob_spk_pub, bob_spk_priv);

    // Bob's one-time pre-key
    std::vector<uint8_t> bob_opk_pub, bob_opk_priv;
    X3DH::generate_one_time_prekey(bob_opk_pub, bob_opk_priv);

    // Alice ephemeral key
    std::vector<uint8_t> alice_eph_pub, alice_eph_priv;
    X3DH::generate_one_time_prekey(alice_eph_pub, alice_eph_priv);

    // Alice computes shared root (initiator)
    auto alice_root = X3DH::compute_shared_secret(
        alice_ik_priv,
        alice_eph_priv,
        bob_ik_pub,
        bob_spk_pub,
        bob_opk_pub,
        true
    );

    // Bob computes shared root (responder)
    auto bob_root = X3DH::compute_shared_secret(
        bob_ik_priv,
        bob_spk_priv,
        alice_ik_pub,
        alice_eph_pub,
        bob_opk_priv,
        false
    );

    assert(alice_root.size() == 32);
    assert(alice_root == bob_root);

    std::cout << "X3DH unit test: OK\n";
    return 0;
}
