#include "securecomm/x3dh.hpp"
#include "securecomm/envelope.hpp"
#include <sodium.h>
#include <iostream>
#include <cassert>

using namespace securecomm;

int main() {
    if (sodium_init() < 0) return 1;

    std::vector<uint8_t> alice_ik_pub, alice_ik_priv;
    std::vector<uint8_t> bob_ik_pub, bob_ik_priv;
    X3DH::generate_identity_keypair(alice_ik_pub, alice_ik_priv);
    X3DH::generate_identity_keypair(bob_ik_pub, bob_ik_priv);

    std::vector<uint8_t> bob_spk_pub, bob_spk_priv;
    X3DH::generate_signed_prekey(bob_ik_priv, bob_spk_pub, bob_spk_priv);

    std::vector<uint8_t> bob_opk_pub, bob_opk_priv;
    X3DH::generate_one_time_prekey(bob_opk_pub, bob_opk_priv);

    std::vector<uint8_t> alice_eph_pub, alice_eph_priv;
    X3DH::generate_one_time_prekey(alice_eph_pub, alice_eph_priv);

    Envelope e_init = X3DH::initiate_handshake(alice_ik_priv, alice_eph_priv,
                                               bob_ik_pub, bob_spk_pub, bob_opk_pub);

    Envelope e_resp = X3DH::respond_handshake(bob_ik_priv, bob_spk_priv,
                                              alice_ik_pub, alice_eph_pub, bob_opk_priv);

    assert(e_init.ciphertext.size() == 32);
    assert(e_resp.ciphertext.size() == 32);

    std::cout << "X3DH (envelope) unit test: OK\n";
    return 0;
}
