#pragma once

#include "envelope.hpp"
#include <vector>
#include <cstdint>

namespace securecomm {

class X3DH {
public:
    static void generate_identity_keypair(std::vector<uint8_t>& pub, std::vector<uint8_t>& priv);
    static void generate_signed_prekey(const std::vector<uint8_t>& ik_priv, std::vector<uint8_t>& spk_pub, std::vector<uint8_t>& spk_priv);
    static void generate_one_time_prekey(std::vector<uint8_t>& opk_pub, std::vector<uint8_t>& opk_priv);

    static Envelope initiate_handshake(const std::vector<uint8_t>& initiator_ik_priv,
                                       const std::vector<uint8_t>& initiator_eph_priv,
                                       const std::vector<uint8_t>& responder_ik_pub,
                                       const std::vector<uint8_t>& responder_spk_pub,
                                       const std::vector<uint8_t>& responder_opk_pub);
    static Envelope respond_handshake(const std::vector<uint8_t>& responder_ik_priv,
                                      const std::vector<uint8_t>& responder_spk_priv,
                                      const std::vector<uint8_t>& initiator_ik_pub,
                                      const std::vector<uint8_t>& initiator_eph_pub,
                                      const std::vector<uint8_t>& responder_opk_priv);
};

} // namespace securecomm
