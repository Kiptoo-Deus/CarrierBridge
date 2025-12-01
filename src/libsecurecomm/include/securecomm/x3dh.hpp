#pragma once

#include <vector>
#include <cstdint>

namespace securecomm {

class X3DH {
public:
    static void generate_identity_keypair(std::vector<uint8_t>& pub, std::vector<uint8_t>& priv);

    static void generate_signed_prekey(const std::vector<uint8_t>& ik_priv,
                                       std::vector<uint8_t>& spk_pub,
                                       std::vector<uint8_t>& spk_priv);

    static void generate_one_time_prekey(std::vector<uint8_t>& opk_pub,
                                        std::vector<uint8_t>& opk_priv);


    static std::vector<uint8_t> compute_shared_secret(
        const std::vector<uint8_t>& ik_priv,
        const std::vector<uint8_t>& eph_priv,
        const std::vector<uint8_t>& remote_ik_pub,
        const std::vector<uint8_t>& remote_spk_pub,
        const std::vector<uint8_t>& remote_opk_pub,
        bool initiator);
};

} // namespace securecomm
