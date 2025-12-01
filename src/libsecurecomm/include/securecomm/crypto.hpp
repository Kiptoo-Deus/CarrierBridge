#pragma once

#include <vector>
#include <cstdint>
#include <optional>
#include <string>

namespace securecomm {


class AEAD {
public:
    AEAD();
    ~AEAD();

    void set_key(const std::vector<uint8_t>& key);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& aad = {}) const;

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& aad = {}) const;

private:
    std::vector<uint8_t> key_;
};

} 
