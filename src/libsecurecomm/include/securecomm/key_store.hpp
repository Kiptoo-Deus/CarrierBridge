#pragma once

#include <string>
#include <vector>

namespace securecomm {

class KeyStore {
public:
KeyStore();
~KeyStore();

// Store a private key in the TEE or HSM; returns an opaque handle
std::string store_private_key(const std::vector<uint8_t>& key_blob);

// Sign data with a stored key handle
std::vector<uint8_t> sign(const std::string& key_handle, const std::vector<uint8_t>& data);

// Retrieve public key bytes
std::vector<uint8_t> get_public_key(const std::string& key_handle);
};

} 