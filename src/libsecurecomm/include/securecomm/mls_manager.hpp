#pragma once

#include <string>
#include <vector>
#include <optional>

namespace securecomm {

class MLSManager {
public:
MLSManager();

// Create a new group and return group ID
std::string create_group(const std::vector<std::string>& member_device_ids);

// Add/remove devices 
bool add_member(const std::string& group_id, const std::string& device_id);
bool remove_member(const std::string& group_id, const std::string& device_id);

// Encrypt a group message
std::vector<uint8_t> encrypt_group_message(const std::string& group_id, const std::vector<uint8_t>& plaintext);

// Decrypt a received group message
std::optional<std::vector<uint8_t>> decrypt_group_message(const std::string& group_id, const std::vector<uint8_t>& ciphertext);
};

} 