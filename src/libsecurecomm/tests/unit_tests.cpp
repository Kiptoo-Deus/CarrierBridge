#include "securecomm/envelope.hpp"
#include <iostream>
#include <vector>
#include <cassert>
#include <cstdint>

using namespace securecomm;

static std::vector<uint8_t> make_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    try {
        Envelope env;
        env.version = 1;
        env.session_id = make_bytes("session123");
        env.message_index = 100;
        env.previous_counter = 99;
        env.timestamp = 1234567890;
        env.sender_device_id = "device1";
        env.associated_data = make_bytes("associated-data-for-ratchet");
        env.ciphertext = make_bytes("this is a ciphertext blob");
        env.signature = make_bytes("signature-bytes");
        env.aad = make_bytes("aad-for-backward-compat");

        auto serialized = env.serialize();
        Envelope decoded = Envelope::deserialize(serialized);

        if (decoded.version != env.version ||
            decoded.session_id != env.session_id ||
            decoded.message_index != env.message_index ||
            decoded.previous_counter != env.previous_counter ||
            decoded.timestamp != env.timestamp ||
            decoded.sender_device_id != env.sender_device_id ||
            decoded.associated_data != env.associated_data ||
            decoded.ciphertext != env.ciphertext ||
            decoded.signature != env.signature ||
            decoded.aad != env.aad) {
            std::cerr << "ERROR: Envelope round-trip failed\n";
            return 1;
        }

        std::cout << "Envelope serialize/deserialize test: OK\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << "\n";
        return 2;
    }
}