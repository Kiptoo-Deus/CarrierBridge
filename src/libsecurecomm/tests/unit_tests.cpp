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
        env.ciphertext = make_bytes("this is a ciphertext blob");
        env.signature = make_bytes("signature-bytes");
        env.aad = make_bytes("associated-data");

        auto serialized = env.serialize();
        Envelope decoded = Envelope::deserialize(serialized);

        if (decoded.version != env.version ||
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
