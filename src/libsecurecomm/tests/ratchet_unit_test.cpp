#include "securecomm/ratchet.hpp"
#include <iostream>
#include <vector>
#include <cassert>

using namespace securecomm;

static std::vector<uint8_t> make_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    try {
        Ratchet ratchet;
        std::vector<uint8_t> root_key(32, 1);
        ratchet.initialize(root_key);

        std::vector<uint8_t> plaintext = make_bytes("Hello Ratchet!");
        std::vector<uint8_t> aad = make_bytes("header");

        auto ciphertext = ratchet.encrypt(plaintext, aad);
        auto decrypted = ratchet.decrypt(ciphertext, aad);

        if (!decrypted.has_value() || decrypted.value() != plaintext) {
            std::cerr << "Ratchet encrypt/decrypt failed\n";
            return 1;
        }

        auto state = ratchet.export_state();
        Ratchet ratchet2;
        ratchet2.import_state(state);

        auto ciphertext2 = ratchet2.encrypt(plaintext, aad);
        auto decrypted2 = ratchet2.decrypt(ciphertext2, aad);
        if (!decrypted2.has_value() || decrypted2.value() != plaintext) {
            std::cerr << "Ratchet import/export failed\n";
            return 2;
        }

        std::cout << "Ratchet skeleton unit test: OK\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << "\n";
        return 10;
    }
}
