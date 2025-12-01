#include "securecomm/crypto.hpp"
#include <iostream>
#include <vector>
#include <cassert>

using namespace securecomm;

static std::vector<uint8_t> make_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    try {
        AEAD aead;
        std::vector<uint8_t> key(32, 42); 
        aead.set_key(key);

        std::vector<uint8_t> plaintext = make_bytes("Secret message");
        std::vector<uint8_t> aad = make_bytes("AssociatedData");

        auto ciphertext = aead.encrypt(plaintext, aad);
        auto decrypted = aead.decrypt(ciphertext, aad);

        if (!decrypted.has_value() || decrypted.value() != plaintext) {
            std::cerr << "AEAD encrypt/decrypt failed\n";
            return 1;
        }

        std::cout << "AEAD encrypt/decrypt test: OK\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << "\n";
        return 2;
    }
}
