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
        std::cout << "Starting two-party Ratchet test...\n";

        // Initialize Alice and Bob with the same root key ---
        std::vector<uint8_t> root_key(32, 1); // simple 32-byte root key
        Ratchet alice;
        Ratchet bob;
        alice.initialize(root_key);
        bob.initialize(root_key);

        // Perform initial ratchet step using each other's DH public keys ---
        alice.ratchet_step(bob.dh_public_key());
        bob.ratchet_step(alice.dh_public_key());

        // Exchange messages ---
        std::vector<std::string> messages = {
            "Hello Bob!", "Hi Alice!", "How are you?", "All good, thanks!"
        };

        for (size_t i = 0; i < messages.size(); ++i) {
            if (i % 2 == 0) {
                // Alice sends, Bob receives
                auto plaintext = make_bytes(messages[i]);
                auto ct = alice.encrypt(plaintext);
                auto pt = bob.decrypt(ct);
                assert(pt.has_value() && pt.value() == plaintext);
            } else {
                // Bob sends, Alice receives
                auto plaintext = make_bytes(messages[i]);
                auto ct = bob.encrypt(plaintext);
                auto pt = alice.decrypt(ct);
                assert(pt.has_value() && pt.value() == plaintext);
            }
        }

        // Test forward secrecy simulation ---
        // Simulate a new DH ratchet step
        alice.ratchet_step(bob.dh_public_key());
        bob.ratchet_step(alice.dh_public_key());

        // Send another message after ratchet step
        auto new_msg = make_bytes("After ratchet step");
        auto ct = alice.encrypt(new_msg);
        auto pt = bob.decrypt(ct);
        assert(pt.has_value() && pt.value() == new_msg);

        std::cout << "Two-party Ratchet test: OK\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << "\n";
        return 1;
    }
}
