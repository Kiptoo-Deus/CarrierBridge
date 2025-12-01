#include "securecomm/ratchet.hpp"
#include <iostream>
#include <vector>
#include <cassert>

using namespace securecomm;

static std::vector<uint8_t> make_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    std::cout << "Starting end-to-end two-party messaging demo...\n";

    // Step 1: shared root key (fixed for now)
    std::vector<uint8_t> root_key(32, 1);

    // Step 2: create ratchets
    Ratchet alice;
    Ratchet bob;
    alice.initialize(root_key);
    bob.initialize(root_key);

    // Step 3: perform initial DH ratchet step
    alice.ratchet_step(bob.dh_public_key());
    bob.ratchet_step(alice.dh_public_key());

    // Step 4: exchange messages
    std::vector<std::string> conversation = {
        "Hello Bob!", "Hi Alice!", "How are you?", "All good, thanks!"
    };

    for (size_t i = 0; i < conversation.size(); ++i) {
        if (i % 2 == 0) {
            // Alice sends, Bob receives
            auto plaintext = make_bytes(conversation[i]);
            auto ct = alice.encrypt(plaintext);
            auto pt = bob.decrypt(ct);
            assert(pt.has_value() && pt.value() == plaintext);
            std::cout << "Bob received: " << conversation[i] << "\n";
        } else {
            // Bob sends, Alice receives
            auto plaintext = make_bytes(conversation[i]);
            auto ct = bob.encrypt(plaintext);
            auto pt = alice.decrypt(ct);
            assert(pt.has_value() && pt.value() == plaintext);
            std::cout << "Alice received: " << conversation[i] << "\n";
        }
    }

    // Step 5: simulate new DH ratchet step
    alice.ratchet_step(bob.dh_public_key());
    bob.ratchet_step(alice.dh_public_key());

    auto final_msg = make_bytes("After ratchet step message");
    auto ct = alice.encrypt(final_msg);
    auto pt = bob.decrypt(ct);
    assert(pt.has_value() && pt.value() == final_msg);
    std::cout << "Bob received after ratchet step: After ratchet step message\n";

    std::cout << "End-to-end messaging demo: OK\n";
    return 0;
}
