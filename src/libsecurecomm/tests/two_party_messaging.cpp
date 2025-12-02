#include "securecomm/ratchet.hpp"
#include "securecomm/envelope.hpp"
#include <iostream>
#include <vector>
#include <cassert>

using namespace securecomm;

static std::vector<uint8_t> make_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    std::cout << "Starting end-to-end two-party messaging demo (envelope)...\n";

    std::vector<uint8_t> root_key(32, 1);

    Ratchet alice;
    Ratchet bob;
    alice.initialize(root_key);
    bob.initialize(root_key);

    alice.ratchet_step(bob.dh_public_key());
    bob.ratchet_step(alice.dh_public_key());

    std::vector<std::string> conversation = {
        "Hello Bob!", "Hi Alice!", "How are you?", "All good, thanks!"
    };

    for (size_t i = 0; i < conversation.size(); ++i) {
        if (i % 2 == 0) {
            auto plaintext = make_bytes(conversation[i]);
            Envelope env = alice.encrypt_envelope(plaintext);
            auto pt = bob.decrypt_envelope(env);
            assert(pt.has_value() && pt.value() == plaintext);
            std::cout << "Bob received: " << conversation[i] << "\n";
        } else {
            auto plaintext = make_bytes(conversation[i]);
            Envelope env = bob.encrypt_envelope(plaintext);
            auto pt = alice.decrypt_envelope(env);
            assert(pt.has_value() && pt.value() == plaintext);
            std::cout << "Alice received: " << conversation[i] << "\n";
        }
    }

    // ratchet again
    alice.ratchet_step(bob.dh_public_key());
    bob.ratchet_step(alice.dh_public_key());

    auto final_msg = make_bytes("After ratchet step message");
    Envelope env = alice.encrypt_envelope(final_msg);
    auto pt = bob.decrypt_envelope(env);
    assert(pt.has_value() && pt.value() == final_msg);
    std::cout << "Bob received after ratchet step: After ratchet step message\n";

    std::cout << "End-to-end messaging demo (envelope): OK\n";
    return 0;
}
