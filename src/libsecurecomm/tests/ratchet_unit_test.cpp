#include "securecomm/ratchet.hpp"
#include <iostream>
#include <vector>
#include <cassert>

using namespace securecomm;

static std::vector<uint8_t> make_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    std::cout << "Starting ratchet unit test (envelope)...\n";

    std::vector<uint8_t> root_key(32, 2);
    Ratchet a, b;
    a.initialize(root_key);
    b.initialize(root_key);

    a.ratchet_step(b.dh_public_key());
    b.ratchet_step(a.dh_public_key());

    auto pt1 = make_bytes("test1");
    Envelope e1 = a.encrypt_envelope(pt1);
    auto r1 = b.decrypt_envelope(e1);
    assert(r1.has_value() && r1.value() == pt1);

    auto pt2 = make_bytes("test2");
    Envelope e2 = b.encrypt_envelope(pt2);
    auto r2 = a.decrypt_envelope(e2);
    assert(r2.has_value() && r2.value() == pt2);

    std::cout << "Ratchet unit test (envelope): OK\n";
    return 0;
}
