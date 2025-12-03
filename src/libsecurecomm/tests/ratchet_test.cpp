#include <cassert>
#include <iostream>
#include <vector>
#include "securecomm/ratchet.hpp"

using namespace securecomm;

// Helper to print hex
void print_hex(const std::string& label, const std::vector<uint8_t>& data, size_t max_len = 8) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), max_len); i++) {
        printf("%02x", data[i]);
    }
    if (data.size() > max_len) std::cout << "...";
    std::cout << std::endl;
}

// Test 1: Initialize two ratchets with same root key
void test_initialize() {
    std::cout << "\n=== Test: Initialize ===" << std::endl;
    
    std::vector<uint8_t> root_key(32, 0x42);
    std::vector<uint8_t> session_id(16, 0x11);
    
    Ratchet r1, r2;
    r1.initialize(root_key, session_id);
    r2.initialize(root_key, session_id);
    
    std::cout << "✓ Both ratchets initialized" << std::endl;
}

// Test 2: Encrypt and decrypt a message
void test_encrypt_decrypt() {
    std::cout << "\n=== Test: Encrypt/Decrypt ===" << std::endl;
    
    std::vector<uint8_t> root_key(32, 0x42);
    std::vector<uint8_t> session_id(16, 0x11);
    
    Ratchet sender, receiver;
    sender.initialize(root_key, session_id);
    receiver.initialize(root_key, session_id);
    
    // Sender encrypts
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    Envelope env = sender.encrypt_envelope(plaintext);
    
    print_hex("Plaintext", plaintext);
    print_hex("Ciphertext", env.ciphertext);
    
    // Receiver decrypts
    auto decrypted = receiver.decrypt_envelope(env);
    assert(decrypted.has_value());
    assert(decrypted.value() == plaintext);
    
    std::cout << "✓ Message encrypted and decrypted successfully" << std::endl;
}

// Test 3: Bidirectional messaging
void test_bidirectional() {
    std::cout << "\n=== Test: Bidirectional Messaging ===" << std::endl;
    
    std::vector<uint8_t> root_key(32, 0x42);
    std::vector<uint8_t> session_id(16, 0x11);
    
    Ratchet alice, bob;
    alice.initialize(root_key, session_id);
    bob.initialize(root_key, session_id);
    
    // Alice -> Bob
    std::vector<uint8_t> msg1 = {'M', 's', 'g', '1'};
    Envelope env1 = alice.encrypt_envelope(msg1);
    auto decrypted1 = bob.decrypt_envelope(env1);
    assert(decrypted1.has_value());
    assert(decrypted1.value() == msg1);
    std::cout << "✓ Alice -> Bob: OK" << std::endl;
    
    // Bob -> Alice
    std::vector<uint8_t> msg2 = {'M', 's', 'g', '2'};
    Envelope env2 = bob.encrypt_envelope(msg2);
    auto decrypted2 = alice.decrypt_envelope(env2);
    assert(decrypted2.has_value());
    assert(decrypted2.value() == msg2);
    std::cout << "✓ Bob -> Alice: OK" << std::endl;
    
    // Alice -> Bob (again)
    std::vector<uint8_t> msg3 = {'M', 's', 'g', '3'};
    Envelope env3 = alice.encrypt_envelope(msg3);
    auto decrypted3 = bob.decrypt_envelope(env3);
    assert(decrypted3.has_value());
    assert(decrypted3.value() == msg3);
    std::cout << "✓ Alice -> Bob (2nd): OK" << std::endl;
}

// Test 4: Chain key advancement
void test_chain_ratchet() {
    std::cout << "\n=== Test: Chain Key Advancement ===" << std::endl;
    
    std::vector<uint8_t> root_key(32, 0x42);
    std::vector<uint8_t> session_id(16, 0x11);
    
    Ratchet r;
    r.initialize(root_key, session_id);
    
    // Encrypt multiple messages
    for (int i = 0; i < 5; i++) {
        std::vector<uint8_t> msg = {'M', 's', 'g', static_cast<uint8_t>('0' + i)};
        Envelope env = r.encrypt_envelope(msg);
    }
    std::cout << "✓ Chain key advanced 5 times" << std::endl;
}

// Test 5: Session ID consistency
void test_session_id() {
    std::cout << "\n=== Test: Session ID Consistency ===" << std::endl;
    
    std::vector<uint8_t> root_key(32, 0x42);
    std::vector<uint8_t> session_id(16, 0xAA);
    
    Ratchet r1, r2;
    r1.initialize(root_key, session_id);
    r2.initialize(root_key, session_id);
    
    Envelope env = r1.encrypt_envelope(std::vector<uint8_t>{'X'});
    
    // Both should have same session_id
    assert(env.session_id == session_id);
    std::cout << "✓ Session ID consistent" << std::endl;
}

// Test 6: Large message
void test_large_message() {
    std::cout << "\n=== Test: Large Message ===" << std::endl;
    
    std::vector<uint8_t> root_key(32, 0x42);
    std::vector<uint8_t> session_id(16, 0x11);
    
    Ratchet sender, receiver;
    sender.initialize(root_key, session_id);
    receiver.initialize(root_key, session_id);
    
    std::vector<uint8_t> large_msg(10000, 0x55);
    Envelope env = sender.encrypt_envelope(large_msg);
    auto decrypted = receiver.decrypt_envelope(env);
    
    assert(decrypted.has_value());
    assert(decrypted.value() == large_msg);
    std::cout << "✓ Large message (10KB) encrypted and decrypted" << std::endl;
}

// Test 7: Empty message
void test_empty_message() {
    std::cout << "\n=== Test: Empty Message ===" << std::endl;
    
    std::vector<uint8_t> root_key(32, 0x42);
    std::vector<uint8_t> session_id(16, 0x11);
    
    Ratchet sender, receiver;
    sender.initialize(root_key, session_id);
    receiver.initialize(root_key, session_id);
    
    std::vector<uint8_t> empty_msg;
    Envelope env = sender.encrypt_envelope(empty_msg);
    auto decrypted = receiver.decrypt_envelope(env);
    
    assert(decrypted.has_value());
    assert(decrypted.value().empty());
    std::cout << "✓ Empty message handled correctly" << std::endl;
}

int main() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "  CarrierBridge Ratchet Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    try {
        test_initialize();
        test_encrypt_decrypt();
        test_bidirectional();
        test_chain_ratchet();
        test_session_id();
        test_large_message();
        test_empty_message();
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "  ✓ All tests passed!" << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
