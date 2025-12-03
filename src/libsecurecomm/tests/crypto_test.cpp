#include "securecomm/crypto.hpp"
#include <iostream>
#include <cassert>
#include <sodium.h>
#include <cstring>

using namespace securecomm;

// =============================================================================
// Test: AEAD Initialization
// =============================================================================
void test_aead_init() {
    std::cout << "Test: AEAD initialization... ";
    
    try {
        AEAD aead;
        std::cout << "✓ AEAD initialized successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: AEAD Key Setting
// =============================================================================
void test_aead_key_setting() {
    std::cout << "Test: AEAD key setting... ";
    
    try {
        AEAD aead;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        aead.set_key(key);
        std::cout << "✓ Key set successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: AEAD Key Validation (wrong size)
// =============================================================================
void test_aead_invalid_key_size() {
    std::cout << "Test: AEAD key validation (invalid size)... ";
    
    AEAD aead;
    std::vector<uint8_t> key(16);  // Wrong size (should be 32)
    randombytes_buf(key.data(), key.size());
    
    try {
        aead.set_key(key);
        std::cout << "✗ FAILED: Should have rejected 16-byte key" << std::endl;
        throw std::runtime_error("Key validation failed");
    } catch (const std::runtime_error& e) {
        if (std::string(e.what()).find("32 bytes") != std::string::npos) {
            std::cout << "✓ Correctly rejected invalid key size" << std::endl;
        } else {
            throw;
        }
    }
}

// =============================================================================
// Test: AEAD Encrypt/Decrypt Round-Trip
// =============================================================================
void test_aead_encrypt_decrypt() {
    std::cout << "Test: AEAD encrypt/decrypt round-trip... ";
    
    try {
        AEAD aead;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        aead.set_key(key);
        
        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
        std::vector<uint8_t> ciphertext = aead.encrypt(plaintext);
        
        auto decrypted = aead.decrypt(ciphertext);
        assert(decrypted.has_value());
        assert(decrypted.value() == plaintext);
        
        std::cout << "✓ Plaintext size: " << plaintext.size() 
                  << ", Ciphertext size: " << ciphertext.size() 
                  << ", Decrypted matches original" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: AEAD with Additional Authenticated Data (AAD)
// =============================================================================
void test_aead_with_aad() {
    std::cout << "Test: AEAD with AAD... ";
    
    try {
        AEAD aead;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        aead.set_key(key);
        
        std::vector<uint8_t> plaintext = {'S','e','c','r','e','t'};
        std::vector<uint8_t> aad = {'a','a','d',' ','d','a','t','a'};
        
        std::vector<uint8_t> ciphertext = aead.encrypt(plaintext, aad);
        auto decrypted = aead.decrypt(ciphertext, aad);
        
        assert(decrypted.has_value());
        assert(decrypted.value() == plaintext);
        
        std::cout << "✓ AAD protected encryption/decryption" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: AEAD AAD Verification (wrong AAD fails)
// =============================================================================
void test_aead_aad_verification() {
    std::cout << "Test: AEAD AAD verification (tampering detection)... ";
    
    try {
        AEAD aead;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        aead.set_key(key);
        
        std::vector<uint8_t> plaintext = {'D','a','t','a'};
        std::vector<uint8_t> aad1 = {'a','a','d','1'};
        std::vector<uint8_t> aad2 = {'a','a','d','2'};
        
        std::vector<uint8_t> ciphertext = aead.encrypt(plaintext, aad1);
        
        // Try to decrypt with different AAD - should fail
        auto decrypted = aead.decrypt(ciphertext, aad2);
        
        if (!decrypted.has_value()) {
            std::cout << "✓ Correctly rejected ciphertext with wrong AAD" << std::endl;
        } else {
            std::cout << "✗ FAILED: Should reject wrong AAD" << std::endl;
            throw std::runtime_error("AAD verification failed");
        }
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: AEAD Empty Plaintext
// =============================================================================
void test_aead_empty_plaintext() {
    std::cout << "Test: AEAD empty plaintext... ";
    
    try {
        AEAD aead;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        aead.set_key(key);
        
        std::vector<uint8_t> plaintext;  // Empty
        std::vector<uint8_t> ciphertext = aead.encrypt(plaintext);
        
        auto decrypted = aead.decrypt(ciphertext);
        assert(decrypted.has_value());
        assert(decrypted.value().empty());
        
        std::cout << "✓ Empty message handled correctly" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: AEAD Large Message
// =============================================================================
void test_aead_large_message() {
    std::cout << "Test: AEAD large message (1MB)... ";
    
    try {
        AEAD aead;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        aead.set_key(key);
        
        // Create 1MB plaintext
        std::vector<uint8_t> plaintext(1024 * 1024);
        for (size_t i = 0; i < plaintext.size(); i++) {
            plaintext[i] = static_cast<uint8_t>(i % 256);
        }
        
        std::vector<uint8_t> ciphertext = aead.encrypt(plaintext);
        auto decrypted = aead.decrypt(ciphertext);
        
        assert(decrypted.has_value());
        assert(decrypted.value() == plaintext);
        
        std::cout << "✓ Large message (1MB) encrypted/decrypted successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: AEAD Ciphertext Tampering Detection
// =============================================================================
void test_aead_tampering_detection() {
    std::cout << "Test: AEAD tampering detection... ";
    
    try {
        AEAD aead;
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        aead.set_key(key);
        
        std::vector<uint8_t> plaintext = {'P','a','y','l','o','a','d'};
        std::vector<uint8_t> ciphertext = aead.encrypt(plaintext);
        
        // Tamper with ciphertext (flip a bit)
        if (ciphertext.size() > 20) {
            ciphertext[20] ^= 0x01;
        }
        
        auto decrypted = aead.decrypt(ciphertext);
        
        if (!decrypted.has_value()) {
            std::cout << "✓ Tampering detected and rejected" << std::endl;
        } else {
            std::cout << "✗ FAILED: Should detect tampering" << std::endl;
            throw std::runtime_error("Tampering detection failed");
        }
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: HMAC-SHA256 Generation
// =============================================================================
void test_hmac_sha256() {
    std::cout << "Test: HMAC-SHA256 generation... ";
    
    try {
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        
        std::vector<uint8_t> message = {'t','e','s','t',' ','d','a','t','a'};
        
        unsigned char hmac[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256(hmac, message.data(), message.size(), key.data());
        
        assert(crypto_auth_hmacsha256_BYTES == 32);
        
        std::cout << "✓ HMAC-SHA256 (" << crypto_auth_hmacsha256_BYTES << " bytes) generated" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: HMAC-SHA256 Verification
// =============================================================================
void test_hmac_sha256_verify() {
    std::cout << "Test: HMAC-SHA256 verification... ";
    
    try {
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        
        std::vector<uint8_t> message = {'v','e','r','i','f','y'};
        
        unsigned char hmac[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256(hmac, message.data(), message.size(), key.data());
        
        // Verify should succeed
        int result = crypto_auth_hmacsha256_verify(hmac, message.data(), message.size(), key.data());
        assert(result == 0);
        
        // Tamper with HMAC and verify should fail
        hmac[0] ^= 0x01;
        result = crypto_auth_hmacsha256_verify(hmac, message.data(), message.size(), key.data());
        assert(result != 0);
        
        std::cout << "✓ HMAC-SHA256 verification working correctly" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: HMAC-SHA256 Deterministic Output
// =============================================================================
void test_hmac_sha256_deterministic() {
    std::cout << "Test: HMAC-SHA256 deterministic output... ";
    
    try {
        std::vector<uint8_t> key(32);
        randombytes_buf(key.data(), key.size());
        
        std::vector<uint8_t> message = {'d','e','t','e','r','m','i','n','i','s','t','i','c'};
        
        unsigned char hmac1[crypto_auth_hmacsha256_BYTES];
        unsigned char hmac2[crypto_auth_hmacsha256_BYTES];
        
        crypto_auth_hmacsha256(hmac1, message.data(), message.size(), key.data());
        crypto_auth_hmacsha256(hmac2, message.data(), message.size(), key.data());
        
        assert(std::memcmp(hmac1, hmac2, crypto_auth_hmacsha256_BYTES) == 0);
        
        std::cout << "✓ HMAC-SHA256 produces consistent output" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: Diffie-Hellman Key Generation
// =============================================================================
void test_dh_key_generation() {
    std::cout << "Test: Diffie-Hellman key generation... ";
    
    try {
        std::vector<uint8_t> secret_key(crypto_scalarmult_BYTES);
        std::vector<uint8_t> public_key(crypto_scalarmult_BYTES);
        
        randombytes_buf(secret_key.data(), secret_key.size());
        
        int result = crypto_scalarmult_base(public_key.data(), secret_key.data());
        assert(result == 0);
        assert(public_key.size() == crypto_scalarmult_BYTES);
        assert(secret_key.size() == crypto_scalarmult_BYTES);
        
        std::cout << "✓ DH keys generated (" << crypto_scalarmult_BYTES << " bytes each)" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: Diffie-Hellman Shared Secret
// =============================================================================
void test_dh_shared_secret() {
    std::cout << "Test: Diffie-Hellman shared secret... ";
    
    try {
        // Generate keys for Alice
        std::vector<uint8_t> alice_secret(crypto_scalarmult_BYTES);
        std::vector<uint8_t> alice_public(crypto_scalarmult_BYTES);
        randombytes_buf(alice_secret.data(), alice_secret.size());
        crypto_scalarmult_base(alice_public.data(), alice_secret.data());
        
        // Generate keys for Bob
        std::vector<uint8_t> bob_secret(crypto_scalarmult_BYTES);
        std::vector<uint8_t> bob_public(crypto_scalarmult_BYTES);
        randombytes_buf(bob_secret.data(), bob_secret.size());
        crypto_scalarmult_base(bob_public.data(), bob_secret.data());
        
        // Compute shared secrets
        std::vector<uint8_t> alice_shared(crypto_scalarmult_BYTES);
        std::vector<uint8_t> bob_shared(crypto_scalarmult_BYTES);
        
        assert(crypto_scalarmult(alice_shared.data(), alice_secret.data(), bob_public.data()) == 0);
        assert(crypto_scalarmult(bob_shared.data(), bob_secret.data(), alice_public.data()) == 0);
        
        // Shared secrets should match
        assert(alice_shared == bob_shared);
        
        std::cout << "✓ DH shared secret computed and matches" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Test: DH Secret Different for Different Key Pairs
// =============================================================================
void test_dh_secret_uniqueness() {
    std::cout << "Test: DH shared secret uniqueness... ";
    
    try {
        // Alice-Bob shared secret
        std::vector<uint8_t> alice_secret(crypto_scalarmult_BYTES);
        std::vector<uint8_t> alice_public(crypto_scalarmult_BYTES);
        randombytes_buf(alice_secret.data(), alice_secret.size());
        crypto_scalarmult_base(alice_public.data(), alice_secret.data());
        
        std::vector<uint8_t> bob_secret(crypto_scalarmult_BYTES);
        std::vector<uint8_t> bob_public(crypto_scalarmult_BYTES);
        randombytes_buf(bob_secret.data(), bob_secret.size());
        crypto_scalarmult_base(bob_public.data(), bob_secret.data());
        
        std::vector<uint8_t> alice_bob_shared(crypto_scalarmult_BYTES);
        assert(crypto_scalarmult(alice_bob_shared.data(), alice_secret.data(), bob_public.data()) == 0);
        
        // Alice-Charlie shared secret
        std::vector<uint8_t> charlie_secret(crypto_scalarmult_BYTES);
        std::vector<uint8_t> charlie_public(crypto_scalarmult_BYTES);
        randombytes_buf(charlie_secret.data(), charlie_secret.size());
        crypto_scalarmult_base(charlie_public.data(), charlie_secret.data());
        
        std::vector<uint8_t> alice_charlie_shared(crypto_scalarmult_BYTES);
        assert(crypto_scalarmult(alice_charlie_shared.data(), alice_secret.data(), charlie_public.data()) == 0);
        
        // Different shared secrets
        assert(alice_bob_shared != alice_charlie_shared);
        
        std::cout << "✓ Different DH key pairs produce different shared secrets" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✗ FAILED: " << e.what() << std::endl;
        throw;
    }
}

// =============================================================================
// Main Test Runner
// =============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Crypto Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;
    
    try {
        // AEAD Tests
        test_aead_init();
        test_aead_key_setting();
        test_aead_invalid_key_size();
        test_aead_encrypt_decrypt();
        test_aead_with_aad();
        test_aead_aad_verification();
        test_aead_empty_plaintext();
        test_aead_large_message();
        test_aead_tampering_detection();
        
        std::cout << std::endl;
        
        // HMAC Tests
        test_hmac_sha256();
        test_hmac_sha256_verify();
        test_hmac_sha256_deterministic();
        
        std::cout << std::endl;
        
        // DH Tests
        test_dh_key_generation();
        test_dh_shared_secret();
        test_dh_secret_uniqueness();
        
        std::cout << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "  ✓ All tests passed!" << std::endl;
        std::cout << "========================================" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cout << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "  ✗ Test suite failed" << std::endl;
        std::cout << "========================================" << std::endl;
        return 1;
    }
}
