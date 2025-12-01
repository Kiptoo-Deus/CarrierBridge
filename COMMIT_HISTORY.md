commit 0010: libsecurecomm: add Ratchet skeleton with AEAD integration
 - Ratchet class with send/recv chain keys and message counters
 - encrypt()/decrypt() use AEAD wrapper
 - State export/import functions with unit test
 - Sets foundation for 1:1 secure messaging
