package com.example.secure_carrier.crypto

class SecureCommNative {
    companion object {
        init {
            System.loadLibrary("securecomm") 
        }
    }

    external fun setKey(key: ByteArray)
    external fun encrypt(plaintext: ByteArray, aad: ByteArray? = null): ByteArray
    external fun decrypt(ciphertext: ByteArray, aad: ByteArray? = null): ByteArray?
}