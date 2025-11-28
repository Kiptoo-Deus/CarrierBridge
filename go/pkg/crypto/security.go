package crypto

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
)

type CryptoManager struct {
    privateKey *rsa.PrivateKey
    publicKey  *rsa.PublicKey
}

func NewCryptoManager() (*CryptoManager, error) {
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    
    return &CryptoManager{
        privateKey: privKey,
        publicKey:  &privKey.PublicKey,
    }, nil
}

func (cm *CryptoManager) Encrypt(data []byte) ([]byte, error) {
    return rsa.EncryptOAEP(
        sha256.New(),
        rand.Reader,
        cm.publicKey,
        data,
        nil,
    )
}

func (cm *CryptoManager) Decrypt(encryptedData []byte) ([]byte, error) {
    return rsa.DecryptOAEP(
        sha256.New(),
        rand.Reader,
        cm.privateKey,
        encryptedData,
        nil,
    )
}

func (cm *CryptoManager) GetPublicKeyPEM() (string, error) {
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(cm.publicKey)
    if err != nil {
        return "", err
    }
    
    pubKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: pubKeyBytes,
    })
    
    return string(pubKeyPEM), nil
}

func PublicKeyFromPEM(pemStr string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pemStr))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing public key")
    }
    
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    
    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        return nil, errors.New("not an RSA public key")
    }
    
    return rsaPub, nil
}