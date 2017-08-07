package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/nbari/crypto"
)

// Encrypt AES-256 GCM
func Encrypt(password, message, additionalData []byte) ([]byte, error) {
	if len(password) != 32 {
		return nil, fmt.Errorf("key size %d != 32", len(password))
	}

	c, err := aes.NewCipher(password)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce, err := crypto.GenerateSalt(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	out := gcm.Seal(nonce, nonce, message, additionalData)
	return out, nil
}

// Decrypt AES-256 GCM
func Decrypt(password, message, additionalData []byte) ([]byte, error) {
	c, err := aes.NewCipher(password)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, message[:gcm.NonceSize()])

	out, err := gcm.Open(nil, nonce, message[gcm.NonceSize():], additionalData)
	if err != nil {
		return nil, err
	}
	return out, nil
}
