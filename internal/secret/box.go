// Package secret encrypts provider credentials at rest.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Seal encrypts plaintext with a 32-byte key. The result is nonce || ciphertext.
func Seal(key, plaintext []byte) ([]byte, error) {
	gcm, err := gcmFrom(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a blob produced by Seal.
func Open(key, blob []byte) ([]byte, error) {
	gcm, err := gcmFrom(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns+gcm.Overhead() {
		return nil, errors.New("secret: ciphertext is too short")
	}
	out, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, errors.New("secret: decryption failed")
	}
	return out, nil
}

func gcmFrom(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secret: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
