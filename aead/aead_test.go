package aead

import (
	"bytes"
	"testing"

	"github.com/nbari/crypto"
)

func TestAEAD(t *testing.T) {
	password, err := crypto.GenerateSalt(32)
	if err != nil {
		t.Error(err)
	}

	message := []byte("The quick brown fox jumps over the lazy dog")
	ciphertext, err := Encrypt(password, message, []byte(""))
	if err != nil {
		t.Error(err)
	}

	plaintext, err := Decrypt(password, ciphertext, []byte(""))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Error("message != plaintext")
	}
}

func TestAEADextra(t *testing.T) {
	password, err := crypto.GenerateSalt(32)
	if err != nil {
		t.Error(err)
	}

	message := []byte("The quick brown fox jumps over the lazy dog")
	extra, err := crypto.GenerateSalt(64)
	if err != nil {
		t.Error(err)
	}

	ciphertext, err := Encrypt(password, message, extra)
	if err != nil {
		t.Error(err)
	}

	plaintext, err := Decrypt(password, ciphertext, extra)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Error("message != plaintext")
	}
}
