package crypto

import "testing"

func TestGenerateSalt(t *testing.T) {
	nonces := make(map[string]int)
	for i := 0; i < 1000000; i++ {
		if nonce, err := GenerateSalt(32); err == nil {
			nonces[string(nonce)] = i
		} else {
			t.Error(err)
		}
	}
	if len(nonces) != 1000000 {
		t.Error("Salts repeating")
	}
}
