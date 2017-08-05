package scrypt

import (
	"testing"
)

func TestPassword(t *testing.T) {
	tests := []struct {
		password string
		len      int
	}{
		{"secret", 10},
		{"secret", 20},
		{"secret", 30},
		{"secret", 40},
		{"secret", 50},
		{"The quick brown fox jumps over the lazy dog", 32},
		{"The quick brown fox jumps over the lazy dog", 64},
	}
	for _, tt := range tests {
		key, err := Create(tt.password, tt.len)
		if err != nil {
			t.Fatal(err)
		}
		result, err := Verify(tt.password, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result {
			t.Fatal("Expecting result to be true")
		}
	}
}
