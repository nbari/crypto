package scrypt

import (
	"testing"
)

func TestPassword(t *testing.T) {
	tt := []struct {
		name     string
		password string
		len      int
	}{
		{"len 10", "secret", 10},
		{"len 20", "secret", 20},
		{"len 30", "secret", 30},
		{"len 40", "secret", 40},
		{"len 50", "secret", 50},
		{"len 32", "The quick brown fox jumps over the lazy dog", 32},
		{"len 64", "The quick brown fox jumps over the lazy dog", 64},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			key, err := Create(tc.password, tc.len)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Verify(tc.password, key)
			if err != nil {
				t.Fatal(err)
			}
			if !result {
				t.Fatal("Expecting result to be true")
			}
		})
	}
}
