package crypto

import "testing"

func TestGenerateSalt(t *testing.T) {
	grains := make(map[string]int)
	for i := 0; i < 1000000; i++ {
		if grain, err := GenerateSalt(32); err == nil {
			grains[string(grain)] = i
		} else {
			t.Error(err)
		}
	}
	if len(grains) != 1000000 {
		t.Error("Salts repeating")
	}
}
