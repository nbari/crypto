package scrypt

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"os"

	"github.com/nbari/crypto"

	"golang.org/x/crypto/scrypt"
)

// The recommended parameters for interactive logins as of 2009 are N=16384, r=8, p=1.
const (
	N = 1 << 14
	r = 8
	p = 1
)

// Create derives a key from the password+pepper, salt, and cost
// parameters, returning a byte slice of length keyLen that can be used as
// cryptographic key.
//
// pepper is taken from environment var SCRYPT_PEPPER
//
// output format
// <---keylen---><----16----><--4--><--4--><--4--><----32---->
//   pass+pepper     salt       N      r      p   sha-256 hash
func Create(password string, keyLen int) ([]byte, error) {
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		return nil, err
	}

	password += os.Getenv("SCRYPT_PEPPER")

	key, err := scrypt.Key([]byte(password), salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}

	// Appending the salt
	key = append(key, salt...)

	// Encoding the params to be stored
	buf := &bytes.Buffer{}
	for _, elem := range [3]int{N, r, p} {
		err = binary.Write(buf, binary.LittleEndian, int32(elem))
		if err != nil {
			return nil, err
		}
		key = append(key, buf.Bytes()...)
		buf.Reset()
	}

	// appending the sha-256 of the entire header at the end
	hash_digest := sha256.New()
	hash_digest.Write(key)
	if err != nil {
		return nil, err
	}
	hash := hash_digest.Sum(nil)
	key = append(key, hash...)

	return key, nil
}

// Verify compare password and derivated key
func Verify(password string, dk []byte) (bool, error) {
	keylen := len(dk) - 60
	pass := dk[:keylen]

	// Get the salt
	salt := dk[keylen : keylen+16]

	// Get the params
	var N, r, p int32

	NPad := keylen + 16 + 4
	rPad := NPad + 4
	pPad := rPad + 4

	// byte for N
	err := binary.Read(bytes.NewReader(dk[keylen+16:NPad]), binary.LittleEndian, &N)
	if err != nil {
		return false, err
	}

	// byte for r
	err = binary.Read(bytes.NewReader(dk[NPad:rPad]), binary.LittleEndian, &r)
	if err != nil {
		return false, err
	}

	// byte for p
	err = binary.Read(bytes.NewReader(dk[rPad:pPad]), binary.LittleEndian, &p)
	if err != nil {
		return false, err
	}

	password += os.Getenv("SCRYPT_PEPPER")

	key, err := scrypt.Key([]byte(password), salt, int(N), int(r), int(p), keylen)
	if err != nil {
		return false, err
	}

	// <--32-->
	dkHash := dk[pPad:]
	h := sha256.New()
	_, err = h.Write(dk[:pPad])
	if err != nil {
		return false, err
	}
	keyHash := h.Sum(nil)

	// ConstantTimeCompare returns ints. Converting it to bool
	keyComp := subtle.ConstantTimeCompare(key, pass) != 0
	hashComp := subtle.ConstantTimeCompare(dkHash, keyHash) != 0
	return keyComp && hashComp, nil
}
