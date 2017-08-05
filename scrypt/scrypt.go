package scrypt

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"log"

	"github.com/nbari/crypto"

	"golang.org/x/crypto/scrypt"
)

// The recommended parameters for interactive logins as of 2009 are N=16384, r=8, p=1.
const (
	N = 1 << 14
	r = 8
	p = 1
)

// Create
// array index starts from left.
// <---keylen---><----16----><--4--><--4--><--4--><----32---->
//    password       salt       N      r      p   sha-256 hash
func Create(password string, keyLen int) ([]byte, error) {
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, N, r, p, keyLen)
	if err != nil {
		log.Printf("Error in deriving passphrase: %s\n", err)
		return nil, err
	}

	// Appending the salt
	key = append(key, salt...)

	// Encoding the params to be stored
	buf := &bytes.Buffer{}
	for _, elem := range [3]int{N, r, p} {
		err = binary.Write(buf, binary.LittleEndian, int32(elem))
		if err != nil {
			log.Printf("binary.Write failed: %s\n", err)
			return nil, err
		}
		key = append(key, buf.Bytes()...)
		buf.Reset()
	}

	// appending the sha-256 of the entire header at the end
	hash_digest := sha256.New()
	hash_digest.Write(key)
	if err != nil {
		log.Printf("hash_digest.Write failed: %s\n", err)
		return nil, err
	}
	hash := hash_digest.Sum(nil)
	key = append(key, hash...)

	return key, nil
}

// Verify compare password and derivated key
func Verify(password string, target []byte) (bool, error) {
	keylen := len(target) - 60
	pass := target[:keylen]

	// Get the salt
	salt := target[keylen : keylen+16]

	// Get the params
	var N, r, p int32

	NPad := keylen + 16 + 4
	rPad := NPad + 4
	pPad := rPad + 4

	// byte 48:52 for N
	err := binary.Read(bytes.NewReader(target[keylen+16:NPad]), binary.LittleEndian, &N)
	if err != nil {
		log.Printf("binary.Read failed for N: %s\n", err)
		return false, err
	}

	// byte 52:56 for r
	err = binary.Read(bytes.NewReader(target[NPad:rPad]), binary.LittleEndian, &r)
	if err != nil {
		log.Printf("binary.Read failed for r: %s\n", err)
		return false, err
	}

	// byte 56:60 for p
	err = binary.Read(bytes.NewReader(target[rPad:pPad]), binary.LittleEndian, &p)
	if err != nil {
		log.Printf("binary.Read failed for p: %s\n", err)
		return false, err
	}

	key, err := scrypt.Key([]byte(password), salt, int(N), int(r), int(p), keylen)
	if err != nil {
		log.Printf("Error in deriving passphrase: %s\n", err)
		return false, err
	}

	// <--32-->
	targetHash := target[pPad:]
	// Doing the sha-256 checksum at the last because we want the attacker
	// to spend as much time possible cracking
	hashDigest := sha256.New()
	_, err = hashDigest.Write(target[:pPad])
	if err != nil {
		log.Printf("hash_digest.Write failed: %s\n", err)
		return false, err
	}
	sourceHash := hashDigest.Sum(nil)

	// ConstantTimeCompare returns ints. Converting it to bool
	keyComp := subtle.ConstantTimeCompare(key, pass) != 0
	hashComp := subtle.ConstantTimeCompare(targetHash, sourceHash) != 0
	return keyComp && hashComp, nil
}
