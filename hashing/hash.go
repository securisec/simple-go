package hashing

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// SHA1 sha 1 hash.
// Return hash string in hex, bytes and error
func SHA1(data []byte) (string, []byte, error) {
	h := sha1.New()
	_, err := h.Write(data)
	if err != nil {
		return "", nil, err
	}
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs), bs, nil
}

// SHA256 sha 256 hash
// Return hash string in hex, bytes and error
func SHA256(data []byte) (string, []byte, error) {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return "", nil, err
	}
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs), bs, nil
}

// SHA512 sha 512 hash
// Return hash string in hex, bytes and error
func SHA512(data []byte) (string, []byte, error) {
	h := sha512.New()
	_, err := h.Write(data)
	if err != nil {
		return "", nil, err
	}
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs), bs, nil
}
