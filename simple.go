package simple

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRandomKey generate a random key in bytes
func GenerateRandomKey(length int) []byte {
	k := make([]byte, length)
	rand.Read(k)
	return k
}

// GenerateRandomKeyHex generate random hex string key
func GenerateRandomKeyHex(length int) string {
	k := make([]byte, length)
	rand.Read(k)
	return hex.EncodeToString(k)
}

// HexToBytes decode hex string to bytes
func HexToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
