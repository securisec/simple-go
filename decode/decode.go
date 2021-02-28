package decode

import (
	"encoding/base64"
	"encoding/hex"
)

// Base64String decode base64 string
func Base64String(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// HexString decode from hex string
func HexString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
