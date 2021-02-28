package encode

import (
	"encoding/base64"
	"encoding/hex"
)

// Base64String encode to base 64
func Base64String(d []byte) []byte {
	base64.StdEncoding.EncodeToString(d)
	return d
}

// Hex decode to hex
func Hex(d []byte) ([]byte, error) {
	o := make([]byte, len(d))
	_, err := hex.Decode(o, d)
	return o, err
}

// HexString encode to hex string
func HexString(d []byte) string {
	return hex.EncodeToString(d)
}
