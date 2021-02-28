package simple

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
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

// InSlice check if string in slice
func InSlice(s string, array []string) bool {
	for _, a := range array {
		if s == a {
			return true
		}
	}
	return false
}

// ToJSON convert to JSON
func ToJSON(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

// GetUUID get a new uuid string
func GetUUID() string {
	return uuid.NewString()
}

// BadHTTPResponse check is http response code is less than 300
func BadHTTPResponse(r *http.Response) error {
	if r.StatusCode < 300 {
		return fmt.Errorf("Bad response code: %d", r.StatusCode)
	}
	return nil
}
