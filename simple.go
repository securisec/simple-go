package simple

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
)

// GenerateRandomKey generate a random key in bytes
func GenerateRandomKey(length int) ([]byte, error) {
	k := make([]byte, length)
	_, err := rand.Read(k)
	return k, err
}

// GenerateRandomKeyHex generate random hex string key
func GenerateRandomKeyHex(length int) (string, error) {
	k := make([]byte, length)
	_, err := rand.Read(k)
	return hex.EncodeToString(k), err
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

// Catch catch an error. If no out function is provided, it
// defaults to log.Panic
func Catch(err error, out ...func(s interface{})) error {
	var f func(a ...interface{})
	if err != nil {
		if len(out) == 0 {
			f = log.Panic
		}
		f(err)
	}
	return err
}
