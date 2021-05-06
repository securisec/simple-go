package sign

import (
	"crypto/hmac"
	"crypto/sha1"
)

// HMACSHA1Sign get hmac sha1 signature of msg
// Returns signature as byte array.
func HMACSHA1Sign(secret []byte, msg []byte) ([]byte, error) {
	c := hmac.New(sha1.New, secret)
	_, err := c.Write(msg)
	return c.Sum(nil), err
}

// HMACSHA1Verify verify hmac sha1 signature
// Returns bool if signature matched
func HMACSHA1Verify(secret []byte, signature []byte, msg []byte) (bool, error) {
	sig, err := HMACSHA1Sign(secret, msg)
	return hmac.Equal(sig, signature), err
}
