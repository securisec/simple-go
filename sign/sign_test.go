package sign

import (
	"encoding/hex"
	"testing"
)

func TestHmacSha1SignVerify(t *testing.T) {
	data := []byte("test")
	secret := []byte("secret")
	// sign
	sig, err := HMACSHA1Sign(secret, data)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sig) != "1aa349585ed7ecbd3b9c486a30067e395ca4b356" {
		t.Fatal("Hash value did not match")
	}

	// verify
	v, err := HMACSHA1Verify(secret, sig, data)
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Fatal("Signature does not match")
	}
}
