package decode

import "testing"

func TestBase64(t *testing.T) {
	o, err := Base64String("dGVzdA==")
	if err != nil {
		t.Fatal(err)
	}
	if string(o) != "test" {
		t.Fatal("Failed to decode")
	}
}

func TestHex(t *testing.T) {
	o, err := HexString("74657374")
	if err != nil {
		t.Fatal(err)
	}
	if string(o) != "test" {
		t.Fatalf("Incorrect value %s", o)
	}
}
