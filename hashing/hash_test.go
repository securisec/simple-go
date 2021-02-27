package hashing

import (
	"testing"
)

func TestSha1(t *testing.T) {
	data := []byte("test")
	h, _, err := SHA1(data)
	if err != nil {
		t.Fatal(err)
	}
	if h != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Fatal("Hash value did not match")
	}
}

func TestSha256(t *testing.T) {
	data := []byte("test")
	h, _, err := SHA256(data)
	if err != nil {
		t.Fatal(err)
	}
	if h != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatal("Hash value did not match")
	}
}

func TestSha512(t *testing.T) {
	data := []byte("test")
	h, _, err := SHA512(data)
	if err != nil {
		t.Fatal(err)
	}
	if h != "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff" {
		t.Fatal("Hash value did not match")
	}
}
