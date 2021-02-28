package simple

import "testing"

func TestUUID(t *testing.T) {
	u := GetUUID()
	if u == "" {
		t.Fatal("No UUID generated")
	}
}
