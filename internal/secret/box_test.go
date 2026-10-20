package secret

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	blob, err := Seal(key, []byte("sk-test"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("sk-test")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := Open(key, blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "sk-test" {
		t.Fatalf("got %q", got)
	}
	other := bytes.Repeat([]byte{8}, 32)
	if _, err := Open(other, blob); err == nil {
		t.Fatal("wrong key opened the box")
	}
}
