package config

import (
	"os"
	"testing"
)

func TestExampleMatchesTemplate(t *testing.T) {
	got, err := os.ReadFile("../../airc.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := Template("irc.example.com", ":6697", "data")
	if string(got) != want {
		t.Fatalf("airc.example.yaml does not match Template:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}
