package provider

import "testing"

func TestValidateBaseURL(t *testing.T) {
	ok := []string{
		"https://api.x.ai/v1",
		"https://api.openai.com/v1",
		"http://127.0.0.1:11434/v1",
		"http://localhost:11434/v1",
		"http://10.1.2.3:8000/v1",
		"http://192.168.1.9/v1",
	}
	for _, raw := range ok {
		if err := ValidateBaseURL(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	bad := []string{
		"http://169.254.169.254/latest",
		"http://example.com/v1",
		"http://metadata.google.internal/",
		"ftp://127.0.0.1/v1",
		"https://user:pass@api.example.com/v1",
		"",
	}
	for _, raw := range bad {
		if err := ValidateBaseURL(raw); err == nil {
			t.Errorf("%s was accepted", raw)
		}
	}
}

func TestEndpoint(t *testing.T) {
	if got := endpoint("https://api.x.ai/v1/"); got != "https://api.x.ai/v1/chat/completions" {
		t.Fatal(got)
	}
	if got := endpoint("https://example.com/v1/chat/completions"); got != "https://example.com/v1/chat/completions" {
		t.Fatal(got)
	}
}
