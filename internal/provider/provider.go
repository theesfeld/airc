// Package provider calls OpenAI-compatible chat completion endpoints.
// The grok provider is that API with the xAI base URL fixed.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// ProviderOpenAI is any OpenAI-compatible HTTP endpoint.
	ProviderOpenAI = "openai"
	// ProviderGrok is the xAI API, including the grok-build model.
	ProviderGrok = "grok"
	// GrokBaseURL is the OpenAI-compatible xAI endpoint.
	GrokBaseURL = "https://api.x.ai/v1"
)

// ChatMessage is one turn sent to a provider.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Backend is one configured model and credential.
type Backend struct {
	Provider string
	Model    string
	BaseURL  string
	APIKey   string
}

// Completer produces a single assistant reply.
type Completer interface {
	Complete(ctx context.Context, backend Backend, messages []ChatMessage) (string, error)
}

// HTTP completes a chat against an OpenAI-compatible endpoint.
type HTTP struct {
	Client *http.Client
}

// NewHTTP returns a client that refuses redirects and blocks unsafe addresses.
func NewHTTP(timeout time.Duration) *HTTP {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&guardDialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &HTTP{Client: &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
			Refusal string `json:"refusal"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete posts one non-streaming chat completion.
func (h *HTTP) Complete(ctx context.Context, backend Backend, messages []ChatMessage) (string, error) {
	if err := ValidateBaseURL(backend.BaseURL); err != nil {
		return "", err
	}
	if backend.Model == "" || backend.APIKey == "" {
		return "", errors.New("provider: model and key are required")
	}
	body, err := json.Marshal(chatRequest{Model: backend.Model, Messages: messages, Stream: false})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint(backend.BaseURL), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+backend.APIKey)
	req.Header.Set("User-Agent", "aIRC")
	client := h.Client
	if client == nil {
		client = NewHTTP(180 * time.Second).Client
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("provider: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", fmt.Errorf("provider: response was unreadable")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("provider: upstream returned %d", resp.StatusCode)
	}
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("provider: response was not a chat completion")
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return "", fmt.Errorf("provider: upstream rejected the request")
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("provider: upstream returned no choices")
	}
	text := parsed.Choices[0].Message.Content
	if text == "" && parsed.Choices[0].Message.Refusal != "" {
		return "", errors.New("provider: the model refused the request")
	}
	return text, nil
}

func endpoint(base string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, "/chat/completions") {
		return base
	}
	return base + "/chat/completions"
}

// guardDialer checks every resolved address before connecting.
type guardDialer struct {
	Timeout   time.Duration
	KeepAlive time.Duration
}

func (g *guardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("provider: name did not resolve")
	}
	for _, ip := range ips {
		if !ipAllowed(ip.IP) {
			return nil, fmt.Errorf("provider: address %s is not allowed", ip.IP)
		}
	}
	d := net.Dialer{Timeout: g.Timeout, KeepAlive: g.KeepAlive}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}
