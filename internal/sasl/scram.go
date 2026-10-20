// Package sasl implements the SASL mechanisms aIRC offers to IRC clients.
// PLAIN is verified by deriving the SCRAM-SHA-256 stored key from the
// candidate password. SCRAM-SHA-256 follows RFC 5802 and RFC 7677.
package sasl

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	MinIterations = 4096
	MaxIterations = 5_000_000
	KeyLen        = 32
)

var (
	ErrAuth       = errors.New("sasl: authentication failed")
	ErrMechanism  = errors.New("sasl: unsupported or malformed exchange")
	ErrIterations = errors.New("sasl: iteration count out of range")
)

// Credentials are the stored SCRAM-SHA-256 parameters for one account.
// The plaintext password is not stored.
type Credentials struct {
	Salt       []byte
	Iterations int
	StoredKey  []byte
	ServerKey  []byte
}

// NewCredentials creates a random salt and derives SCRAM keys from password.
func NewCredentials(password string, iterations int) (Credentials, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Credentials{}, err
	}
	return Derive(password, salt, iterations)
}

// Derive produces SCRAM keys for a known salt.
func Derive(password string, salt []byte, iterations int) (Credentials, error) {
	if iterations < MinIterations || iterations > MaxIterations {
		return Credentials{}, ErrIterations
	}
	if len(salt) < 8 {
		return Credentials{}, ErrMechanism
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, KeyLen)
	if err != nil {
		return Credentials{}, err
	}
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	sum := sha256.Sum256(clientKey)
	return Credentials{
		Salt:       append([]byte(nil), salt...),
		Iterations: iterations,
		StoredKey:  sum[:],
		ServerKey:  hmacSHA256(salted, []byte("Server Key")),
	}, nil
}

// Verify checks a plaintext password against stored SCRAM parameters.
// It is the PLAIN check. Cost is one PBKDF2, including for wrong passwords.
func (c Credentials) Verify(password string) bool {
	got, err := Derive(password, c.Salt, c.Iterations)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got.StoredKey, c.StoredKey) == 1
}

// Fake builds stable verifier material for a username that does not exist.
// The salt is a MAC of the server secret, so retries and restarts look like
// a real account and login failure does not reveal which names are registered.
func Fake(serverSecret []byte, username string, iterations int) Credentials {
	salt := mac(serverSecret, "airc sasl fake salt v1", username)[:16]
	return Credentials{
		Salt:       salt,
		Iterations: iterations,
		StoredKey:  mac(serverSecret, "airc sasl fake stored v1", username),
		ServerKey:  mac(serverSecret, "airc sasl fake server v1", username),
	}
}

func mac(key []byte, label, username string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(label))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write([]byte(username))
	return m.Sum(nil)
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}

// Convo is one SCRAM-SHA-256 server exchange.
type Convo struct {
	Username    string
	Creds       Credentials
	ServerNonce string // set in tests; generated when empty

	gs2         string
	bare        string
	fullNonce   string
	serverFirst string
}

// AcceptFirst consumes the client-first message and returns the server-first message.
func (c *Convo) AcceptFirst(clientFirst string) (string, error) {
	header, bare, err := splitGS2(clientFirst)
	if err != nil {
		return "", err
	}
	flag := header
	if i := strings.IndexByte(header, ','); i >= 0 {
		flag = header[:i]
	}
	// "n" is no support, "y" is the client does not use binding. Channel binding is refused.
	if flag != "n" && flag != "y" {
		return "", ErrMechanism
	}
	attrs := parseAttrs(bare)
	user, err := unescapeName(attrs["n"])
	if err != nil || user == "" || attrs["r"] == "" {
		return "", ErrMechanism
	}
	if user != c.Username {
		return "", ErrAuth
	}
	nonce := c.ServerNonce
	if nonce == "" {
		raw := make([]byte, 18)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		nonce = base64.RawURLEncoding.EncodeToString(raw)
	}
	if strings.ContainsAny(nonce, ",") {
		return "", ErrMechanism
	}
	c.gs2 = header
	c.bare = bare
	c.fullNonce = attrs["r"] + nonce
	c.serverFirst = "r=" + c.fullNonce + ",s=" + base64.StdEncoding.EncodeToString(c.Creds.Salt) + ",i=" + strconv.Itoa(c.Creds.Iterations)
	return c.serverFirst, nil
}

// AcceptFinal consumes the client-final message and returns the server-final message.
func (c *Convo) AcceptFinal(clientFinal string) (string, error) {
	if c.serverFirst == "" {
		return "", ErrMechanism
	}
	attrs := parseAttrs(clientFinal)
	if attrs["r"] != c.fullNonce {
		return "", ErrAuth
	}
	wantC := base64.StdEncoding.EncodeToString([]byte(c.gs2))
	if subtle.ConstantTimeCompare([]byte(attrs["c"]), []byte(wantC)) != 1 {
		return "", ErrAuth
	}
	proof, err := base64.StdEncoding.DecodeString(attrs["p"])
	if err != nil || len(proof) != KeyLen || len(c.Creds.StoredKey) != KeyLen {
		return "", ErrAuth
	}
	without := clientFinal
	if i := strings.LastIndex(clientFinal, ",p="); i >= 0 {
		without = clientFinal[:i]
	}
	authMsg := c.bare + "," + c.serverFirst + "," + without
	sig := hmacSHA256(c.Creds.StoredKey, []byte(authMsg))
	clientKey := make([]byte, KeyLen)
	for i := range clientKey {
		clientKey[i] = proof[i] ^ sig[i]
	}
	sum := sha256.Sum256(clientKey)
	if subtle.ConstantTimeCompare(sum[:], c.Creds.StoredKey) != 1 {
		return "", ErrAuth
	}
	serverSig := hmacSHA256(c.Creds.ServerKey, []byte(authMsg))
	return "v=" + base64.StdEncoding.EncodeToString(serverSig), nil
}

// splitGS2 splits a client-first message into the GS2 header (including the
// comma that terminates it) and the client-first-message-bare.
func splitGS2(first string) (header, bare string, err error) {
	i := strings.IndexByte(first, ',')
	if i < 0 {
		return "", "", ErrMechanism
	}
	j := strings.IndexByte(first[i+1:], ',')
	if j < 0 {
		return "", "", ErrMechanism
	}
	j += i + 1
	return first[:j+1], first[j+1:], nil
}

func parseAttrs(s string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func unescapeName(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '=' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("sasl: bad escaped username")
		}
		switch s[i : i+3] {
		case "=2C":
			b.WriteByte(',')
		case "=3D":
			b.WriteByte('=')
		default:
			return "", fmt.Errorf("sasl: bad escaped username")
		}
		i += 2
	}
	return b.String(), nil
}
