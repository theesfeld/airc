package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theesfeld/airc/internal/config"
	"github.com/theesfeld/airc/internal/provider"
	"github.com/theesfeld/airc/internal/sasl"
	"github.com/theesfeld/airc/internal/secret"
	"github.com/theesfeld/airc/internal/store"
)

func TestSASLRequired(t *testing.T) {
	r := newRig(t, nil)
	c := r.dial()
	defer c.close()
	c.send("NICK admin")
	c.send("USER admin 0 * :Admin")
	lines := c.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "requires SASL")
	})
	if contains(lines, " 001 ") {
		t.Fatalf("registered without SASL:\n%s", strings.Join(lines, "\n"))
	}

	c = r.dial()
	defer c.close()
	c.send("PASS hunter2hunter2")
	c.send("NICK admin")
	c.send("USER admin 0 * :Admin")
	lines = c.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "requires SASL")
	})
	if contains(lines, " 001 ") {
		t.Fatalf("PASS authenticated:\n%s", strings.Join(lines, "\n"))
	}

	c = r.dial()
	defer c.close()
	c.send("CAP LS 302")
	c.send("CAP END")
	lines = c.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "requires SASL")
	})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "sasl=PLAIN,SCRAM-SHA-256") {
		t.Fatalf("CAP LS 302 missing mechanisms:\n%s", joined)
	}
	if contains(lines, " 001 ") {
		t.Fatalf("CAP END registered without SASL:\n%s", joined)
	}
}

func TestSASLPlainAndSCRAM(t *testing.T) {
	r := newRig(t, nil)

	bad := r.dial()
	defer bad.close()
	bad.send("CAP LS 302")
	bad.send("NICK admin")
	bad.send("USER admin 0 * :Admin")
	bad.send("CAP REQ :sasl")
	bad.send("AUTHENTICATE PLAIN")
	bad.send("AUTHENTICATE " + plainToken("admin", "wrong-password"))
	lines := bad.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, " 904 ")
	})
	if contains(lines, " 001 ") {
		t.Fatalf("bad password registered:\n%s", strings.Join(lines, "\n"))
	}
	bad.send("PING still-here")
	bad.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "PONG") && strings.Contains(line, "still-here")
	})

	unknown := r.dial()
	defer unknown.close()
	unknown.send("CAP LS 302")
	unknown.send("NICK ghost")
	unknown.send("USER ghost 0 * :Ghost")
	unknown.send("CAP REQ :sasl")
	unknown.send("AUTHENTICATE PLAIN")
	unknown.send("AUTHENTICATE " + plainToken("ghost", "wrong-password"))
	lines = unknown.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, " 904 ")
	})
	if strings.Contains(strings.Join(lines, "\n"), "No such") {
		t.Fatalf("unknown user was distinguishable:\n%s", strings.Join(lines, "\n"))
	}

	admin := r.dial()
	defer admin.close()
	lines = loginPlain(admin, "admin", adminPass)
	if !contains(lines, " 903 ") || !contains(lines, " 001 ") {
		t.Fatalf("PLAIN login failed:\n%s", strings.Join(lines, "\n"))
	}

	member := r.dial()
	defer member.close()
	lines = loginSCRAM(member, "member", memberPass)
	if !contains(lines, " 903 ") || !contains(lines, " 001 ") {
		t.Fatalf("SCRAM login failed:\n%s", strings.Join(lines, "\n"))
	}
}

func TestSessionPrivacyAndProvider(t *testing.T) {
	const apiKey = "sk-test-secret"
	var mu sync.Mutex
	var gotAuth, gotPath, gotAgent string
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotAgent = r.Header.Get("User-Agent")
		gotBody = body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"model says hello"}}]}`)
	}))
	defer upstream.Close()

	r := newRig(t, provider.NewHTTP(5*time.Second))
	admin := r.dial()
	defer admin.close()
	loginPlain(admin, "admin", adminPass)
	admin.send("PRIVMSG airc :ai add bot openai grok-build-0.1 " + upstream.URL + "/v1 " + apiKey)
	admin.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "Added bot")
	})
	admin.send("PRIVMSG airc :ai list")
	listed := admin.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "key=set")
	})
	if strings.Contains(strings.Join(listed, "\n"), apiKey) {
		t.Fatal("ai list echoed the API key")
	}

	admin.send("PRIVMSG bot :hello")
	session := admin.until(5*time.Second, func(line string) bool {
		return strings.Contains(line, "PRIVMSG") && strings.Contains(line, "model says hello")
	})
	channel := regexp.MustCompile(`#bot-[0-9a-f]{8}`).FindString(strings.Join(session, "\n"))
	if channel == "" {
		t.Fatalf("no session channel:\n%s", strings.Join(session, "\n"))
	}
	if !strings.Contains(strings.Join(session, "\n"), "bot!bot@bots.airc") {
		t.Fatalf("reply was not from the AI nick:\n%s", strings.Join(session, "\n"))
	}

	mu.Lock()
	auth, path, agent, body := gotAuth, gotPath, gotAgent, append([]byte(nil), gotBody...)
	mu.Unlock()
	if auth != "Bearer "+apiKey {
		t.Fatalf("authorization = %q", auth)
	}
	if path != "/v1/chat/completions" {
		t.Fatalf("path = %q", path)
	}
	if agent != "aIRC" {
		t.Fatalf("user agent = %q", agent)
	}
	var payload struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Model != "grok-build-0.1" || payload.Stream {
		t.Fatalf("payload model=%q stream=%v", payload.Model, payload.Stream)
	}
	if len(payload.Messages) < 2 || payload.Messages[len(payload.Messages)-1].Content != "hello" {
		t.Fatalf("messages = %#v", payload.Messages)
	}
	for _, m := range payload.Messages {
		if strings.Contains(m.Content, apiKey) {
			t.Fatal("provider request included the API key")
		}
	}
	if strings.Contains(r.logs.String(), apiKey) {
		t.Fatalf("log contained the API key:\n%s", r.logs.String())
	}
	if strings.Contains(strings.Join(session, "\n"), apiKey) {
		t.Fatal("server sent the API key back to the client")
	}

	member := r.dial()
	defer member.close()
	loginPlain(member, "member", memberPass)
	member.send("PRIVMSG airc :ai add other openai grok-build-0.1 " + upstream.URL + "/v1 " + apiKey)
	denied := member.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "requires an admin")
	})
	if strings.Contains(strings.Join(denied, "\n"), apiKey) || strings.Contains(r.logs.String(), apiKey) {
		t.Fatal("denied ai add leaked the API key")
	}
	member.send("JOIN " + channel)
	member.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, " 473 ")
	})
	member.send("LIST")
	listed = member.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "End of LIST")
	})
	if strings.Contains(strings.Join(listed, "\n"), channel) {
		t.Fatalf("LIST showed another user's session:\n%s", strings.Join(listed, "\n"))
	}
	member.send("WHOIS bot")
	whois := member.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "End of WHOIS")
	})
	if strings.Contains(strings.Join(whois, "\n"), channel) {
		t.Fatalf("WHOIS showed another user's session:\n%s", strings.Join(whois, "\n"))
	}
}

func TestModelTextCannotInjectIRC(t *testing.T) {
	script := &scriptAI{reply: "hel\x00lo\r\nQUIT :bye"}
	r := newRig(t, script)
	sealed, err := secret.Seal(r.key, []byte("local-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.st.CreateAI(store.AI{
		Nick: "bot", Provider: provider.ProviderOpenAI, Model: "grok-build-0.1",
		BaseURL: "http://127.0.0.1:9/v1", Secret: sealed,
	}); err != nil {
		t.Fatal(err)
	}
	c := r.dial()
	defer c.close()
	loginPlain(c, "admin", adminPass)
	c.send("PRIVMSG bot :hello")
	lines := c.until(5*time.Second, func(line string) bool {
		return strings.Contains(line, "QUIT :bye")
	})
	sawHello := false
	for _, line := range lines {
		if strings.Contains(line, "\x00") || strings.Contains(line, "\r") {
			t.Fatalf("control byte on the wire: %q", line)
		}
		fields := strings.Fields(stripPrefix(line))
		if len(fields) > 0 && fields[0] == "QUIT" {
			t.Fatalf("model text became a command: %q", line)
		}
		if strings.Contains(line, "PRIVMSG") && strings.Contains(line, ":hello") {
			sawHello = true
		}
	}
	if !sawHello {
		t.Fatalf("hello was not delivered inside PRIVMSG:\n%s", strings.Join(lines, "\n"))
	}
	c.send("PING after-injection")
	c.until(3*time.Second, func(line string) bool {
		return strings.Contains(line, "PONG") && strings.Contains(line, "after-injection")
	})
	sess, err := r.st.LatestOpenSession("admin", "bot")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := r.st.RecentMessages(sess.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) == 0 || !strings.Contains(msgs[len(msgs)-1].Body, "\r\nQUIT") {
		t.Fatalf("stored body = %#v", msgs)
	}
}

const (
	adminPass  = "admin-password-1"
	memberPass = "member-password-1"
)

type rig struct {
	t    *testing.T
	st   *store.Store
	srv  *Server
	key  []byte
	logs *bytes.Buffer
}

func newRig(t *testing.T, ai provider.Completer) *rig {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := writeCert(t, dir)
	cfg := &config.File{}
	cfg.Server.Name = "irc.test"
	cfg.Server.Network = "aIRC"
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.Cert = certPath
	cfg.Server.Key = keyPath
	cfg.Data.Directory = dir
	cfg.Limits.SCRAMIterations = 4096
	cfg.Limits.AuthFailures = 5
	cfg.Limits.AuthBan = time.Minute
	cfg.Limits.Replay = 100
	cfg.Limits.ContextMessages = 40
	cfg.Limits.ProviderTimeout = 5 * time.Second
	cfg.Limits.MaxConnections = 20

	st, err := store.Open(filepath.Join(dir, "airc.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct{ name, pass, role string }{
		{"admin", adminPass, "admin"},
		{"member", memberPass, "member"},
	} {
		creds, err := sasl.NewCredentials(u.pass, 4096)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.CreateUser(u.name, u.role, creds); err != nil {
			t.Fatal(err)
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	srv, err := New(cfg, st, ai, key, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = st.Close()
	})
	return &rig{t: t, st: st, srv: srv, key: key, logs: logs}
}

func (r *rig) dial() *ircConn {
	r.t.Helper()
	conn, err := tls.Dial("tcp", r.srv.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		r.t.Fatal(err)
	}
	c := &ircConn{t: r.t, conn: conn, lines: make(chan string, 1024), done: make(chan struct{})}
	go c.read()
	return c
}

type ircConn struct {
	t     *testing.T
	conn  net.Conn
	lines chan string
	done  chan struct{}
}

func (c *ircConn) close() { _ = c.conn.Close() }

func (c *ircConn) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.t.Fatalf("send %q: %v", line, err)
	}
}

func (c *ircConn) read() {
	defer close(c.done)
	r := bufio.NewReaderSize(c.conn, 8192)
	for {
		var buf []byte
		for {
			b, err := r.ReadByte()
			if err != nil {
				return
			}
			if b == '\n' {
				line := strings.TrimRight(string(buf), "\r")
				c.lines <- line
				break
			}
			buf = append(buf, b)
			if b == 0 {
				c.lines <- "NUL " + string(buf)
				return
			}
		}
	}
}

func (c *ircConn) next(timer <-chan time.Time) (string, bool) {
	select {
	case line := <-c.lines:
		return line, true
	default:
	}
	select {
	case line := <-c.lines:
		return line, true
	case <-c.done:
		select {
		case line := <-c.lines:
			return line, true
		default:
			return "", false
		}
	case <-timer:
		return "", false
	}
}

func (c *ircConn) until(d time.Duration, pred func(string) bool) []string {
	c.t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	var all []string
	for {
		line, ok := c.next(timer.C)
		if !ok {
			c.t.Fatalf("timed out or connection closed; got:\n%s", strings.Join(all, "\n"))
		}
		all = append(all, line)
		if pred(line) {
			return all
		}
	}
}

func loginPlain(c *ircConn, nick, password string) []string {
	c.send("CAP LS 302")
	c.send("NICK " + nick)
	c.send("USER " + nick + " 0 * :" + nick)
	c.send("CAP REQ :sasl")
	c.send("AUTHENTICATE PLAIN")
	c.send("AUTHENTICATE " + plainToken(nick, password))
	c.send("CAP END")
	return c.until(5*time.Second, func(line string) bool {
		return strings.Contains(line, " 001 ")
	})
}

func loginSCRAM(c *ircConn, nick, password string) []string {
	c.send("CAP LS 302")
	c.send("NICK " + nick)
	c.send("USER " + nick + " 0 * :" + nick)
	c.send("CAP REQ :sasl")
	c.send("AUTHENTICATE SCRAM-SHA-256")
	c.until(5*time.Second, func(line string) bool { return line == "AUTHENTICATE +" })
	nonce := "rOprNGfwEbeRWgbNEkqO"
	bare := "n=" + nick + ",r=" + nonce
	c.send("AUTHENTICATE " + base64.StdEncoding.EncodeToString([]byte("n,,"+bare)))
	var encoded string
	c.until(5*time.Second, func(line string) bool {
		if strings.HasPrefix(line, "AUTHENTICATE ") && line != "AUTHENTICATE +" {
			encoded = strings.TrimPrefix(line, "AUTHENTICATE ")
			return true
		}
		return false
	})
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		c.t.Fatal(err)
	}
	final, err := scramClientFinal(password, bare, string(raw))
	if err != nil {
		c.t.Fatal(err)
	}
	c.send("AUTHENTICATE " + base64.StdEncoding.EncodeToString([]byte(final)))
	c.send("CAP END")
	return c.until(5*time.Second, func(line string) bool {
		return strings.Contains(line, " 001 ")
	})
}

func plainToken(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
}

func scramClientFinal(password, bare, serverFirst string) (string, error) {
	attrs := map[string]string{}
	for _, part := range strings.Split(serverFirst, ",") {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			attrs[k] = v
		}
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil {
		return "", err
	}
	iter, err := strconv.Atoi(attrs["i"])
	if err != nil {
		return "", err
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return "", err
	}
	clientKey := macSHA256(salted, []byte("Client Key"))
	sum := sha256.Sum256(clientKey)
	gs2 := "n,,"
	channel := base64.StdEncoding.EncodeToString([]byte(gs2))
	without := "c=" + channel + ",r=" + attrs["r"]
	auth := bare + "," + serverFirst + "," + without
	sig := macSHA256(sum[:], []byte(auth))
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ sig[i]
	}
	return without + ",p=" + base64.StdEncoding.EncodeToString(proof), nil
}

func macSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}

func contains(lines []string, needle string) bool {
	return strings.Contains(strings.Join(lines, "\n"), needle)
}

func stripPrefix(line string) string {
	if strings.HasPrefix(line, "@") {
		_, line, _ = strings.Cut(line, " ")
	}
	if strings.HasPrefix(line, ":") {
		_, line, _ = strings.Cut(line, " ")
	}
	return line
}

type scriptAI struct {
	mu    sync.Mutex
	reply string
}

func (s *scriptAI) Complete(ctx context.Context, _ provider.Backend, _ []provider.ChatMessage) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reply, nil
}

func writeCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "irc.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"irc.test", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
