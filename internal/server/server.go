// Package server is the aIRC client protocol: TLS, mandatory SASL, and AI sessions.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/theesfeld/airc/internal/config"
	"github.com/theesfeld/airc/internal/provider"
	"github.com/theesfeld/airc/internal/store"
)

// Version is reported in VERSION and RPL_MYINFO.
const Version = "aIRC-0.1.0"

// Server is one aIRC process.
type Server struct {
	cfg   *config.File
	store *store.Store
	ai    provider.Completer
	key   []byte
	log   *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	ln  net.Listener
	tls *tls.Config

	mu      sync.Mutex
	clients map[string]*Client
	live    map[string]*liveSession
	conns   int
	fails   map[string]*strike
	wg      sync.WaitGroup
}

type strike struct {
	n     int
	until time.Time
}

type liveSession struct {
	rec    store.Session
	wake   chan struct{}
	cancel context.CancelFunc
	topic  string
}

// New builds a server. key is the 32-byte at-rest encryption key.
func New(cfg *config.File, st *store.Store, ai provider.Completer, key []byte, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if ai == nil {
		ai = provider.NewHTTP(cfg.Limits.ProviderTimeout)
	}
	cert, err := tls.LoadX509KeyPair(cfg.Server.Cert, cfg.Server.Key)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:     cfg,
		store:   st,
		ai:      ai,
		key:     append([]byte(nil), key...),
		log:     logger,
		ctx:     ctx,
		cancel:  cancel,
		clients: map[string]*Client{},
		live:    map[string]*liveSession{},
		fails:   map[string]*strike{},
		tls: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}
	sessions, err := st.AllOpenSessions()
	if err != nil {
		cancel()
		return nil, err
	}
	for _, sess := range sessions {
		s.startWorker(sess)
	}
	return s, nil
}

// Listen accepts TLS connections until Close.
func (s *Server) Listen() error {
	ln, err := tls.Listen("tcp", s.cfg.Server.Listen, s.tls)
	if err != nil {
		return err
	}
	s.ln = ln
	s.log.Info("listening", "addr", ln.Addr().String(), "name", s.cfg.Server.Name)
	go s.accept()
	return nil
}

// Addr is the bound address, set after Listen.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Close stops listeners, workers, and connections.
func (s *Server) Close() error {
	s.cancel()
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	s.mu.Lock()
	clients := make([]*Client, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	for _, ls := range s.live {
		ls.cancel()
	}
	s.mu.Unlock()
	for _, c := range clients {
		c.kill()
	}
	s.wg.Wait()
	return err
}

func (s *Server) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept", "err", err)
			continue
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if ip == "" {
		ip = conn.RemoteAddr().String()
	}
	if !s.admit(ip) {
		_, _ = conn.Write([]byte("ERROR :Closing link: too many connections\r\n"))
		_ = conn.Close()
		return
	}
	defer s.release()
	c := &Client{
		srv:      s,
		conn:     conn,
		ip:       ip,
		out:      make(chan string, 512),
		closed:   make(chan struct{}),
		caps:     map[string]bool{},
		channels: map[string]bool{},
	}
	go c.writeLoop()
	go c.pingLoop()
	c.readLoop()
}

func (s *Server) admit(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.fails[ip]; st != nil && time.Now().Before(st.until) {
		return false
	}
	if s.conns >= s.cfg.Limits.MaxConnections {
		return false
	}
	s.conns++
	return true
}

func (s *Server) release() {
	s.mu.Lock()
	s.conns--
	s.mu.Unlock()
}

func (s *Server) strike(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.fails[ip]
	if st == nil {
		st = &strike{}
		s.fails[ip] = st
	}
	st.n++
	if st.n >= s.cfg.Limits.AuthFailures {
		st.until = time.Now().Add(s.cfg.Limits.AuthBan)
		st.n = 0
		s.log.Warn("auth ban", "ip", ip, "until", st.until.Format(time.RFC3339))
	}
}

func (s *Server) clearStrikes(ip string) {
	s.mu.Lock()
	delete(s.fails, ip)
	s.mu.Unlock()
}

func (s *Server) publish(c *Client) {
	s.mu.Lock()
	old := s.clients[c.account]
	s.clients[c.account] = c
	s.mu.Unlock()
	if old != nil && old != c {
		old.quit("Logged in from another connection")
	}
}

func (s *Server) unregister(c *Client) {
	if c.account == "" {
		return
	}
	s.mu.Lock()
	if s.clients[c.account] == c {
		delete(s.clients, c.account)
	}
	s.mu.Unlock()
}

func (s *Server) client(account string) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[account]
}

func (s *Server) saslSecret() []byte { return s.key }

// randomToken returns n bytes of hex. n is the number of random bytes.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
