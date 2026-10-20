// Package store is the SQLite state for accounts, AI nicks, sessions, and transcripts.
package store

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theesfeld/airc/internal/sasl"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrExists is returned when a name is already taken.
var ErrExists = errors.New("store: already exists")

// User is a SASL account.
type User struct {
	ID    int64
	Name  string
	Role  string
	Creds sasl.Credentials
}

// AI is a server-owned nick backed by a provider.
type AI struct {
	ID       int64
	Nick     string
	Provider string
	Model    string
	BaseURL  string
	Secret   []byte
	Created  time.Time
}

// Session is one private conversation channel.
type Session struct {
	ID      int64
	OwnerID int64
	Owner   string
	AIID    int64
	AINick  string
	Channel string
	Created time.Time
}

// Message is one line in a session transcript.
type Message struct {
	ID      int64
	Sender  string
	Body    string
	Created time.Time
}

// Store is one SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=rwc"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	_, err := s.db.Exec(`
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('admin','member')),
  salt BLOB NOT NULL,
  iterations INTEGER NOT NULL,
  stored_key BLOB NOT NULL,
  server_key BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ais (
  id INTEGER PRIMARY KEY,
  nick TEXT NOT NULL,
  nick_fold TEXT NOT NULL UNIQUE,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  base_url TEXT NOT NULL,
  secret BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  ai_id INTEGER NOT NULL REFERENCES ais(id),
  channel TEXT NOT NULL,
  channel_fold TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  closed_at INTEGER
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  session_id INTEGER NOT NULL REFERENCES sessions(id),
  sender TEXT NOT NULL CHECK (sender IN ('user','ai')),
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_session ON messages(session_id, id);
`)
	if err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err = s.db.Exec(`INSERT INTO schema_version(version) VALUES (1)`)
	}
	return err
}

// CreateUser inserts an account. Name is stored lowercase.
func (s *Store) CreateUser(name, role string, creds sasl.Credentials) error {
	name = strings.ToLower(name)
	_, err := s.db.Exec(`INSERT INTO users(name, role, salt, iterations, stored_key, server_key, created_at)
		VALUES(?,?,?,?,?,?,?)`, name, role, creds.Salt, creds.Iterations, creds.StoredKey, creds.ServerKey, now())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrExists
	}
	return err
}

// UserByName loads an account. The name match is case-insensitive.
func (s *Store) UserByName(name string) (User, error) {
	var u User
	err := s.db.QueryRow(`SELECT id, name, role, salt, iterations, stored_key, server_key FROM users WHERE name = ?`, strings.ToLower(name)).
		Scan(&u.ID, &u.Name, &u.Role, &u.Creds.Salt, &u.Creds.Iterations, &u.Creds.StoredKey, &u.Creds.ServerKey)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// ListUsers returns every account, admin first.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, name, role FROM users ORDER BY role, name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.Role); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetPassword replaces SCRAM material for an account.
func (s *Store) SetPassword(name string, creds sasl.Credentials) error {
	res, err := s.db.Exec(`UPDATE users SET salt=?, iterations=?, stored_key=?, server_key=? WHERE name=?`,
		creds.Salt, creds.Iterations, creds.StoredKey, creds.ServerKey, strings.ToLower(name))
	return rowsAffected(res, err)
}

// SetRole changes admin or member.
func (s *Store) SetRole(name, role string) error {
	res, err := s.db.Exec(`UPDATE users SET role=? WHERE name=?`, role, strings.ToLower(name))
	return rowsAffected(res, err)
}

// DeleteUser removes an account and its sessions.
func (s *Store) DeleteUser(name string) error {
	u, err := s.UserByName(name)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM messages WHERE session_id IN (SELECT id FROM sessions WHERE owner_id=?)`, u.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE owner_id=?`, u.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id=?`, u.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// AdminCount returns how many admin accounts exist.
func (s *Store) AdminCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n)
	return n, err
}

// UserCount returns how many accounts exist.
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateAI inserts a provider-backed nick.
func (s *Store) CreateAI(ai AI) error {
	_, err := s.db.Exec(`INSERT INTO ais(nick, nick_fold, provider, model, base_url, secret, created_at)
		VALUES(?,?,?,?,?,?,?)`, ai.Nick, fold(ai.Nick), ai.Provider, ai.Model, ai.BaseURL, ai.Secret, now())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrExists
	}
	return err
}

// AIByNick loads an AI nick.
func (s *Store) AIByNick(nick string) (AI, error) {
	var ai AI
	var created int64
	err := s.db.QueryRow(`SELECT id, nick, provider, model, base_url, secret, created_at FROM ais WHERE nick_fold=?`, fold(nick)).
		Scan(&ai.ID, &ai.Nick, &ai.Provider, &ai.Model, &ai.BaseURL, &ai.Secret, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return AI{}, ErrNotFound
	}
	ai.Created = time.UnixMilli(created)
	return ai, err
}

// ListAIs returns every AI nick.
func (s *Store) ListAIs() ([]AI, error) {
	rows, err := s.db.Query(`SELECT id, nick, provider, model, base_url, created_at FROM ais ORDER BY nick_fold`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AI
	for rows.Next() {
		var ai AI
		var created int64
		if err := rows.Scan(&ai.ID, &ai.Nick, &ai.Provider, &ai.Model, &ai.BaseURL, &created); err != nil {
			return nil, err
		}
		ai.Created = time.UnixMilli(created)
		out = append(out, ai)
	}
	return out, rows.Err()
}

// UpdateAI updates model, base URL, or secret. Empty fields keep the current value.
func (s *Store) UpdateAI(nick, model, baseURL string, secret []byte) error {
	ai, err := s.AIByNick(nick)
	if err != nil {
		return err
	}
	if model == "" {
		model = ai.Model
	}
	if baseURL == "" {
		baseURL = ai.BaseURL
	}
	if secret == nil {
		secret = ai.Secret
	}
	_, err = s.db.Exec(`UPDATE ais SET model=?, base_url=?, secret=? WHERE id=?`, model, baseURL, secret, ai.ID)
	return err
}

// DeleteAI removes a nick and every session that used it.
func (s *Store) DeleteAI(nick string) error {
	ai, err := s.AIByNick(nick)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM messages WHERE session_id IN (SELECT id FROM sessions WHERE ai_id=?)`, ai.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE ai_id=?`, ai.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ais WHERE id=?`, ai.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSession opens a conversation channel.
func (s *Store) CreateSession(owner, aiNick, channel string) (Session, error) {
	u, err := s.UserByName(owner)
	if err != nil {
		return Session{}, err
	}
	ai, err := s.AIByNick(aiNick)
	if err != nil {
		return Session{}, err
	}
	res, err := s.db.Exec(`INSERT INTO sessions(owner_id, ai_id, channel, channel_fold, created_at) VALUES(?,?,?,?,?)`,
		u.ID, ai.ID, channel, fold(channel), now())
	if err != nil {
		return Session{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Session{}, err
	}
	return s.SessionByID(id)
}

// SessionByChannel loads an open or closed session.
func (s *Store) SessionByChannel(channel string) (Session, error) {
	return s.scanSession(`WHERE s.channel_fold=?`, fold(channel))
}

// SessionByID loads a session.
func (s *Store) SessionByID(id int64) (Session, error) {
	return s.scanSession(`WHERE s.id=?`, id)
}

func (s *Store) scanSession(where string, arg any) (Session, error) {
	q := `SELECT s.id, s.owner_id, u.name, s.ai_id, a.nick, s.channel, s.created_at
		FROM sessions s JOIN users u ON u.id=s.owner_id JOIN ais a ON a.id=s.ai_id ` + where
	var sess Session
	var created int64
	err := s.db.QueryRow(q, arg).Scan(&sess.ID, &sess.OwnerID, &sess.Owner, &sess.AIID, &sess.AINick, &sess.Channel, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	sess.Created = time.UnixMilli(created)
	return sess, err
}

// LatestOpenSession returns the newest open session for an account and AI nick.
func (s *Store) LatestOpenSession(owner, aiNick string) (Session, error) {
	q := `SELECT s.id, s.owner_id, u.name, s.ai_id, a.nick, s.channel, s.created_at
		FROM sessions s JOIN users u ON u.id=s.owner_id JOIN ais a ON a.id=s.ai_id
		WHERE u.name=? AND a.nick_fold=? AND s.closed_at IS NULL ORDER BY s.id DESC LIMIT 1`
	var sess Session
	var created int64
	err := s.db.QueryRow(q, strings.ToLower(owner), fold(aiNick)).Scan(&sess.ID, &sess.OwnerID, &sess.Owner, &sess.AIID, &sess.AINick, &sess.Channel, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	sess.Created = time.UnixMilli(created)
	return sess, err
}

// OpenSessions returns the account's open sessions.
func (s *Store) OpenSessions(owner string) ([]Session, error) {
	rows, err := s.db.Query(`SELECT s.id, s.owner_id, u.name, s.ai_id, a.nick, s.channel, s.created_at
		FROM sessions s JOIN users u ON u.id=s.owner_id JOIN ais a ON a.id=s.ai_id
		WHERE u.name=? AND s.closed_at IS NULL ORDER BY s.id`, strings.ToLower(owner))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanSessions(rows)
}

// AllOpenSessions returns every session that is still open.
func (s *Store) AllOpenSessions() ([]Session, error) {
	rows, err := s.db.Query(`SELECT s.id, s.owner_id, u.name, s.ai_id, a.nick, s.channel, s.created_at
		FROM sessions s JOIN users u ON u.id=s.owner_id JOIN ais a ON a.id=s.ai_id
		WHERE s.closed_at IS NULL ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanSessions(rows)
}

// SessionsByAI returns open sessions for an AI nick.
func (s *Store) SessionsByAI(aiNick string) ([]Session, error) {
	rows, err := s.db.Query(`SELECT s.id, s.owner_id, u.name, s.ai_id, a.nick, s.channel, s.created_at
		FROM sessions s JOIN users u ON u.id=s.owner_id JOIN ais a ON a.id=s.ai_id
		WHERE a.nick_fold=? AND s.closed_at IS NULL ORDER BY s.id`, fold(aiNick))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanSessions(rows)
}

func scanSessions(rows *sql.Rows) ([]Session, error) {
	var out []Session
	for rows.Next() {
		var sess Session
		var created int64
		if err := rows.Scan(&sess.ID, &sess.OwnerID, &sess.Owner, &sess.AIID, &sess.AINick, &sess.Channel, &created); err != nil {
			return nil, err
		}
		sess.Created = time.UnixMilli(created)
		out = append(out, sess)
	}
	return out, rows.Err()
}

// CloseSession marks a session closed.
func (s *Store) CloseSession(id int64) error {
	res, err := s.db.Exec(`UPDATE sessions SET closed_at=? WHERE id=? AND closed_at IS NULL`, now(), id)
	return rowsAffected(res, err)
}

// IsOpen reports whether the session is still open.
func (s *Store) IsOpen(id int64) (bool, error) {
	var closed sql.NullInt64
	err := s.db.QueryRow(`SELECT closed_at FROM sessions WHERE id=?`, id).Scan(&closed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	return !closed.Valid, nil
}

// AddMessage appends a transcript line.
func (s *Store) AddMessage(sessionID int64, sender, body string) (Message, error) {
	created := now()
	res, err := s.db.Exec(`INSERT INTO messages(session_id, sender, body, created_at) VALUES(?,?,?,?)`, sessionID, sender, body, created)
	if err != nil {
		return Message{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Message{}, err
	}
	return Message{ID: id, Sender: sender, Body: body, Created: time.UnixMilli(created)}, nil
}

// RecentMessages returns up to limit messages in chronological order.
func (s *Store) RecentMessages(sessionID int64, limit int) ([]Message, error) {
	rows, err := s.db.Query(`SELECT id, sender, body, created_at FROM messages
		WHERE session_id=? ORDER BY id DESC LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var rev []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		rev = append(rev, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanMessage(rows scanner) (Message, error) {
	var m Message
	var created int64
	if err := rows.Scan(&m.ID, &m.Sender, &m.Body, &created); err != nil {
		return Message{}, err
	}
	m.Created = time.UnixMilli(created)
	return m, nil
}

func rowsAffected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func now() int64 { return time.Now().UnixMilli() }

func fold(s string) string { return strings.ToLower(s) }
