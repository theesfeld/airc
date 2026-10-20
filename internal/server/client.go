package server

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ergochat/irc-go/ircmsg"
	"github.com/theesfeld/airc/internal/sasl"
)

// Client is one TCP connection.
type Client struct {
	srv  *Server
	conn interface {
		Read(b []byte) (int, error)
		Write(b []byte) (int, error)
		Close() error
		SetReadDeadline(t time.Time) error
		SetWriteDeadline(t time.Time) error
	}
	ip  string
	out chan string

	closed chan struct{}
	once   sync.Once

	nick           string
	account        string
	real           string
	host           string
	caps           map[string]bool
	registered     bool
	away           string
	capOpen        bool
	cap302         bool
	haveNick       bool
	haveUser       bool
	requestedNick  string
	saslOK         bool
	sawCAP         bool
	saslFails      int
	saslMech       string
	saslBuf        strings.Builder
	scram          *sasl.Convo
	saslUserExists bool
	channels       map[string]bool
	mu             sync.Mutex

	label        string
	labelReplies int
}

func (c *Client) readLoop() {
	defer c.srv.unregister(c)
	defer c.kill()
	r := bufio.NewReaderSize(c.conn, 8192)
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.readWait()))
		line, err := readLine(r, 8192)
		if err != nil {
			return
		}
		c.dispatchLine(line)
		if c.closedCh() {
			return
		}
	}
}

func (c *Client) readWait() time.Duration {
	if c.registered {
		return 180 * time.Second
	}
	return 30 * time.Second
}

func (c *Client) closedCh() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *Client) writeLoop() {
	defer func() { _ = c.conn.Close() }()
	for {
		select {
		case <-c.closed:
			c.drainOut()
			return
		case line := <-c.out:
			if !c.writeLine(line) {
				return
			}
		}
	}
}

func (c *Client) drainOut() {
	for {
		select {
		case line := <-c.out:
			if !c.writeLine(line) {
				return
			}
		default:
			return
		}
	}
}

func (c *Client) writeLine(line string) bool {
	_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(c.conn, line); err != nil {
		c.kill()
		return false
	}
	return true
}

func (c *Client) pingLoop() {
	t := time.NewTicker(90 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-c.srv.ctx.Done():
			c.kill()
			return
		case <-t.C:
			c.enqueue("PING :" + c.srv.cfg.Server.Name)
		}
	}
}

func (c *Client) kill() {
	c.once.Do(func() {
		close(c.closed)
	})
}

func (c *Client) quit(reason string) {
	if reason == "" {
		reason = "Closing link"
	}
	c.enqueue("ERROR :Closing link: " + cleanLine(reason))
	c.kill()
}

func (c *Client) enqueue(line string) {
	if !strings.HasSuffix(line, "\r\n") {
		line += "\r\n"
	}
	select {
	case <-c.closed:
	case c.out <- line:
	default:
		c.kill()
	}
}

func readLine(r *bufio.Reader, max int) (string, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return strings.TrimRight(string(buf), "\r"), nil
		}
		if b == 0 {
			return "", errors.New("nul")
		}
		buf = append(buf, b)
		if len(buf) > max {
			return "", errors.New("line too long")
		}
	}
}

func (c *Client) dispatchLine(line string) {
	msg, err := ircmsg.ParseLineStrict(line, true, 512)
	if err != nil {
		if errors.Is(err, ircmsg.ErrorBodyTooLong) || errors.Is(err, ircmsg.ErrorTagsTooLong) {
			if c.registered {
				c.reply(417, "Input line was too long")
			}
		}
		return
	}
	c.label = ""
	c.labelReplies = 0
	if c.caps["labeled-response"] {
		if ok, v := msg.GetTag("label"); ok {
			c.label = v
		}
	}
	c.handle(msg)
	c.endLabel()
}

func (c *Client) endLabel() {
	label := c.label
	n := c.labelReplies
	c.label = ""
	if label != "" && n == 0 {
		msg := ircmsg.MakeMessage(map[string]string{"label": label}, c.srv.cfg.Server.Name, "ACK")
		c.writeMsg(msg, false)
	}
}

func (c *Client) writeMsg(msg ircmsg.Message, countLabel bool) {
	if c.label != "" {
		if present, _ := msg.GetTag("label"); !present {
			msg.SetTag("label", c.label)
		}
		if countLabel {
			c.labelReplies++
		}
	}
	keepTags := c.caps["message-tags"] || c.caps["server-time"] || c.caps["account-tag"]
	if !keepTags {
		for name := range msg.AllTags() {
			if name == "label" && c.caps["labeled-response"] {
				continue
			}
			msg.DeleteTag(name)
		}
	}
	raw, err := msg.Line()
	if err != nil {
		return
	}
	c.enqueue(raw)
}

func (c *Client) send(command string, params ...string) {
	c.sendFrom(c.srv.cfg.Server.Name, command, params...)
}

func (c *Client) sendFrom(source, command string, params ...string) {
	tags := c.msgTags("")
	msg := ircmsg.MakeMessage(tags, source, command, params...)
	if len(params) > 0 {
		msg.ForceTrailing()
	}
	c.writeMsg(msg, true)
}

func (c *Client) reply(code int, params ...string) {
	all := append([]string{c.nickOrStar()}, params...)
	msg := ircmsg.MakeMessage(nil, c.srv.cfg.Server.Name, padCode(code), all...)
	msg.ForceTrailing()
	c.writeMsg(msg, true)
}

func (c *Client) nickOrStar() string {
	if c.nick == "" {
		return "*"
	}
	return c.nick
}

func padCode(code int) string {
	s := ""
	switch {
	case code < 10:
		s = "00"
	case code < 100:
		s = "0"
	}
	return s + itoa(code)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (c *Client) prefix() string {
	nick := c.nick
	if nick == "" {
		nick = c.requestedNick
	}
	if nick == "" {
		nick = c.account
	}
	if nick == "" {
		nick = "*"
	}
	user := c.account
	if user == "" {
		user = "user"
	}
	host := c.host
	if host == "" {
		host = "airc"
	}
	return nick + "!" + user + "@" + host
}

func (c *Client) joinMark(channel string) {
	c.mu.Lock()
	c.channels[fold(channel)] = true
	c.mu.Unlock()
}

func (c *Client) onChannel(channel string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.channels[fold(channel)]
}

func (c *Client) leaveMark(channel string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := fold(channel)
	if !c.channels[key] {
		return false
	}
	delete(c.channels, key)
	return true
}

func (c *Client) channelNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.channels))
	for ch := range c.channels {
		out = append(out, ch)
	}
	return out
}

func (c *Client) msgTags(msgid string) map[string]string {
	if !c.caps["message-tags"] && !c.caps["server-time"] && !c.caps["account-tag"] {
		return nil
	}
	tags := map[string]string{}
	if c.caps["server-time"] || c.caps["message-tags"] {
		tags["time"] = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if msgid == "" {
		msgid = "m" + randomHex(8)
	}
	if c.caps["message-tags"] {
		tags["msgid"] = msgid
	}
	return tags
}

func (c *Client) accountTag(account string) map[string]string {
	tags := c.msgTags("")
	if c.caps["account-tag"] {
		if tags == nil {
			tags = map[string]string{}
		}
		if account == "" {
			account = "*"
		}
		tags["account"] = account
	}
	return tags
}

func decodeB64(s string) ([]byte, error) {
	if s == "" || s == "+" {
		return nil, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func encodeAuth(payload string) []string {
	if payload == "" {
		return []string{"+"}
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	var out []string
	for len(b64) > 400 {
		out = append(out, b64[:400])
		b64 = b64[400:]
	}
	out = append(out, b64)
	if len(out[len(out)-1]) == 400 {
		out = append(out, "+")
	}
	return out
}
