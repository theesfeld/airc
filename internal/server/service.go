package server

import (
	"fmt"
	"strings"

	"github.com/theesfeld/airc/internal/provider"
	"github.com/theesfeld/airc/internal/sasl"
	"github.com/theesfeld/airc/internal/secret"
	"github.com/theesfeld/airc/internal/store"
)

const minPassword = 12

func (s *Server) service(c *Client, text string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		s.help(c)
		return
	}
	if strings.HasPrefix(fields[0], "/") {
		fields[0] = strings.TrimPrefix(fields[0], "/")
	}
	cmd := strings.ToLower(fields[0])
	switch cmd {
	case "help":
		s.help(c)
	case "passwd":
		s.cmdPasswd(c, fields)
	case "session":
		s.cmdSession(c, fields)
	case "ai":
		s.cmdAI(c, fields)
	case "user":
		s.cmdUserAdmin(c, fields)
	default:
		c.notice(servicePrefix, "Unknown command. Send: help")
	}
}

func (s *Server) help(c *Client) {
	lines := []string{
		"aIRC commands are sent to the airc nick. Example: /msg airc help",
		"session new <ai>             open a private channel with an AI nick",
		"session list                  list your open sessions",
		"session close <#channel>      end a session",
		"passwd <new-password>         change your SASL password",
		"Messaging an AI nick opens or continues your latest session with it.",
	}
	if s.isAdmin(c.account) {
		lines = append(lines,
			"ai list",
			"ai add <nick> openai <model> <https-url> <api-key>",
			"ai add <nick> grok <model> <api-key>     xAI, including grok-build-0.1",
			"ai edit <nick> model <model>",
			"ai edit <nick> url <https-url>",
			"ai edit <nick> key <api-key>",
			"ai rm <nick>",
			"user list",
			"user add <account> <password>",
			"user passwd <account> <password>",
			"user role <account> admin|member",
			"user rm <account>",
		)
	}
	for _, line := range lines {
		c.notice(servicePrefix, line)
	}
}

func (s *Server) isAdmin(account string) bool {
	u, err := s.store.UserByName(account)
	return err == nil && u.Role == "admin"
}

func (s *Server) requireAdmin(c *Client) bool {
	if s.isAdmin(c.account) {
		return true
	}
	c.notice(servicePrefix, "That command requires an admin account.")
	return false
}

func (s *Server) cmdPasswd(c *Client, f []string) {
	if len(f) != 2 {
		c.notice(servicePrefix, "Usage: passwd <new-password>")
		return
	}
	if err := s.setPassword(c.account, f[1]); err != nil {
		c.notice(servicePrefix, err.Error())
		return
	}
	c.notice(servicePrefix, "Password updated.")
}

func (s *Server) setPassword(account, password string) error {
	if len(password) < minPassword {
		return fmt.Errorf("password must be at least %d characters", minPassword)
	}
	if len(password) > 256 {
		return fmt.Errorf("password is too long")
	}
	creds, err := sasl.NewCredentials(password, s.cfg.Limits.SCRAMIterations)
	if err != nil {
		return fmt.Errorf("could not store that password")
	}
	if err := s.store.SetPassword(account, creds); err != nil {
		return fmt.Errorf("could not store that password")
	}
	return nil
}

func (s *Server) cmdSession(c *Client, f []string) {
	if len(f) < 2 {
		c.notice(servicePrefix, "Usage: session new <ai> | session list | session close <#channel>")
		return
	}
	switch strings.ToLower(f[1]) {
	case "new":
		if len(f) != 3 {
			c.notice(servicePrefix, "Usage: session new <ai>")
			return
		}
		ai, err := s.store.AIByNick(f[2])
		if err != nil {
			c.notice(servicePrefix, "No AI nick is named "+f[2]+".")
			return
		}
		sess, err := s.openSession(c.account, ai)
		if err != nil {
			c.notice(servicePrefix, "Could not open a session.")
			s.log.Error("session", "err", err)
			return
		}
		s.joinBurst(c, sess, false)
		c.notice(servicePrefix, "Session with "+ai.Nick+" is "+sess.Channel)
	case "list":
		sessions, err := s.store.OpenSessions(c.account)
		if err != nil || len(sessions) == 0 {
			c.notice(servicePrefix, "You have no open sessions.")
			return
		}
		for _, sess := range sessions {
			c.notice(servicePrefix, sess.Channel+"  "+sess.AINick)
		}
	case "close":
		if len(f) != 3 {
			c.notice(servicePrefix, "Usage: session close <#channel>")
			return
		}
		sess, ok := s.visibleSession(c, f[2])
		if !ok && s.isAdmin(c.account) {
			if found, err := s.store.SessionByChannel(f[2]); err == nil {
				sess, ok = found, true
			}
		}
		if !ok {
			c.notice(servicePrefix, "No open session named "+f[2]+".")
			return
		}
		open, err := s.store.IsOpen(sess.ID)
		if err != nil || !open {
			c.notice(servicePrefix, "That session is already closed.")
			return
		}
		s.shutdownSession(sess, "Session closed")
		c.notice(servicePrefix, "Closed "+sess.Channel)
	default:
		c.notice(servicePrefix, "Usage: session new <ai> | session list | session close <#channel>")
	}
}

func (s *Server) cmdAI(c *Client, f []string) {
	if !s.requireAdmin(c) {
		return
	}
	if len(f) < 2 {
		c.notice(servicePrefix, "Usage: ai list | ai add | ai edit | ai rm")
		return
	}
	switch strings.ToLower(f[1]) {
	case "list":
		ais, err := s.store.ListAIs()
		if err != nil || len(ais) == 0 {
			c.notice(servicePrefix, "No AI nicks are configured.")
			return
		}
		for _, ai := range ais {
			c.notice(servicePrefix, fmt.Sprintf("%s provider=%s model=%s url=%s key=set", ai.Nick, ai.Provider, ai.Model, ai.BaseURL))
		}
	case "add":
		s.addAI(c, f)
	case "edit":
		s.editAI(c, f)
	case "rm", "remove", "del", "delete":
		if len(f) != 3 {
			c.notice(servicePrefix, "Usage: ai rm <nick>")
			return
		}
		sessions, _ := s.store.SessionsByAI(f[2])
		for _, sess := range sessions {
			s.shutdownSession(sess, "AI removed")
		}
		if err := s.store.DeleteAI(f[2]); err != nil {
			c.notice(servicePrefix, "No AI nick is named "+f[2]+".")
			return
		}
		c.notice(servicePrefix, "Removed "+f[2]+".")
	default:
		c.notice(servicePrefix, "Usage: ai list | ai add | ai edit | ai rm")
	}
}

func (s *Server) addAI(c *Client, f []string) {
	if len(f) < 5 {
		c.notice(servicePrefix, "Usage: ai add <nick> openai <model> <url> <api-key>")
		c.notice(servicePrefix, "Usage: ai add <nick> grok <model> <api-key>")
		return
	}
	nick := f[2]
	kind := strings.ToLower(f[3])
	if !validName(nick) || reserved(nick) {
		c.notice(servicePrefix, "AI nick must be 1-32 letters, digits, underscore, or hyphen, and not a reserved name.")
		return
	}
	if _, err := s.store.UserByName(nick); err == nil {
		c.notice(servicePrefix, "That name is already an account.")
		return
	}
	var model, base, key string
	switch kind {
	case provider.ProviderOpenAI:
		if len(f) != 7 {
			c.notice(servicePrefix, "Usage: ai add <nick> openai <model> <url> <api-key>")
			return
		}
		model, base, key = f[4], f[5], f[6]
	case provider.ProviderGrok:
		if len(f) != 6 {
			c.notice(servicePrefix, "Usage: ai add <nick> grok <model> <api-key>")
			return
		}
		model, key = f[4], f[5]
		base = provider.GrokBaseURL
	default:
		c.notice(servicePrefix, "Provider must be openai or grok.")
		return
	}
	if err := validateModel(model); err != nil {
		c.notice(servicePrefix, err.Error())
		return
	}
	if err := provider.ValidateBaseURL(base); err != nil {
		c.notice(servicePrefix, err.Error())
		return
	}
	if key == "" || len(key) > 512 {
		c.notice(servicePrefix, "The API key is missing or too long.")
		return
	}
	sealed, err := secret.Seal(s.key, []byte(key))
	if err != nil {
		c.notice(servicePrefix, "Could not store that credential.")
		return
	}
	err = s.store.CreateAI(store.AI{
		Nick: nick, Provider: kind, Model: model, BaseURL: base, Secret: sealed,
	})
	if err != nil {
		c.notice(servicePrefix, "That AI nick already exists.")
		return
	}
	c.notice(servicePrefix, "Added "+nick+" ("+kind+", "+model+").")
}

func (s *Server) editAI(c *Client, f []string) {
	if len(f) < 5 {
		c.notice(servicePrefix, "Usage: ai edit <nick> model|url|key <value>")
		return
	}
	nick, field, value := f[2], strings.ToLower(f[3]), f[4]
	ai, err := s.store.AIByNick(nick)
	if err != nil {
		c.notice(servicePrefix, "No AI nick is named "+nick+".")
		return
	}
	switch field {
	case "model":
		if err := validateModel(value); err != nil {
			c.notice(servicePrefix, err.Error())
			return
		}
		if err := s.store.UpdateAI(ai.Nick, value, "", nil); err != nil {
			c.notice(servicePrefix, "Could not update that AI.")
			return
		}
	case "url":
		if err := provider.ValidateBaseURL(value); err != nil {
			c.notice(servicePrefix, err.Error())
			return
		}
		if err := s.store.UpdateAI(ai.Nick, "", value, nil); err != nil {
			c.notice(servicePrefix, "Could not update that AI.")
			return
		}
	case "key":
		if value == "" || len(value) > 512 {
			c.notice(servicePrefix, "The API key is missing or too long.")
			return
		}
		sealed, err := secret.Seal(s.key, []byte(value))
		if err != nil {
			c.notice(servicePrefix, "Could not store that credential.")
			return
		}
		if err := s.store.UpdateAI(ai.Nick, "", "", sealed); err != nil {
			c.notice(servicePrefix, "Could not update that AI.")
			return
		}
	default:
		c.notice(servicePrefix, "Usage: ai edit <nick> model|url|key <value>")
		return
	}
	c.notice(servicePrefix, "Updated "+ai.Nick+".")
}

func validateModel(model string) error {
	if model == "" || len(model) > 128 || strings.ContainsAny(model, " \r\n\t") {
		return fmt.Errorf("model name is invalid")
	}
	return nil
}

func (s *Server) cmdUserAdmin(c *Client, f []string) {
	if !s.requireAdmin(c) {
		return
	}
	if len(f) < 2 {
		c.notice(servicePrefix, "Usage: user list | user add | user passwd | user role | user rm")
		return
	}
	switch strings.ToLower(f[1]) {
	case "list":
		users, err := s.store.ListUsers()
		if err != nil {
			c.notice(servicePrefix, "Could not list accounts.")
			return
		}
		for _, u := range users {
			c.notice(servicePrefix, u.Name+"  "+u.Role)
		}
	case "add":
		if len(f) != 4 {
			c.notice(servicePrefix, "Usage: user add <account> <password>")
			return
		}
		s.addUser(c, f[2], f[3], "member")
	case "passwd":
		if len(f) != 4 {
			c.notice(servicePrefix, "Usage: user passwd <account> <password>")
			return
		}
		if _, err := s.store.UserByName(f[2]); err != nil {
			c.notice(servicePrefix, "No account is named "+f[2]+".")
			return
		}
		if err := s.setPassword(strings.ToLower(f[2]), f[3]); err != nil {
			c.notice(servicePrefix, err.Error())
			return
		}
		c.notice(servicePrefix, "Password updated for "+strings.ToLower(f[2])+".")
	case "role":
		s.setRole(c, f)
	case "rm", "remove", "del", "delete":
		if len(f) != 3 {
			c.notice(servicePrefix, "Usage: user rm <account>")
			return
		}
		s.removeUser(c, f[2])
	default:
		c.notice(servicePrefix, "Usage: user list | user add | user passwd | user role | user rm")
	}
}

func (s *Server) addUser(c *Client, name, password, role string) {
	name = strings.ToLower(name)
	if !validName(name) || reserved(name) {
		c.notice(servicePrefix, "Account name must be 1-32 letters, digits, underscore, or hyphen.")
		return
	}
	if _, err := s.store.AIByNick(name); err == nil {
		c.notice(servicePrefix, "That name is already an AI nick.")
		return
	}
	if len(password) < minPassword {
		c.notice(servicePrefix, fmt.Sprintf("Password must be at least %d characters.", minPassword))
		return
	}
	creds, err := sasl.NewCredentials(password, s.cfg.Limits.SCRAMIterations)
	if err != nil {
		c.notice(servicePrefix, "Could not store that password.")
		return
	}
	if err := s.store.CreateUser(name, role, creds); err != nil {
		c.notice(servicePrefix, "That account already exists.")
		return
	}
	c.notice(servicePrefix, "Added account "+name+".")
}

func (s *Server) setRole(c *Client, f []string) {
	if len(f) != 4 {
		c.notice(servicePrefix, "Usage: user role <account> admin|member")
		return
	}
	name := strings.ToLower(f[2])
	role := strings.ToLower(f[3])
	if role != "admin" && role != "member" {
		c.notice(servicePrefix, "Role must be admin or member.")
		return
	}
	user, err := s.store.UserByName(name)
	if err != nil {
		c.notice(servicePrefix, "No account is named "+name+".")
		return
	}
	if user.Role == "admin" && role != "admin" {
		n, err := s.store.AdminCount()
		if err != nil || n <= 1 {
			c.notice(servicePrefix, "The last admin cannot be demoted.")
			return
		}
	}
	if err := s.store.SetRole(name, role); err != nil {
		c.notice(servicePrefix, "Could not change that role.")
		return
	}
	c.notice(servicePrefix, name+" is now "+role+".")
}

func (s *Server) removeUser(c *Client, name string) {
	name = strings.ToLower(name)
	if name == c.account {
		c.notice(servicePrefix, "Use another admin account to remove yourself.")
		return
	}
	user, err := s.store.UserByName(name)
	if err != nil {
		c.notice(servicePrefix, "No account is named "+name+".")
		return
	}
	if user.Role == "admin" {
		n, err := s.store.AdminCount()
		if err != nil || n <= 1 {
			c.notice(servicePrefix, "The last admin cannot be removed.")
			return
		}
	}
	sessions, _ := s.store.OpenSessions(name)
	for _, sess := range sessions {
		s.shutdownSession(sess, "Account removed")
	}
	if other := s.client(name); other != nil {
		other.quit("Account removed")
	}
	if err := s.store.DeleteUser(name); err != nil {
		c.notice(servicePrefix, "Could not remove that account.")
		return
	}
	c.notice(servicePrefix, "Removed account "+name+".")
}
