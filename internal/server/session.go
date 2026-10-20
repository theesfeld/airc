package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ergochat/irc-go/ircmsg"
	"github.com/theesfeld/airc/internal/provider"
	"github.com/theesfeld/airc/internal/secret"
	"github.com/theesfeld/airc/internal/store"
)

func (s *Server) replaySessions(c *Client) {
	sessions, err := s.store.OpenSessions(c.account)
	if err != nil {
		s.log.Error("sessions", "err", err, "account", c.account)
		return
	}
	for _, sess := range sessions {
		s.joinBurst(c, sess, true)
	}
}

func (s *Server) joinExisting(c *Client, channel string, replay bool) {
	sess, ok := s.visibleSession(c, channel)
	if !ok {
		c.reply(473, channel, "Cannot join channel (+i)")
		return
	}
	if c.onChannel(sess.Channel) {
		return
	}
	s.joinBurst(c, sess, replay)
}

func (s *Server) visibleSession(c *Client, channel string) (store.Session, bool) {
	sess, err := s.store.SessionByChannel(channel)
	if err != nil {
		return store.Session{}, false
	}
	open, err := s.store.IsOpen(sess.ID)
	if err != nil || !open || sess.Owner != c.account {
		return store.Session{}, false
	}
	return sess, true
}

func (s *Server) joinBurst(c *Client, sess store.Session, replay bool) {
	c.joinMark(sess.Channel)
	if c.caps["extended-join"] {
		c.sendFrom(c.prefix(), "JOIN", sess.Channel, c.account, c.real)
		c.sendFrom(aiPrefix(sess.AINick), "JOIN", sess.Channel, "*", "AI assistant")
	} else {
		c.sendFrom(c.prefix(), "JOIN", sess.Channel)
		c.sendFrom(aiPrefix(sess.AINick), "JOIN", sess.Channel)
	}
	c.send("MODE", sess.Channel, "+isnt")
	c.send("MODE", sess.Channel, "+o", c.nick)
	c.reply(353, "=", sess.Channel, "@"+c.nick+" "+sess.AINick)
	c.reply(366, sess.Channel, "End of /NAMES list")
	c.reply(332, sess.Channel, s.topic(sess))
	c.reply(333, sess.Channel, sess.AINick, fmt.Sprintf("%d", sess.Created.Unix()))
	c.reply(329, sess.Channel, fmt.Sprintf("%d", sess.Created.Unix()))
	if replay {
		s.replay(c, sess)
	}
}

func (s *Server) replay(c *Client, sess store.Session) {
	msgs, err := s.store.RecentMessages(sess.ID, s.cfg.Limits.Replay)
	if err != nil || len(msgs) == 0 {
		return
	}
	batch := ""
	if c.caps["batch"] && c.caps["message-tags"] {
		batch = "h" + randomHex(4)
		c.send("BATCH", "+"+batch, "chathistory", sess.Channel)
	}
	for _, m := range msgs {
		for _, line := range splitReply(m.Body) {
			source := c.prefix()
			account := c.account
			if m.Sender == "ai" {
				source = aiPrefix(sess.AINick)
				account = "*"
			}
			tags := map[string]string{}
			if c.caps["server-time"] || c.caps["message-tags"] {
				tags["time"] = m.Created.UTC().Format("2006-01-02T15:04:05.000Z")
			}
			if c.caps["message-tags"] {
				tags["msgid"] = fmt.Sprintf("m%d", m.ID)
			}
			if c.caps["account-tag"] {
				tags["account"] = account
			}
			if batch != "" {
				tags["batch"] = batch
			}
			if len(tags) == 0 {
				tags = nil
			}
			msg := ircmsg.MakeMessage(tags, source, "PRIVMSG", sess.Channel, line)
			msg.ForceTrailing()
			c.writeMsg(msg, true)
		}
	}
	if batch != "" {
		c.send("BATCH", "-"+batch)
	}
}

func (s *Server) part(c *Client, channel, reason string) {
	if !c.leaveMark(channel) {
		c.reply(442, channel, "You're not on that channel")
		return
	}
	c.sendFrom(c.prefix(), "PART", channel, cleanLine(reason))
}

func (s *Server) messageAI(c *Client, ai store.AI, text string) {
	if tooLong(c, text) {
		return
	}
	sess, err := s.store.LatestOpenSession(c.account, ai.Nick)
	created := false
	if err != nil {
		sess, err = s.createSession(c.account, ai)
		if err != nil {
			c.notice(servicePrefix, "Could not open a session.")
			s.log.Error("session", "err", err, "account", c.account)
			return
		}
		created = true
	}
	if !c.onChannel(sess.Channel) {
		s.joinBurst(c, sess, !created)
	}
	if created {
		c.notice(servicePrefix, "Session with "+ai.Nick+" is "+sess.Channel+". Talk in that channel.")
	}
	if _, err := s.store.AddMessage(sess.ID, "user", text); err != nil {
		c.notice(servicePrefix, "Could not store that message.")
		return
	}
	s.sayAs(c, c.prefix(), c.account, sess.Channel, text)
	s.poke(sess.Channel)
}

func (s *Server) messageChannel(c *Client, channel, text string, notice bool) {
	sess, ok := s.visibleSession(c, channel)
	if !ok || !c.onChannel(sess.Channel) {
		if !notice {
			c.reply(404, channel, "Cannot send to channel")
		}
		return
	}
	if notice || tooLong(c, text) {
		return
	}
	c.echo(sess.Channel, text)
	if _, err := s.store.AddMessage(sess.ID, "user", text); err != nil {
		c.notice(servicePrefix, "Could not store that message.")
		return
	}
	s.poke(sess.Channel)
}

func (s *Server) sayAs(c *Client, source, account, channel, text string) {
	for _, line := range splitReply(text) {
		tags := c.accountTag(account)
		msg := ircmsg.MakeMessage(tags, source, "PRIVMSG", channel, line)
		msg.ForceTrailing()
		c.writeMsg(msg, true)
	}
}

func tooLong(c *Client, text string) bool {
	if len([]rune(text)) > 4000 {
		c.notice(servicePrefix, "That message is too long.")
		return true
	}
	return false
}

func (s *Server) createSession(owner string, ai store.AI) (store.Session, error) {
	var last error
	for i := 0; i < 5; i++ {
		channel := "#" + ai.Nick + "-" + randomHex(4)
		sess, err := s.store.CreateSession(owner, ai.Nick, channel)
		if err == nil {
			s.startWorker(sess)
			return sess, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("channel name collision")
	}
	return store.Session{}, last
}

func (s *Server) startWorker(sess store.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fold(sess.Channel)
	if _, ok := s.live[key]; ok {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	ls := &liveSession{
		rec:    sess,
		wake:   make(chan struct{}, 1),
		cancel: cancel,
		topic:  "Conversation with " + sess.AINick,
	}
	s.live[key] = ls
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.worker(ctx, ls)
	}()
}

func (s *Server) poke(channel string) {
	s.mu.Lock()
	ls := s.live[fold(channel)]
	s.mu.Unlock()
	if ls == nil {
		return
	}
	select {
	case ls.wake <- struct{}{}:
	default:
	}
}

func (s *Server) worker(ctx context.Context, ls *liveSession) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ls.wake:
		}
		for {
			if ctx.Err() != nil {
				return
			}
			again, err := s.respond(ctx, ls)
			if err != nil {
				s.log.Error("provider", "channel", ls.rec.Channel, "err", err)
			}
			if !again {
				break
			}
		}
	}
}

func (s *Server) respond(ctx context.Context, ls *liveSession) (bool, error) {
	open, err := s.store.IsOpen(ls.rec.ID)
	if err != nil || !open {
		return false, err
	}
	history, err := s.store.RecentMessages(ls.rec.ID, s.cfg.Limits.ContextMessages)
	if err != nil {
		return false, err
	}
	if len(history) == 0 || history[len(history)-1].Sender != "user" {
		return false, nil
	}
	ai, err := s.store.AIByNick(ls.rec.AINick)
	if err != nil {
		s.noticeOwner(ls.rec, "That AI nick is no longer available.")
		return false, err
	}
	key, err := secret.Open(s.key, ai.Secret)
	if err != nil {
		s.noticeOwner(ls.rec, "The stored credential for "+ai.Nick+" could not be read.")
		return false, err
	}
	chat := make([]provider.ChatMessage, 0, len(history)+1)
	chat = append(chat, provider.ChatMessage{
		Role: "system",
		Content: "You are " + ai.Nick + ", an AI assistant in a private IRC session with the account " + ls.rec.Owner +
			". Reply in plain text that an IRC client can display.",
	})
	for _, m := range history {
		role := "user"
		if m.Sender == "ai" {
			role = "assistant"
		}
		chat = append(chat, provider.ChatMessage{Role: role, Content: m.Body})
	}
	callCtx, cancel := context.WithTimeout(ctx, s.cfg.Limits.ProviderTimeout)
	defer cancel()
	reply, err := s.ai.Complete(callCtx, provider.Backend{
		Provider: ai.Provider,
		Model:    ai.Model,
		BaseURL:  ai.BaseURL,
		APIKey:   string(key),
	}, chat)
	if err != nil {
		s.noticeOwner(ls.rec, ai.Nick+" could not answer: "+err.Error())
		return false, err
	}
	reply = strings.TrimSpace(reply)
	if reply == "" {
		s.noticeOwner(ls.rec, ai.Nick+" returned an empty reply.")
		return false, nil
	}
	if _, err := s.store.AddMessage(ls.rec.ID, "ai", reply); err != nil {
		return false, err
	}
	s.deliverAI(ls.rec, reply)
	return true, nil
}

func (s *Server) deliverAI(sess store.Session, text string) {
	c := s.client(sess.Owner)
	if c == nil || !c.onChannel(sess.Channel) {
		return
	}
	for _, line := range splitReply(text) {
		tags := map[string]string{}
		if c.caps["server-time"] || c.caps["message-tags"] {
			tags["time"] = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		}
		if c.caps["message-tags"] {
			tags["msgid"] = "m" + randomHex(8)
		}
		if c.caps["account-tag"] {
			tags["account"] = "*"
		}
		if len(tags) == 0 {
			tags = nil
		}
		msg := ircmsg.MakeMessage(tags, aiPrefix(sess.AINick), "PRIVMSG", sess.Channel, line)
		msg.ForceTrailing()
		raw, err := msg.Line()
		if err != nil {
			continue
		}
		c.enqueue(raw)
	}
}

func (s *Server) noticeOwner(sess store.Session, text string) {
	c := s.client(sess.Owner)
	if c == nil {
		return
	}
	msg := ircmsg.MakeMessage(nil, servicePrefix, "NOTICE", sess.Owner, cleanLine(text))
	msg.ForceTrailing()
	raw, err := msg.Line()
	if err != nil {
		return
	}
	c.enqueue(raw)
}

func (s *Server) topic(sess store.Session) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ls := s.live[fold(sess.Channel)]; ls != nil && ls.topic != "" {
		return ls.topic
	}
	return "Conversation with " + sess.AINick
}

func (s *Server) setTopic(channel, topic string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ls := s.live[fold(channel)]; ls != nil {
		ls.topic = topic
	}
}

func (s *Server) shutdownSession(sess store.Session, reason string) {
	s.mu.Lock()
	ls := s.live[fold(sess.Channel)]
	delete(s.live, fold(sess.Channel))
	s.mu.Unlock()
	if ls != nil {
		ls.cancel()
	}
	_ = s.store.CloseSession(sess.ID)
	c := s.client(sess.Owner)
	if c == nil {
		return
	}
	if c.leaveMark(sess.Channel) {
		msg := ircmsg.MakeMessage(nil, c.prefix(), "PART", sess.Channel, cleanLine(reason))
		msg.ForceTrailing()
		if raw, err := msg.Line(); err == nil {
			c.enqueue(raw)
		}
	}
}

func (s *Server) openSession(owner string, ai store.AI) (store.Session, error) {
	return s.createSession(owner, ai)
}
