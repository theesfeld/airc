package server

import (
	"strconv"
	"strings"
	"time"

	"github.com/ergochat/irc-go/ircmsg"
	"github.com/theesfeld/airc/internal/sasl"
)

const servicePrefix = "airc!airc@services.airc"

func aiPrefix(nick string) string { return nick + "!" + nick + "@bots.airc" }

func (c *Client) handle(msg ircmsg.Message) {
	cmd := strings.ToUpper(msg.Command)
	if !c.registered && !registrationCommand(cmd) {
		c.reply(451, "You have not registered")
		return
	}
	switch cmd {
	case "CAP":
		c.cmdCAP(msg.Params)
	case "AUTHENTICATE":
		c.cmdAuthenticate(msg.Params)
	case "NICK":
		c.cmdNick(msg.Params)
	case "USER":
		c.cmdUser(msg.Params)
	case "PASS":
		if c.registered {
			c.reply(462, "You may not reregister")
		}
	case "PING":
		c.cmdPing(msg.Params)
	case "PONG", "AWAY":
		if cmd == "AWAY" {
			c.cmdAway(msg.Params)
		}
	case "QUIT":
		c.quit("Client quit")
	case "JOIN":
		c.cmdJoin(msg.Params)
	case "PART":
		c.cmdPart(msg.Params)
	case "PRIVMSG":
		c.cmdMsg(msg.Params, false)
	case "NOTICE":
		c.cmdMsg(msg.Params, true)
	case "MODE":
		c.cmdMode(msg.Params)
	case "WHO":
		c.cmdWho(msg.Params)
	case "WHOIS":
		c.cmdWhois(msg.Params)
	case "NAMES":
		c.cmdNames(msg.Params)
	case "LIST":
		c.cmdList()
	case "TOPIC":
		c.cmdTopic(msg.Params)
	case "MOTD":
		c.sendMOTD()
	case "LUSERS":
		c.sendLusers()
	case "VERSION":
		c.reply(351, Version, c.srv.cfg.Server.Name, Version)
	case "TIME":
		c.reply(391, c.srv.cfg.Server.Name, time.Now().UTC().Format(time.RFC1123))
	case "ADMIN", "INFO":
		c.reply(371, "aIRC is a single-purpose IRC server for talking to AI.")
		c.reply(374, "End of INFO list")
	case "ISON":
		c.cmdIson(msg.Params)
	case "USERHOST":
		c.cmdUserhost(msg.Params)
	case "AIRC":
		c.srv.service(c, strings.Join(msg.Params, " "))
	default:
		c.reply(421, cmd, "Unknown command")
	}
}

func registrationCommand(cmd string) bool {
	switch cmd {
	case "CAP", "AUTHENTICATE", "NICK", "USER", "PASS", "PING", "PONG", "QUIT":
		return true
	default:
		return false
	}
}

func (c *Client) cmdCAP(params []string) {
	if len(params) == 0 {
		c.reply(461, "CAP", "Not enough parameters")
		return
	}
	sub := strings.ToUpper(params[0])
	target := "*"
	if c.registered {
		target = c.nick
	}
	switch sub {
	case "LS":
		c.capOpen = true
		c.sawCAP = true
		if len(params) > 1 && params[1] == "302" {
			c.cap302 = true
		}
		c.send("CAP", target, "LS", c.capAdvertisement())
	case "LIST":
		c.send("CAP", target, "LIST", c.enabledCaps())
	case "REQ":
		if len(params) < 2 {
			c.reply(461, "CAP", "Not enough parameters")
			return
		}
		if c.registered {
			c.send("CAP", target, "NAK", params[1])
			return
		}
		c.capOpen = true
		c.sawCAP = true
		ack, nak := c.applyCaps(strings.Fields(params[1]))
		if len(ack) > 0 {
			c.send("CAP", target, "ACK", strings.Join(ack, " "))
		}
		if len(nak) > 0 {
			c.send("CAP", target, "NAK", strings.Join(nak, " "))
		}
	case "END":
		c.capOpen = false
		if !c.saslOK {
			c.fatal("This server requires SASL authentication")
			return
		}
		c.finishIfReady()
	default:
		c.reply(410, sub, "Invalid CAP command")
	}
}

func (c *Client) capAdvertisement() string {
	names := []string{
		"message-tags", "server-time", "account-tag", "account-notify",
		"echo-message", "batch", "labeled-response", "away-notify",
		"extended-join", "multi-prefix", "cap-notify",
	}
	saslCap := "sasl"
	if c.cap302 {
		saslCap = "sasl=PLAIN,SCRAM-SHA-256"
	}
	return saslCap + " " + strings.Join(names, " ")
}

func (c *Client) enabledCaps() string {
	var names []string
	for name := range c.caps {
		names = append(names, name)
	}
	return strings.Join(names, " ")
}

func supportedCap(name string) bool {
	switch name {
	case "sasl", "message-tags", "server-time", "account-tag", "account-notify",
		"echo-message", "batch", "labeled-response", "away-notify",
		"extended-join", "multi-prefix", "cap-notify":
		return true
	default:
		return false
	}
}

func (c *Client) applyCaps(req []string) (ack, nak []string) {
	for _, name := range req {
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "-") {
			base := name[1:]
			if supportedCap(base) {
				delete(c.caps, base)
				ack = append(ack, name)
			} else {
				nak = append(nak, name)
			}
			continue
		}
		if supportedCap(name) {
			c.caps[name] = true
			ack = append(ack, name)
		} else {
			nak = append(nak, name)
		}
	}
	return ack, nak
}

func (c *Client) cmdNick(params []string) {
	if len(params) == 0 || params[0] == "" {
		c.reply(431, "No nickname given")
		return
	}
	if c.registered {
		c.reply(437, params[0], "Nick is fixed to your account name")
		return
	}
	c.requestedNick = params[0]
	c.haveNick = true
	if c.nick == "" {
		c.nick = params[0]
	}
	c.finishIfReady()
}

func (c *Client) cmdUser(params []string) {
	if c.registered || c.haveUser {
		c.reply(462, "You may not reregister")
		return
	}
	if len(params) < 4 {
		c.reply(461, "USER", "Not enough parameters")
		return
	}
	c.real = cleanLine(params[3])
	if c.real == "" {
		c.real = "user"
	}
	if len(c.real) > 64 {
		c.real = c.real[:64]
	}
	c.haveUser = true
	c.finishIfReady()
}

func (c *Client) finishIfReady() {
	if c.registered || c.closedCh() {
		return
	}
	// A client that finishes NICK and USER without ever starting capability
	// negotiation has no SASL path left. CAP LS / CAP REQ still allow SASL
	// before or after NICK.
	if c.haveNick && c.haveUser && !c.capOpen && !c.saslOK && !c.sawCAP {
		c.fatal("This server requires SASL authentication")
		return
	}
	if !c.haveNick || !c.haveUser || c.capOpen || !c.saslOK {
		return
	}
	c.welcome()
}

func (c *Client) fatal(reason string) {
	c.quit(reason)
}

func (c *Client) welcome() {
	if !strings.EqualFold(c.requestedNick, c.account) && c.requestedNick != "" {
		old := c.requestedNick + "!" + c.account + "@" + c.account + ".users.airc"
		c.sendFrom(old, "NICK", c.account)
	}
	c.nick = c.account
	c.host = c.account + ".users.airc"
	if c.real == "" {
		c.real = c.account
	}
	c.registered = true
	c.srv.publish(c)
	c.srv.log.Info("login", "account", c.account, "ip", c.ip)
	c.reply(1, "Welcome to the "+c.srv.cfg.Server.Network+" Network "+c.prefix())
	c.reply(2, "Your host is "+c.srv.cfg.Server.Name+", running "+Version)
	c.reply(3, "This server was created for private AI conversations")
	c.reply(4, c.srv.cfg.Server.Name, Version, "i", "isnt")
	c.reply(5,
		"CASEMAPPING=ascii",
		"CHANTYPES=#",
		"CHANMODES=,k,l,imnst",
		"CHANNELLEN=64",
		"NICKLEN=32",
		"PREFIX=(o)@",
		"NETWORK="+c.srv.cfg.Server.Network,
		"TARGMAX=NAMES:1,LIST:1,WHOIS:1,PRIVMSG:1",
		"UTF8ONLY",
		"are supported by this server",
	)
	c.sendLusers()
	c.sendMOTD()
	c.srv.replaySessions(c)
}

func (c *Client) sendLusers() {
	n := c.srv.userCount()
	ch := c.srv.sessionCount()
	c.reply(251, "There are "+strconv.Itoa(n)+" users and 0 invisible on 1 server")
	c.reply(252, "0", "operator(s) online")
	c.reply(254, strconv.Itoa(ch), "channels formed")
	c.reply(255, "I have "+strconv.Itoa(n)+" clients and 1 server")
	c.reply(265, strconv.Itoa(n), strconv.Itoa(n), "Current local users "+strconv.Itoa(n)+", max "+strconv.Itoa(n))
	c.reply(266, strconv.Itoa(n), strconv.Itoa(n), "Current global users "+strconv.Itoa(n)+", max "+strconv.Itoa(n))
}

func (c *Client) sendMOTD() {
	name := c.srv.cfg.Server.Name
	c.reply(375, "- "+name+" Message of the day -")
	c.reply(372, "- aIRC gives an IRC client a private channel with an AI nick.")
	c.reply(372, "- Authentication is SASL over TLS. Message airc for help.")
	c.reply(376, "End of MOTD command")
}

func (c *Client) cmdPing(params []string) {
	token := c.srv.cfg.Server.Name
	if len(params) > 0 && params[0] != "" {
		token = cleanLine(params[0])
	}
	c.send("PONG", c.srv.cfg.Server.Name, token)
}

func (c *Client) cmdAway(params []string) {
	if len(params) == 0 || params[0] == "" {
		c.away = ""
		c.reply(305, "You are no longer marked as being away")
		return
	}
	c.away = cleanLine(params[0])
	c.reply(306, "You have been marked as being away")
}

func (c *Client) cmdAuthenticate(params []string) {
	if len(params) == 0 {
		c.reply(461, "AUTHENTICATE", "Not enough parameters")
		return
	}
	param := params[0]
	if param == "*" {
		c.saslMech = ""
		c.scram = nil
		c.saslBuf.Reset()
		c.reply(906, "SASL authentication aborted")
		return
	}
	if c.saslOK {
		c.reply(907, "You have already authenticated")
		return
	}
	if !c.caps["sasl"] {
		c.reply(908, "PLAIN,SCRAM-SHA-256", "are available SASL mechanisms")
		return
	}
	if c.saslMech == "" {
		switch strings.ToUpper(param) {
		case "PLAIN", "SCRAM-SHA-256":
			c.saslMech = strings.ToUpper(param)
			c.saslBuf.Reset()
			c.enqueue("AUTHENTICATE +")
		default:
			c.reply(908, "PLAIN,SCRAM-SHA-256", "are available SASL mechanisms")
		}
		return
	}
	if param != "+" {
		if len(param) > 400 {
			c.saslFails++
			c.saslMech = ""
			c.scram = nil
			c.saslBuf.Reset()
			c.srv.strike(c.ip)
			c.reply(905, "SASL message too long")
			if c.saslFails >= 3 {
				c.fatal("SASL authentication failed")
			}
			return
		}
		c.saslBuf.WriteString(param)
	}
	if param != "+" && len(param) == 400 {
		return
	}
	raw, err := decodeB64(c.saslBuf.String())
	c.saslBuf.Reset()
	if err != nil {
		c.failSASL()
		return
	}
	if c.saslMech == "PLAIN" {
		c.authPlain(raw)
		return
	}
	c.authSCRAM(string(raw))
}

func (c *Client) authPlain(raw []byte) {
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		c.failSASL()
		return
	}
	authzid, authcid, password := parts[0], parts[1], parts[2]
	if authcid == "" || (authzid != "" && !strings.EqualFold(authzid, authcid)) {
		c.failSASL()
		return
	}
	account := strings.ToLower(authcid)
	user, err := c.srv.store.UserByName(account)
	if err != nil {
		fake := sasl.Fake(c.srv.saslSecret(), account, c.srv.cfg.Limits.SCRAMIterations)
		_ = fake.Verify(password)
		c.failSASL()
		return
	}
	if !user.Creds.Verify(password) {
		c.failSASL()
		return
	}
	c.saslSuccess(user.Name)
}

func (c *Client) authSCRAM(message string) {
	if c.scram == nil {
		attrs := parseSCRAMUser(message)
		if attrs == "" {
			c.failSASL()
			return
		}
		account := strings.ToLower(attrs)
		user, err := c.srv.store.UserByName(account)
		var creds sasl.Credentials
		exists := err == nil
		if exists {
			creds = user.Creds
		} else {
			creds = sasl.Fake(c.srv.saslSecret(), account, c.srv.cfg.Limits.SCRAMIterations)
		}
		convo := &sasl.Convo{Username: attrs, Creds: creds}
		serverFirst, err := convo.AcceptFirst(message)
		if err != nil {
			c.failSASL()
			return
		}
		c.scram = convo
		c.saslUserExists = exists
		c.account = account
		for _, chunk := range encodeAuth(serverFirst) {
			c.enqueue("AUTHENTICATE " + chunk)
		}
		return
	}
	serverFinal, err := c.scram.AcceptFinal(message)
	if err != nil || !c.saslUserExists {
		c.failSASL()
		return
	}
	for _, chunk := range encodeAuth(serverFinal) {
		c.enqueue("AUTHENTICATE " + chunk)
	}
	c.saslSuccess(c.account)
}

func parseSCRAMUser(clientFirst string) string {
	_, bare, err := splitGS2Local(clientFirst)
	if err != nil {
		return ""
	}
	for _, part := range strings.Split(bare, ",") {
		k, v, ok := strings.Cut(part, "=")
		if ok && k == "n" {
			v = strings.ReplaceAll(v, "=3D", "=")
			v = strings.ReplaceAll(v, "=2C", ",")
			return v
		}
	}
	return ""
}

func splitGS2Local(first string) (header, bare string, err error) {
	i := strings.IndexByte(first, ',')
	if i < 0 {
		return "", "", sasl.ErrMechanism
	}
	j := strings.IndexByte(first[i+1:], ',')
	if j < 0 {
		return "", "", sasl.ErrMechanism
	}
	j += i + 1
	return first[:j+1], first[j+1:], nil
}

func (c *Client) saslSuccess(account string) {
	c.saslOK = true
	c.account = account
	c.host = account + ".users.airc"
	c.saslMech = ""
	c.scram = nil
	c.srv.clearStrikes(c.ip)
	c.srv.log.Info("sasl", "account", account, "ip", c.ip)
	c.reply(900, c.prefix(), account, "You are now logged in as "+account)
	c.reply(903, "SASL authentication successful")
	c.finishIfReady()
}

func (c *Client) failSASL() {
	c.saslFails++
	c.saslMech = ""
	c.scram = nil
	c.saslBuf.Reset()
	c.saslUserExists = false
	if !c.saslOK {
		c.account = ""
	}
	c.srv.strike(c.ip)
	c.srv.log.Warn("sasl failed", "ip", c.ip)
	c.reply(904, "SASL authentication failed")
	if c.saslFails >= 3 {
		c.fatal("SASL authentication failed")
	}
}

func (c *Client) cmdMsg(params []string, notice bool) {
	if len(params) < 2 || params[0] == "" {
		if !notice {
			c.reply(411, "No recipient given")
		}
		return
	}
	target, text := params[0], params[1]
	if strings.TrimSpace(text) == "" {
		return
	}
	if !notice {
		if next, ok := c.filterCTCP(target, text); !ok {
			return
		} else {
			text = next
		}
	}
	if strings.EqualFold(target, "airc") {
		if !notice {
			c.echo(target, text)
			c.srv.service(c, text)
		}
		return
	}
	if ai, err := c.srv.store.AIByNick(target); err == nil {
		if notice {
			return
		}
		c.echo(target, text)
		c.srv.messageAI(c, ai, text)
		return
	}
	if strings.HasPrefix(target, "#") {
		c.srv.messageChannel(c, target, text, notice)
		return
	}
	if !notice {
		c.reply(401, target, "No such nick/channel")
	}
}

func (c *Client) filterCTCP(target, text string) (string, bool) {
	if len(text) < 2 || text[0] != 0x01 || text[len(text)-1] != 0x01 {
		return text, true
	}
	inner := text[1 : len(text)-1]
	cmd, rest, _ := strings.Cut(inner, " ")
	source := servicePrefix
	if ai, err := c.srv.store.AIByNick(target); err == nil {
		source = aiPrefix(ai.Nick)
	}
	switch strings.ToUpper(cmd) {
	case "VERSION":
		c.notice(source, "\x01VERSION "+Version+"\x01")
		return "", false
	case "PING":
		c.notice(source, "\x01PING "+cleanLine(rest)+"\x01")
		return "", false
	case "TIME":
		c.notice(source, "\x01TIME "+time.Now().UTC().Format(time.RFC3339)+"\x01")
		return "", false
	case "ACTION":
		if strings.TrimSpace(rest) == "" {
			return "", false
		}
		return rest, true
	default:
		return "", false
	}
}

func (c *Client) notice(source, text string) {
	msg := ircmsg.MakeMessage(nil, source, "NOTICE", c.nickOrStar(), text)
	msg.ForceTrailing()
	c.writeMsg(msg, true)
}

func (c *Client) echo(target, text string) {
	if !c.caps["echo-message"] {
		return
	}
	for _, line := range splitReply(text) {
		tags := c.accountTag(c.account)
		msg := ircmsg.MakeMessage(tags, c.prefix(), "PRIVMSG", target, line)
		msg.ForceTrailing()
		c.writeMsg(msg, true)
	}
}

func (c *Client) cmdJoin(params []string) {
	if len(params) == 0 || params[0] == "" {
		c.reply(461, "JOIN", "Not enough parameters")
		return
	}
	if params[0] == "0" {
		for _, ch := range c.channelNames() {
			c.srv.part(c, ch, "Leaving")
		}
		return
	}
	for _, ch := range strings.Split(params[0], ",") {
		c.srv.joinExisting(c, ch, true)
	}
}

func (c *Client) cmdPart(params []string) {
	if len(params) == 0 {
		c.reply(461, "PART", "Not enough parameters")
		return
	}
	reason := "Leaving"
	if len(params) > 1 {
		reason = params[1]
	}
	for _, ch := range strings.Split(params[0], ",") {
		c.srv.part(c, ch, reason)
	}
}

func (c *Client) cmdMode(params []string) {
	if len(params) == 0 {
		c.reply(461, "MODE", "Not enough parameters")
		return
	}
	target := params[0]
	if strings.HasPrefix(target, "#") {
		sess, ok := c.srv.visibleSession(c, target)
		if !ok {
			c.reply(403, target, "No such channel")
			return
		}
		if len(params) == 1 {
			c.reply(324, sess.Channel, "+isnt")
			c.reply(329, sess.Channel, strconv.FormatInt(sess.Created.Unix(), 10))
			return
		}
		if sess.Owner != c.account {
			c.reply(482, sess.Channel, "You're not a channel operator")
			return
		}
		c.send("MODE", sess.Channel, params[1])
		return
	}
	if !strings.EqualFold(target, c.nick) {
		c.reply(502, "Can't change mode for other users")
		return
	}
	if len(params) == 1 {
		c.reply(221, "+")
		return
	}
	c.reply(221, "+")
}

func (c *Client) cmdWho(params []string) {
	mask := "*"
	if len(params) > 0 {
		mask = params[0]
	}
	server := c.srv.cfg.Server.Name
	if strings.HasPrefix(mask, "#") {
		sess, ok := c.srv.visibleSession(c, mask)
		if ok {
			c.whoReply(sess.Channel, c.account, c.host, server, c.nick, "H@", c.real)
			c.whoReply(sess.Channel, sess.AINick, "bots.airc", server, sess.AINick, "H", "AI assistant")
		}
		c.reply(315, mask, "End of WHO list")
		return
	}
	if strings.EqualFold(mask, c.nick) || mask == "*" || mask == "0" {
		c.whoReply("*", c.account, c.host, server, c.nick, "H", c.real)
	}
	if ai, err := c.srv.store.AIByNick(mask); err == nil {
		c.whoReply("*", ai.Nick, "bots.airc", server, ai.Nick, "H", "AI assistant")
	}
	if strings.EqualFold(mask, "airc") || mask == "*" || mask == "0" {
		c.whoReply("*", "airc", "services.airc", server, "airc", "H", "aIRC service")
	}
	c.reply(315, mask, "End of WHO list")
}

func (c *Client) whoReply(channel, user, host, server, nick, flags, real string) {
	c.reply(352, channel, user, host, server, nick, flags, "0 "+real)
}

func (c *Client) cmdWhois(params []string) {
	if len(params) == 0 {
		c.reply(431, "No nickname given")
		return
	}
	nick := params[len(params)-1]
	if strings.EqualFold(nick, c.nick) {
		c.reply(311, c.nick, c.account, c.host, "*", c.real)
		c.whoisChannels(c.nick)
		if c.away != "" {
			c.reply(301, c.nick, c.away)
		}
		c.reply(312, c.nick, c.srv.cfg.Server.Name, "aIRC")
		c.reply(330, c.nick, c.account, "is logged in as")
		c.reply(318, c.nick, "End of WHOIS list")
		return
	}
	if strings.EqualFold(nick, "airc") {
		c.reply(311, "airc", "airc", "services.airc", "*", "aIRC service")
		c.reply(312, "airc", c.srv.cfg.Server.Name, "aIRC")
		c.reply(318, "airc", "End of WHOIS list")
		return
	}
	if ai, err := c.srv.store.AIByNick(nick); err == nil {
		c.reply(311, ai.Nick, ai.Nick, "bots.airc", "*", "AI assistant")
		c.whoisAIChannels(ai.Nick)
		c.reply(312, ai.Nick, c.srv.cfg.Server.Name, "aIRC")
		c.reply(318, ai.Nick, "End of WHOIS list")
		return
	}
	c.reply(401, nick, "No such nick/channel")
}

func (c *Client) whoisChannels(nick string) {
	var names []string
	for _, ch := range c.channelNames() {
		if sess, ok := c.srv.visibleSession(c, ch); ok {
			names = append(names, "@"+sess.Channel)
		}
	}
	if len(names) > 0 {
		c.reply(319, nick, strings.Join(names, " "))
	}
}

func (c *Client) whoisAIChannels(nick string) {
	sessions, err := c.srv.store.OpenSessions(c.account)
	if err != nil {
		return
	}
	var names []string
	for _, sess := range sessions {
		if strings.EqualFold(sess.AINick, nick) {
			names = append(names, sess.Channel)
		}
	}
	if len(names) > 0 {
		c.reply(319, nick, strings.Join(names, " "))
	}
}

func (c *Client) cmdNames(params []string) {
	if len(params) == 0 {
		c.reply(366, "*", "End of /NAMES list")
		return
	}
	ch := params[0]
	sess, ok := c.srv.visibleSession(c, ch)
	if !ok {
		c.reply(366, ch, "End of /NAMES list")
		return
	}
	c.reply(353, "=", sess.Channel, "@"+c.nick+" "+sess.AINick)
	c.reply(366, sess.Channel, "End of /NAMES list")
}

func (c *Client) cmdList() {
	c.reply(321, "Channel", "Users Name")
	sessions, err := c.srv.store.OpenSessions(c.account)
	if err == nil {
		for _, sess := range sessions {
			c.reply(322, sess.Channel, "2", c.srv.topic(sess))
		}
	}
	c.reply(323, "End of LIST")
}

func (c *Client) cmdTopic(params []string) {
	if len(params) == 0 {
		c.reply(461, "TOPIC", "Not enough parameters")
		return
	}
	sess, ok := c.srv.visibleSession(c, params[0])
	if !ok {
		c.reply(403, params[0], "No such channel")
		return
	}
	if len(params) == 1 {
		c.reply(332, sess.Channel, c.srv.topic(sess))
		c.reply(333, sess.Channel, sess.AINick, strconv.FormatInt(sess.Created.Unix(), 10))
		return
	}
	if sess.Owner != c.account {
		c.reply(482, sess.Channel, "You're not a channel operator")
		return
	}
	c.srv.setTopic(sess.Channel, cleanLine(params[1]))
	c.send("TOPIC", sess.Channel, cleanLine(params[1]))
}

func (c *Client) cmdIson(params []string) {
	var online []string
	for _, nick := range params {
		if strings.EqualFold(nick, c.nick) || strings.EqualFold(nick, "airc") {
			online = append(online, nick)
			continue
		}
		if _, err := c.srv.store.AIByNick(nick); err == nil {
			online = append(online, nick)
		}
	}
	c.reply(303, strings.Join(online, " "))
}

func (c *Client) cmdUserhost(params []string) {
	if len(params) == 0 {
		c.reply(461, "USERHOST", "Not enough parameters")
		return
	}
	var parts []string
	for _, nick := range params {
		switch {
		case strings.EqualFold(nick, c.nick):
			parts = append(parts, c.nick+"=+"+c.account+"@"+c.host)
		case strings.EqualFold(nick, "airc"):
			parts = append(parts, "airc=+airc@services.airc")
		default:
			if ai, err := c.srv.store.AIByNick(nick); err == nil {
				parts = append(parts, ai.Nick+"=+"+ai.Nick+"@bots.airc")
			}
		}
	}
	c.reply(302, strings.Join(parts, " "))
}

func (s *Server) userCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

func (s *Server) sessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}
