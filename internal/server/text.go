package server

import (
	"strings"
	"unicode/utf8"
)

const payloadLimit = 300

// cleanLine removes bytes that would split an IRC message.
func cleanLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == 0 || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

// splitReply turns model output into IRC-sized plain lines.
func splitReply(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if len(text) > 16*1024 {
		text = text[:16*1024] + "\n[truncated]"
	}
	var out []string
	for _, part := range strings.Split(text, "\n") {
		part = cleanLine(part)
		if strings.TrimSpace(part) == "" {
			continue
		}
		out = append(out, chunkBytes(part, payloadLimit)...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func chunkBytes(s string, limit int) []string {
	b := []byte(s)
	var out []string
	for len(b) > 0 {
		n := limit
		if n > len(b) {
			n = len(b)
		}
		for n > 0 && !utf8.Valid(b[:n]) {
			n--
		}
		if n == 0 {
			n = 1
		}
		if n < len(b) {
			if i := lastBreak(b[:n]); i > 0 {
				n = i
			}
		}
		out = append(out, string(b[:n]))
		b = b[n:]
		for len(b) > 0 && (b[0] == ' ' || b[0] == '\n') {
			b = b[1:]
		}
	}
	return out
}

func lastBreak(b []byte) int {
	for i := len(b) - 1; i > len(b)/2; i-- {
		if b[i] == ' ' {
			return i
		}
	}
	return -1
}

func validName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 {
			if c < 'A' || (c > 'Z' && c < 'a') || c > 'z' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func fold(s string) string { return strings.ToLower(s) }

func reserved(name string) bool {
	switch fold(name) {
	case "airc", "nickserv", "chanserv":
		return true
	default:
		return false
	}
}
