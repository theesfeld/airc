package server

import (
	"strings"
	"testing"
)

func TestSplitReplyKeepsIRCInjectionInsideText(t *testing.T) {
	lines := splitReply("hel\x00lo\r\nQUIT :bye\r\n")
	if len(lines) != 2 || lines[0] != "hello" || lines[1] != "QUIT :bye" {
		t.Fatalf("lines = %#v", lines)
	}
	for _, line := range lines {
		if strings.ContainsAny(line, "\x00\r\n") {
			t.Fatalf("control byte survived: %q", line)
		}
	}
}
