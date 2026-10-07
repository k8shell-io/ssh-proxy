package server

import (
	"fmt"
	"os"
	"regexp"
	"testing"
)

func TestNewConnIDFormatAndUniqueness(t *testing.T) {
	re := regexp.MustCompile(fmt.Sprintf(`^%s-%d-[a-z2-7]{26}$`, regexp.QuoteMeta(GetProxyID()), os.Getpid()))
	seen := make(map[string]struct{}, 100000)
	for i := 0; i < 100000; i++ {
		id := newConnID()
		if !re.MatchString(id) {
			t.Fatalf("unexpected connId format: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate connId: %q", id)
		}
		seen[id] = struct{}{}
	}
}
