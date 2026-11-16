package dataplane

import (
	"strings"
	"testing"
)

// Lose one owned NFQUEUE row while keeping BOTH total rule count and total
// NFQUEUE count unchanged. The replacement belongs to a different chain/queue.
func nfqws2HookSameCountLoss(t *testing.T, image, chain string) string {
	t.Helper()
	lines := strings.Split(image, "\n")
	replaced := false
	for i, line := range lines {
		if !replaced && strings.HasPrefix(line, "-A "+chain+" ") && strings.Contains(line, "-j NFQUEUE ") {
			lines[i] = "-A FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 64515"
			replaced = true
		}
	}
	result := strings.Join(lines, "\n")
	if !replaced || result == image || strings.Count(result, "\n-A ") != strings.Count(image, "\n-A ") || strings.Count(result, "-j NFQUEUE ") != strings.Count(image, "-j NFQUEUE ") {
		t.Fatal("same-count lost-direction fixture did not preserve its negative-control counts")
	}
	return result
}
