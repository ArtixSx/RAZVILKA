//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"io"
	"strings"
	"sync"
)

const mihomoSidecarOutputLimit = 8 << 10

// Diagnostic storage only. A full buffer never stops draining, closes a pipe,
// changes an error, or grants admission. os/exec already joins this output copy
// in the original Wait. The same comparable writer is used for both streams,
// preserving their existing shared pipe with io.Discard.
type mihomoSidecarOutput struct {
	mu        sync.Mutex
	buffer    [mihomoSidecarOutputLimit]byte
	used      int
	truncated bool
	finished  bool
	category  string
}

func (o *mihomoSidecarOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.finished {
		n := copy(o.buffer[o.used:], p)
		o.used += n
		o.truncated = o.truncated || n != len(p)
	}
	return len(p), nil
}

func (o *mihomoSidecarOutput) finish() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished {
		return
	}
	o.category = "unknown"
	if !o.truncated {
		o.category = mihomoSidecarOutputCategory(o.buffer[:o.used])
	}
	clear(o.buffer[:])
	o.used = 0
	o.finished = true
}

func mihomoLiveSidecarConfigureOutput(n *mihomoLiveSidecar) {
	n.command.Stdout, n.command.Stderr = io.Discard, io.Discard
	if n.owner != nil && n.owner.definition.Sidecar.Kind == "hev" {
		output := &mihomoSidecarOutput{}
		n.command.Stdout, n.command.Stderr = output, output
	}
}

func mihomoLiveSidecarFinishOutput(n *mihomoLiveSidecar) {
	if output, ok := n.command.Stdout.(*mihomoSidecarOutput); ok && n.command.Stderr == output {
		output.finish()
	}
}

func mihomoLiveSidecarOutputSummary(n *mihomoLiveSidecar) (bool, string, bool) {
	if n == nil || n.self != n || !n.started || n.command == nil {
		return false, "unknown", false
	}
	select {
	case <-n.done:
	default:
		return false, "unknown", false
	}
	output, ok := n.command.Stdout.(*mihomoSidecarOutput)
	if !ok || n.command.Stderr != output {
		return false, "unknown", false
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if !output.finished {
		return false, "unknown", false
	}
	return true, output.category, output.truncated
}

// Fixed messages from HEV 2.17.1, commit 9a06bc6e7989. The CLI maps every
// negative startup result to exit254; that value is never interpreted as errno.
// No raw line, path, strerror suffix, or configuration byte leaves this parser.
func mihomoSidecarOutputCategory(data []byte) string {
	category := ""
	for len(data) > 0 {
		line, rest, _ := bytes.Cut(data, []byte{'\n'})
		data = rest
		if len(line) == 0 {
			continue
		}
		current := mihomoSidecarOutputLine(line)
		if current == "unknown" || category != "" && current != category {
			return "unknown"
		}
		category = current
	}
	if category == "" {
		return "unknown"
	}
	return category
}

func mihomoSidecarOutputLine(line []byte) string {
	switch string(line) {
	case "Open /proc/self/fd/4 failed!":
		return "config-open"
	case "Parse /proc/self/fd/4 failed!":
		return "config-parse"
	case "Can't found socks5.port!", "Can't found socks5.address!", "Must be set both socks5 username and password!":
		return "config-required"
	}
	// Exact logger envelope: [YYYY-MM-DD hh:mm:ss] [E] <message>.
	if len(line) < 26 || line[0] != '[' || string(line[20:26]) != "] [E] " {
		return "unknown"
	}
	for i := 1; i < 20; i++ {
		switch i {
		case 5, 8:
			if line[i] != '-' {
				return "unknown"
			}
		case 11:
			if line[i] != ' ' {
				return "unknown"
			}
		case 14, 17:
			if line[i] != ':' {
				return "unknown"
			}
		default:
			if line[i] < '0' || line[i] > '9' {
				return "unknown"
			}
		}
	}
	message := string(line[26:])
	switch message {
	case "socks5 tunnel mtu":
		return "tun-mtu"
	case "socks5 tunnel ipv4":
		return "tun-ipv4"
	case "socks5 tunnel ipv6":
		return "tun-ipv6"
	case "socks5 tunnel state":
		return "tun-up"
	case "socks5 tunnel netif":
		return "lwip-netif"
	case "socks5 tunnel tcp":
		return "lwip-tcp"
	case "socks5 tunnel udp":
		return "lwip-udp"
	case "socks5 tunnel event":
		return "event-socketpair"
	case "socks5 tunnel event nonblock":
		return "event-nonblock"
	case "socks5 tunnel task event":
		return "event-task"
	case "socks5 tunnel task lwip":
		return "lwip-task"
	case "socks5 tunnel task timer":
		return "timer-task"
	}
	if strings.HasPrefix(message, "socks5 tunnel open (") && strings.HasSuffix(message, ")") {
		return "tun-open"
	}
	return "unknown"
}
