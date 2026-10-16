//go:build linux

package physicalscope

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Read-only diagnostics, never an acceptance proof or input to a scope issuer.
// It records shapes/counts, not neighbor addresses, MACs or raw kernel payloads.
func TestNativeNeighborEventShapes(t *testing.T) {
	if os.Getenv("RAZVILKA_NEIGHBOR_EVENT_SHAPES") != "1" {
		t.Skip("coordinator-owned read-only kernel notification observation")
	}
	fd, _, err := routeSocket(4)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	buf := make([]byte, 1<<20)
	counts := map[string]int{}
	total := 0
	for ctx.Err() == nil {
		n, err := receive(fd, buf)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(poll, 100); err != nil && err != unix.EINTR {
				t.Fatal(err)
			}
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				t.Fatal("kernel notification socket failed")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		total += n
		if total > maxNetBytes {
			t.Fatal("notification byte bound exceeded")
		}
		frames, err := messages(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range frames {
			if (m.kind != 28 && m.kind != 29) || len(m.data) < 12 {
				t.Fatal("unexpected notification envelope")
			}
			a, err := attrs(m.data[12:])
			if err != nil {
				t.Fatal("invalid notification attributes")
			}
			attributes := make([]string, 0, len(a))
			for kind, value := range a {
				attributes = append(attributes, fmt.Sprintf("%d:%d", kind, len(value)))
			}
			slices.Sort(attributes)
			shape := fmt.Sprintf("kind=%d flags=%d family=%d index=%d state=%d ndm_flags=%d type=%d attrs=%s", m.kind, m.flags, m.data[0], binary.NativeEndian.Uint32(m.data[4:8]), binary.NativeEndian.Uint16(m.data[8:10]), m.data[10], m.data[11], strings.Join(attributes, ","))
			if _, found := counts[shape]; !found && len(counts) >= 128 {
				t.Fatal("notification shape bound exceeded")
			}
			counts[shape]++
		}
	}
	shapes := make([]string, 0, len(counts))
	for shape := range counts {
		shapes = append(shapes, shape)
	}
	slices.Sort(shapes)
	for _, shape := range shapes {
		t.Logf("count=%d %s", counts[shape], shape)
	}
	t.Log("read-only notification observation finished; no scope or packet authority issued")
}
