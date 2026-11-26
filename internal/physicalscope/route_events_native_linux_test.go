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

// Diagnostic only: observe bounded route notification shapes without publishing
// addresses, gateways, raw payloads or any authority for a later network change.
func TestNativeRouteEventShapes(t *testing.T) {
	if os.Getenv("RAZVILKA_ROUTE_EVENT_SHAPES") != "1" {
		t.Skip("coordinator-owned read-only route notification observation")
	}
	fd, _, err := routeSocket(0x40 | 0x400)
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
			if (m.kind != 24 && m.kind != 25) || len(m.data) < 12 {
				t.Fatal("unexpected route notification envelope")
			}
			a, err := attrs(m.data[12:])
			if err != nil {
				t.Fatal("invalid route notification attributes")
			}
			attributes := make([]string, 0, len(a))
			for kind, value := range a {
				attributes = append(attributes, fmt.Sprintf("%d:%d", kind, len(value)))
			}
			slices.Sort(attributes)
			oif := uint32(0)
			if len(a[4]) == 4 {
				oif = binary.NativeEndian.Uint32(a[4])
			}
			shape := fmt.Sprintf("kind=%d flags=%d family=%d dst_bits=%d src_bits=%d tos=%d table=%d proto=%d scope=%d type=%d route_flags=%d oif=%d attrs=%s", m.kind, m.flags, m.data[0], m.data[1], m.data[2], m.data[3], m.data[4], m.data[5], m.data[6], m.data[7], binary.NativeEndian.Uint32(m.data[8:12]), oif, strings.Join(attributes, ","))
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
	t.Log("read-only route notifications finished; no scope or route authority issued")
}
