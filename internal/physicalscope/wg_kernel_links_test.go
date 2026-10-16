package physicalscope

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func wgLinkDumpFixture() []message {
	frames := []message{linkFrame(1, "lo", "", "", 0), linkFrame(9, "foreign-wg", "wireguard", "", 0), linkFrame(10, "foreign-awg", "amneziawg", "", 0), linkFrame(11, "down-veth", "veth", "", 0)}
	for i := range frames {
		frames[i].flags = 2
	}
	return frames
}

func TestWGKernelLinkInventoryPreservesEveryKindAndRejectsIncompleteDump(t *testing.T) {
	for _, cut := range []string{"none", "empty", "duplicate-name", "duplicate-index", "short", "wrong-message", "wrong-flags", "malformed-attrs", "oversized"} {
		t.Run(cut, func(t *testing.T) {
			frames := wgLinkDumpFixture()
			switch cut {
			case "empty":
				frames = nil
			case "duplicate-name":
				frames = append(frames, linkFrame(12, "foreign-wg", "tun", "", 0))
				frames[len(frames)-1].flags = 2
			case "duplicate-index":
				frames = append(frames, linkFrame(9, "other", "tun", "", 0))
				frames[len(frames)-1].flags = 2
			case "short":
				frames[1].data = []byte{0}
			case "wrong-message":
				frames[1].kind = 17
			case "wrong-flags":
				frames[1].flags |= 0x10
			case "malformed-attrs":
				frames[1].data = append(frames[1].data, attr(3, []byte("hidden\x00"))...)
			case "oversized":
				frames = make([]message, 4097)
			}
			links, err := wgKernelLinks(frames)
			if cut != "none" {
				if err == nil || len(links) != 0 {
					t.Fatal("incomplete dump became usable inventory", cut)
				}
				return
			}
			want := []WGKernelLink{{"lo", 1, ""}, {"foreign-wg", 9, "wireguard"}, {"foreign-awg", 10, "amneziawg"}, {"down-veth", 11, "veth"}}
			if err != nil || !slices.Equal(links, want) {
				t.Fatal("foreign or non-WG link was filtered out", links, err)
			}
			clear(frames[1].data)
			if !slices.Equal(links, want) {
				t.Fatal("returned facts alias mutable dump bytes")
			}
		})
	}
}

func TestWGKernelLinkInventoryRequiresBoundedOriginalNamespaceBookends(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 7}
	for _, cut := range []string{"none", "foreign-identity", "missing-callback", "twice", "closing", "transport", "canceled", "unbounded"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if cut == "unbounded" {
				ctx = context.Background()
			}
			if cut == "canceled" {
				cancel()
			}
			captures := 0
			current := func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				if cut == "missing-callback" {
					return nil
				}
				actual := id
				if cut == "foreign-identity" {
					actual.Inode++
				}
				if err := use(c, actual); err != nil {
					return err
				}
				if cut == "twice" {
					return use(c, actual)
				}
				if cut == "closing" {
					return errors.New("namespace closing observation changed")
				}
				return nil
			}
			capture := func(c context.Context) ([]message, error) {
				captures++
				if deadline, ok := c.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
					t.Fatal("kernel leaf lost its bound")
				}
				if cut == "transport" {
					return wgLinkDumpFixture(), errors.New("partial dump/truncated transport")
				}
				return wgLinkDumpFixture(), nil
			}
			links, err := readWGKernelLinks(ctx, id, current, capture)
			if cut == "none" {
				if err != nil || len(links) != 4 || captures != 1 {
					t.Fatal("complete held observation refused", err)
				}
			} else if err == nil || len(links) != 0 {
				t.Fatal("unknown namespace/capture published facts", cut, links, err)
			}
		})
	}
	if links, err := ReadWGKernelLinks(context.Background(), nil, id); len(links) != 0 || err == nil {
		t.Fatal("unissued provider observed inventory")
	}
}
