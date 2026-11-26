package dataplane

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type embeddedMihomoCommandIdentity struct {
	MihomoLiveCommandAdmission
	starts int
}

func (c *embeddedMihomoCommandIdentity) WithStart(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
	c.starts++
	return begin()
}

// Private comparison model only. A matching header cannot replace the actual
// ready control review, original tool lease or final one-use Start admission.
func TestMihomoLiveCommandIdentityRejectsEmbeddingCopyAndEscape(t *testing.T) {
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	m := New(t.TempDir())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	s := &executionResourceScope{manager: m, adapter: "mihomo", adapterOwner: a}
	r := &mihomoLiveResource{adapter: a, scope: s, control: &operationgate.ControlEpochReview{}}
	r.self = r
	s.mihomoLive = r
	c := &mihomoLiveCommand{owner: r, name: "/original/ip", args: []string{"route", "add", "default", "dev", "rz-mihomo", "table", "207"}, review: strings.Repeat("a", 64), open: true}
	c.self = c
	base, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := context.WithValue(base, mihomoLiveCommandKey{}, c)
	if !OriginalMihomoLiveCommand(ctx, c, c.name, c.args, c.review) {
		t.Fatal("original command comparison refused")
	}
	if c.used {
		t.Fatal("comparison consumed final Start")
	}
	wrapper := &embeddedMihomoCommandIdentity{MihomoLiveCommandAdmission: c}
	if OriginalMihomoLiveCommand(ctx, wrapper, c.name, c.args, c.review) || wrapper.starts != 0 {
		t.Fatal("embedding override adopted token")
	}
	copy := &mihomoLiveCommand{self: c, owner: r, name: c.name, args: c.args, review: c.review, open: true}
	if OriginalMihomoLiveCommand(context.WithValue(base, mihomoLiveCommandKey{}, copy), copy, c.name, c.args, c.review) {
		t.Fatal("copied header adopted token")
	}
	if OriginalMihomoLiveCommand(base, c, c.name, c.args, c.review) || OriginalMihomoLiveCommand(ctx, c, c.name, []string{"route", "del", "default"}, c.review) || OriginalMihomoLiveCommand(ctx, c, c.name, c.args, strings.Repeat("b", 64)) {
		t.Fatal("foreign context/argv/review adopted")
	}
	c.open = false
	if OriginalMihomoLiveCommand(ctx, c, c.name, c.args, c.review) {
		t.Fatal("escaped token accepted")
	}
	c.open = true
	canceled, stop := context.WithCancel(ctx)
	stop()
	if OriginalMihomoLiveCommand(canceled, c, c.name, c.args, c.review) {
		t.Fatal("canceled token accepted")
	}
	called := false
	if err := c.WithStart(ctx, c.name, c.args, c.review, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("comparison header replaced actual control admission")
	}
	if OriginalMihomoLiveCommand(ctx, c, c.name, c.args, c.review) {
		t.Fatal("consumed Start accepted")
	}
}
