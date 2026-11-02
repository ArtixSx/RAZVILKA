package startuptools

import (
	"context"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type embeddedMihomoEffectAdmission struct {
	dataplane.MihomoLiveCommandAdmission
	starts int
}

func (a *embeddedMihomoEffectAdmission) WithStart(_ context.Context, _ string, _ []string, _ string, begin func() error) error {
	a.starts++
	return begin()
}

func TestMihomoImplicitIPv4NeverExpandsGenericOrEmbeddedAdmission(t *testing.T) {
	review := strings.Repeat("a", 64)
	for _, args := range [][]string{{"route", "add", "default", "dev", "rz-mihomo", "table", "207", "proto", "boot", "metric", "0"}, {"route", "del", "default", "dev", "rz-mihomo", "table", "207"}, {"rule", "add", "priority", "31200", "lookup", "207"}} {
		if effectArguments(2, args) {
			t.Fatal("generic implicit IPv4 ABI expanded", args)
		}
		if !effectArguments(2, append([]string{"-4"}, args...)) {
			t.Fatal("actual command not equivalent to existing explicit ABI", args)
		}
		fake := &embeddedMihomoEffectAdmission{}
		ctx := WithCommandAdmission(context.Background(), fake)
		if mihomoLiveImplicitIPv4Effect(ctx, "/original/ip", review, 2, args) || fake.starts != 0 {
			t.Fatal("embedded fake became implicit effect admission")
		}
		for _, index := range []int{0, 1, 3} {
			if mihomoLiveImplicitIPv4Effect(ctx, "/original/ip", review, index, args) {
				t.Fatal("non-IP alias expanded")
			}
		}
	}
	for _, args := range [][]string{{"route", "flush", "table", "207"}, {"link", "set", "dev", "rz-mihomo", "up"}, {"-6", "route", "add", "default"}, {"rule", "show"}} {
		if mihomoLiveImplicitIPv4Effect(context.Background(), "/original/ip", review, 2, args) {
			t.Fatal("unissued or unreviewed command accepted", args)
		}
	}
}
