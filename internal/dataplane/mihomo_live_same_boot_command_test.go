package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This exercises the real Gate/Start leaf with a modeled private CORE owner.
// It cannot establish parent/process absence or issue an external cold owner.
func TestMihomoSameBootCommandStartIsOneUseAndOriginal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate := &operationgate.Gate{}
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
		t.Fatal(err)
	}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	cleanup, err := control.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	o := &mihomoSameBootCleanup{control: control, cleanup: cleanup}
	o.self = o
	c := &mihomoSameBootCommand{owner: o, name: "/actual/ip", args: []string{"rule", "del", "priority", "31200", "lookup", "207"}, review: strings.Repeat("a", 64), open: true}
	c.self = c
	actual := context.WithValue(held, mihomoSameBootCommandKey{}, c)
	if !OriginalMihomoSameBootCommand(actual, c, c.name, c.args, c.review) {
		t.Fatal("original comparison refused")
	}
	starts := 0
	cause := errors.New("actual Start leaf refused")
	begin := func() error { starts++; return cause }
	for _, change := range []string{"context", "name", "args", "review", "copy"} {
		cc, cn, ca, cr, ct := c, c.name, slices.Clone(c.args), c.review, actual
		switch change {
		case "context":
			ct = held
		case "name":
			cn += "-foreign"
		case "args":
			ca[1] = "add"
		case "review":
			cr = strings.Repeat("b", 64)
		case "copy":
			cc = &mihomoSameBootCommand{self: c, owner: o, name: c.name, args: c.args, review: c.review, open: true}
		}
		if cc.WithStart(ct, cn, ca, cr, begin) == nil || starts != 0 {
			t.Fatal("foreign/copy reached Start", change)
		}
	}
	if err := c.WithStart(actual, c.name, c.args, c.review, begin); !errors.Is(err, cause) || starts != 1 {
		t.Fatal("original exception/Start lost", err, starts)
	}
	if c.WithStart(actual, c.name, c.args, c.review, begin) == nil || starts != 1 || OriginalMihomoSameBootCommand(actual, c, c.name, c.args, c.review) {
		t.Fatal("consumed token reused")
	}
}

func TestMihomoSameBootDeleteABIRejectsWiderPolicy(t *testing.T) {
	d := mihomoLiveDefinitionFixture(t)
	o := &mihomoSameBootCleanup{inputs: &mihomoSameBootInputs{definition: d}, read: &mihomoColdReadRunner{tools: SyntheticDNSCommandTools{IP: "/original/ip", IPTables: "/original/iptables"}, ip6: "/original/ip6tables"}}
	rules, err := kernelRulesForPolicy(d.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		args := kernelRuleArgs("del", r)
		if ok, err := o.deleteCommand(t.Context(), o.read.tools.IP, args); !ok || err != nil {
			t.Fatal("exact original rule refused", err)
		}
		args = slices.Clone(args)
		for n := range args {
			if args[n] == "del" {
				args[n] = "add"
			}
		}
		// Add must refuse before any default-route read or kernel action.
		if mihomoLiveEffectCommand(true, args) == false {
			t.Fatal("add escaped effect classification")
		}
	}
	for _, table := range proxyFirewallTables(d.Policy) {
		name := o.read.tools.IPTables
		if table.v6 {
			name = o.read.ip6
		}
		for _, args := range [][]string{{"-t", table.table, "-X", table.chain}, append([]string{"-t", table.table, "-D", table.parent}, table.jumps[0]...)} {
			if ok, err := o.deleteCommand(t.Context(), name, args); !ok || err != nil {
				t.Fatal("exact compiled deletion refused", err)
			}
		}
		for _, args := range [][]string{{"-t", table.table, "-F", table.chain}, {"-t", table.table, "-X", "foreign"}, {"-t", table.table, "-N", table.chain}, {"-t", table.table, "-D", table.parent, "-j", table.chain}} {
			if ok, err := o.deleteCommand(t.Context(), name, args); ok || err != nil {
				t.Fatal("wider deletion admitted", args, err)
			}
		}
	}
}
