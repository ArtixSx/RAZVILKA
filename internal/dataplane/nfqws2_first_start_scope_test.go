package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestNFQWS2FirstStartScopeRequiresKnownEmptyPolicyAndCurrentSingleWAN(t *testing.T) {
	original, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	a := NewNFQWS2Adapter()
	if err := a.bindStateRoot(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"empty", "known-ansi-empty", "unknown-ansi", "nonempty-policy", "wrong-wan", "multiple-interfaces", "unknown-source"} {
		t.Run(which, func(t *testing.T) {
			policy := []byte(nil)
			wan := "eth3"
			sourceErr := error(nil)
			config := bytes.Clone(original)
			switch which {
			case "known-ansi-empty":
				policy = []byte{0x1b, '[', 'K', 0x1b, '[', 'K'}
			case "unknown-ansi":
				policy = []byte{0x1b, '[', 'K'}
			case "nonempty-policy":
				policy = []byte("policy entries require a reviewed formatter\n")
			case "wrong-wan":
				wan = "nwg0"
			case "multiple-interfaces":
				config = bytes.Replace(config, []byte("ISP_INTERFACE=\"eth3\""), []byte("ISP_INTERFACE=\"eth3 eth4\""), 1)
			case "unknown-source":
				sourceErr = errors.New("incomplete source")
			}
			a.firstStartScopeRead = func(context.Context) ([]byte, string, error) { return policy, wan, sourceErr }
			err := a.reviewFirstStartScope(firstStartContext(t), config, false)
			pass := which == "empty" || which == "known-ansi-empty"
			if pass && err != nil || !pass && !errors.Is(err, ErrNFQWSFirstStartScope) {
				t.Fatal(which, err)
			}
		})
	}
}

func TestNFQWS2FirstStartScopeRefusesResolvedPolicyAfterLaunch(t *testing.T) {
	a := NewNFQWS2Adapter()
	root := t.TempDir()
	a.ConfigPath = filepath.Join(root, "nfqws2.conf")
	if err := a.bindStateRoot(root); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := a.owner()
	config, err := engineconfig.NFQWSFirstStartConfig(original, owner, []string{"selected.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.firstStartScopeRead = func(context.Context) ([]byte, string, error) { return nil, "eth3", nil }
	for _, mark := range []string{"", "0xffff/0x0fffffff"} {
		run := []byte("ISP_INTERFACE=\"eth3\"\nIPV6_ENABLED=0\nTCP_PORTS=443\nUDP_PORTS=\nPOLICY_NAME=\"nfqws\"\nPOLICY_EXCLUDE=0\nPOLICY_MARK=\"" + mark + "\"\nNFQUEUE_NUM=300\n")
		if err := os.WriteFile(a.ConfigPath+".run", run, 0600); err != nil {
			t.Fatal(err)
		}
		err := a.reviewFirstStartScope(firstStartContext(t), config, true)
		if mark == "" && err != nil || mark != "" && !errors.Is(err, ErrNFQWSFirstStartScope) {
			t.Fatal(mark, err)
		}
	}
}

func TestNFQWS2FirstStartPolicyPreflightAndPostStartFence(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"preflight", "post-start", "wrong-wan"} {
		t.Run(which, func(t *testing.T) {
			f := newFirstStartFixture(t)
			switch which {
			case "preflight":
				f.policyFacts = []byte("unreviewed policy table\n")
			case "post-start":
				f.policyMark = "0xffff/0x0fffffff"
			case "wrong-wan":
				f.wan = "nwg0"
			}
			result, err := f.m.Apply(firstStartContext(t), f.plan, nil)
			if err == nil {
				t.Fatal("scope mismatch committed")
			}
			if which == "post-start" {
				if result.State != "rolled-back" || f.running || f.ownedRules {
					t.Fatal("post-start narrowing did not roll back", result, err)
				}
			} else {
				for _, call := range f.calls {
					if firstStartRuntimeAction(call) {
						t.Fatal("scope preflight changed runtime", call)
					}
				}
			}
		})
	}
}
