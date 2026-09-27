package dataplane

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNFQWS2RollbackVerification(t *testing.T) {
	for _, scenario := range []string{"restored", "already-restored", "config", "user-list", "ipset-list", "init", "lease", "process", "rules", "other-chain", "other-queue", "read-failed", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			a, runner, root := newOwnedNFQWS2(t)
			a.IPTablesSave = "iptables-save"
			first := stageOwnedNFQWS2(t, a, root, "old.example")
			if err := a.Activate(context.Background(), Plan{}, first); err != nil {
				t.Fatal(err)
			}
			next := stageOwnedNFQWS2(t, a, root, "next.example")
			if err := a.Activate(context.Background(), Plan{}, next); err != nil {
				t.Fatal(err)
			}
			if err := a.Rollback(context.Background(), Plan{}, next); err != nil {
				t.Fatal(err)
			}
			if scenario == "already-restored" {
				if err := a.Rollback(context.Background(), Plan{}, next); err != nil {
					t.Fatal(err)
				}
			}
			paths := map[string]string{"config": a.ConfigPath, "user-list": a.UserListPath, "ipset-list": a.IPSetListPath, "init": a.InitPath}
			if path := paths[scenario]; path != "" {
				if err := os.WriteFile(path, []byte("changed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "lease" {
				if err := a.writeLease(nil); err != nil {
					t.Fatal(err)
				}
			}
			a.Runner = nfqws2RunFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == a.InitPath && scenario == "process" {
					return []byte("not running"), errors.New("exit 1")
				}
				if name == "iptables-save" {
					switch scenario {
					case "rules":
						return []byte("# no rules"), nil
					case "other-chain":
						return []byte("-A foreign -j NFQUEUE --queue-num 300"), nil
					case "other-queue":
						return []byte("-A nfqws_post -j NFQUEUE --queue-num 301"), nil
					case "read-failed":
						return nil, errors.New("exit 4")
					}
				}
				return runner.Run(ctx, name, args...)
			})
			runner.calls = nil
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			ok, err := a.VerifyRollback(ctx, Plan{}, next)
			want := scenario == "restored" || scenario == "already-restored"
			if ok != want || want && err != nil || !want && err == nil {
				t.Fatalf("confirmed=%v err=%v", ok, err)
			}
			for _, call := range runner.calls {
				if !strings.HasSuffix(call, " status") && call != "iptables-save " {
					t.Fatalf("verifier mutated runtime: %s", call)
				}
			}
		})
	}
}

func TestNFQWS2RollbackWithoutOwnershipIsUnconfirmed(t *testing.T) {
	a, _, root := newOwnedNFQWS2(t)
	transaction := stageOwnedNFQWS2(t, a, root, "first.example")
	if ok, err := a.VerifyRollback(context.Background(), Plan{}, transaction); ok || err != nil {
		t.Fatalf("confirmed=%v err=%v", ok, err)
	}
}

func TestNFQWS2RollbackLiteralQueue(t *testing.T) {
	for _, test := range []struct {
		config, queue string
		ok            bool
	}{
		{"", "300", true}, {"NFQUEUE_NUM=123", "123", true}, {"NFQUEUE_NUM=\"123\" # queue", "123", true},
		{"export NFQUEUE_NUM='123'", "123", true}, {"NFQUEUE_NUM=$(echo 300)", "", false},
		{"NFQUEUE_NUM=0", "", false}, {"NFQUEUE_NUM=65536", "", false}, {"# NFQUEUE_NUM=123", "300", true},
	} {
		if queue, ok := nfqws2LiteralQueue([]byte(test.config)); queue != test.queue || ok != test.ok {
			t.Fatalf("%q: %q %v", test.config, queue, ok)
		}
	}
}
