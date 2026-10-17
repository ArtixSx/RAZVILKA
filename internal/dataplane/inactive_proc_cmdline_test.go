package dataplane

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInactiveProcArgumentsPreserveFinalBytesAndBounds(t *testing.T) {
	for _, raw := range []string{"daemon: worker process", "daemon\x00--config=/private/managed.json", "daemon\x00--config=/private/managed.json\x00"} {
		args, ok := inactiveProcArguments([]byte(raw))
		want := strings.Split(strings.TrimSuffix(raw, "\x00"), "\x00")
		if !ok || !reflect.DeepEqual(args, want) {
			t.Fatalf("final argument changed: %q", args)
		}
	}
	for _, raw := range []string{"", "\x00", "\x00daemon", strings.Repeat("x", (64<<10)+1), "daemon\x00" + strings.Repeat("arg\x00", 256) + "final"} {
		if _, ok := inactiveProcArguments([]byte(raw)); ok {
			t.Fatal("malformed or oversized argv accepted")
		}
	}
}

func TestInactiveObserversAcceptRewrittenTitleOnlyWithOtherProofs(t *testing.T) {
	for _, observer := range []string{"proxy", "nfq"} {
		for _, kind := range []string{"stock-title", "known-exe", "known-argv", "managed-final-argument", "empty-argv", "overflow", "missing-exe", "invalid-stat"} {
			t.Run(observer+"/"+kind, func(t *testing.T) {
				// Nonsecret setproctitle shape of an ordinary stock daemon; no
				// executable-name exemption is used by either actual observer.
				image := "nginx: worker process"
				if kind == "empty-argv" {
					image = "\x00nginx"
				}
				if kind == "overflow" {
					image = strings.Repeat("x", (64<<10)+1)
				}
				var err error
				if observer == "proxy" {
					f := newInactiveFixture(t, "xray")
					if kind == "known-argv" {
						image = f.a.EngineBin
					}
					if kind == "managed-final-argument" {
						image = "unrelated\x00--config=" + f.a.engineConfigPath()
					}
					f.writeProcess(t, 865, "S", "0", image)
					path := filepath.Join(f.proof.procRoot, "865")
					if kind == "known-exe" {
						inactiveWrite(t, filepath.Join(path, "exe"), []byte(f.a.EngineBin))
					}
					if kind == "missing-exe" {
						f.proof.readlink = func(string) (string, error) { return "", nil }
					}
					if kind == "invalid-stat" {
						inactiveWrite(t, filepath.Join(path, "stat"), []byte("invalid"))
					}
					err = f.a.verifyRuntimeInactive(context.Background(), f.proof)
				} else {
					f := newNFQWS2InactiveFixture(t)
					if kind == "known-argv" {
						image = "nfqws2"
					}
					if kind == "managed-final-argument" {
						image = "unrelated\x00--config=" + f.a.ConfigPath
					}
					f.process(t, 865, "nginx", 'S', 0, image)
					if kind == "known-exe" {
						f.proof.readlink = func(string) (string, error) { return "/usr/bin/nfqws2", nil }
					}
					if kind == "missing-exe" {
						f.proof.readlink = func(string) (string, error) { return "", nil }
					}
					if kind == "invalid-stat" {
						inactiveWrite(t, filepath.Join(f.proof.procRoot, "865", "stat"), []byte("invalid"))
					}
					err = nfqws2InactiveProcesses(context.Background(), f.proof, f.a)
				}
				if (err == nil) != (kind == "stock-title") {
					t.Fatalf("rewritten title proof kind=%s err=%v", kind, err)
				}
			})
		}
	}
}
