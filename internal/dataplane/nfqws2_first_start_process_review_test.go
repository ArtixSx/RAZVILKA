package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func firstStartProcessReviewFixture(t *testing.T) (*nfqws2InactiveFixture, components.NFQWSRuntimeProcessIdentity) {
	t.Helper()
	f := newNFQWS2InactiveFixture(t)
	prefix := filepath.Join(filepath.Dir(filepath.Dir(f.a.StateRoot)), "opt")
	f.a.InitPath = filepath.Join(prefix, "etc", "init.d", "S51nfqws2")
	f.a.ConfigPath = filepath.Join(prefix, "etc", "nfqws2", "nfqws2.conf")
	f.a.UserListPath = filepath.Join(prefix, "etc", "nfqws2", "lists", "user.list")
	f.a.IPSetListPath = filepath.Join(prefix, "etc", "nfqws2", "lists", "ipset.list")
	f.source.startup = *f.a
	receipt := components.NFQWSRuntimeProcessIdentity{PID: 42, ParentPID: 1, Group: 42, Start: "123", BootID: f.source.identity.BootID, Executable: filepath.Join(prefix, "usr", "bin", "nfqws2"), ArgumentsSHA256: strings.Repeat("a", 64)}
	f.a.firstStartProcessRead = func(pid int) (components.NFQWSRuntimeProcessIdentity, error) {
		if pid != receipt.PID {
			return components.NFQWSRuntimeProcessIdentity{}, errors.New("wrong PID")
		}
		return receipt, nil
	}
	pidPath := f.a.firstStartPIDPath()
	if err := os.MkdirAll(filepath.Dir(pidPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidPath, []byte("42\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f.process(t, 42, "nfqws2", 'S', 0, "nfqws2\x00--qnum=300\x00")
	return f, receipt
}

func firstStartProcessModelReview(f *nfqws2InactiveFixture, ctx context.Context, receipt components.NFQWSRuntimeProcessIdentity, closing func()) error {
	return f.a.reviewFirstStartProcessWithSources(ctx, receipt, f.proof, func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
		f.uses++
		err := use(c, f.source.identity)
		if closing != nil {
			closing()
		}
		return err
	})
}

func TestNFQWSFirstStartProcessReviewRequiresWholeInventoryAndExactPIDFile(t *testing.T) {
	for _, which := range []string{"only-original", "pidfile-foreign", "second-nfq-name", "second-nfq-exe", "second-nfq-queue", "second-nfq-zombie", "stock-pgrep-wrapper", "unknown-process", "original-missing", "identity-changed", "source-changed", "unbounded"} {
		t.Run(which, func(t *testing.T) {
			f, receipt := firstStartProcessReviewFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			switch which {
			case "pidfile-foreign":
				if err := os.WriteFile(f.a.firstStartPIDPath(), []byte("43\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "second-nfq-name":
				f.process(t, 43, "nfqws2", 'S', 0, "nfqws2\x00--qnum=301\x00")
			case "second-nfq-exe":
				f.process(t, 43, "other", 'S', 0, "other\x00")
				f.proof.readlink = func(path string) (string, error) {
					if strings.Contains(path, string(filepath.Separator)+"43"+string(filepath.Separator)) {
						return "/usr/bin/nfqws2", nil
					}
					return "/usr/bin/controller", nil
				}
			case "second-nfq-queue":
				f.process(t, 43, "other", 'S', 0, "other\x00--qnum=301\x00")
			case "second-nfq-zombie":
				f.process(t, 43, "nfqws2", 'Z', 0, "nfqws2\x00")
			case "stock-pgrep-wrapper":
				f.process(t, 43, "other", 'S', 0, "sh\x00-c\x00"+receipt.Executable+" --start\x00")
			case "unknown-process":
				f.process(t, 43, "other", 'S', 0, "")
			case "original-missing":
				if err := os.Rename(filepath.Join(f.proof.procRoot, "42"), filepath.Join(filepath.Dir(f.proof.procRoot), "original42")); err != nil {
					t.Fatal(err)
				}
			case "identity-changed":
				f.a.firstStartProcessRead = func(int) (components.NFQWSRuntimeProcessIdentity, error) {
					changed := receipt
					changed.Start = "124"
					return changed, nil
				}
			case "source-changed":
				f.a.ConfigPath += ".foreign"
			case "unbounded":
				ctx = context.Background()
			}
			err := firstStartProcessModelReview(f, ctx, receipt, nil)
			if (err == nil) != (which == "only-original") {
				t.Fatal("unexpected whole-process admission", which, err)
			}
		})
	}
}

func TestNFQWSFirstStartProcessReviewRechecksPIDFileAndBirthAtClosure(t *testing.T) {
	for _, which := range []string{"pidfile", "process", "source", "new-process"} {
		t.Run(which, func(t *testing.T) {
			f, receipt := firstStartProcessReviewFixture(t)
			err := firstStartProcessModelReview(f, nfqws2InactiveTestContext(t), receipt, func() {
				switch which {
				case "pidfile":
					if err := os.WriteFile(f.a.firstStartPIDPath(), []byte("43\n"), 0644); err != nil {
						t.Fatal(err)
					}
				case "process":
					f.a.firstStartProcessRead = func(int) (components.NFQWSRuntimeProcessIdentity, error) {
						changed := receipt
						changed.Start = "124"
						return changed, nil
					}
				case "source":
					f.a.InitPath += ".foreign"
				case "new-process":
					f.process(t, 43, "nfqws2", 'S', 0, "nfqws2\x00--qnum=301\x00")
				}
			})
			if err == nil {
				t.Fatal("closing mutation remained admitted")
			}
		})
	}
}
