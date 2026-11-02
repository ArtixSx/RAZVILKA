//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

// Genuine five private leases, Gate and policy receipt/marker/root FDs. The
// private CORE owner and kernel transitions are explicitly modeled. No native
// command or complete same-boot absence source is issued by this fixture.
func sameBootPolicyFixture(t *testing.T, use func(context.Context, *mihomoSameBootPolicy, *policyAdditionSession)) {
	t.Helper()
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		gate := &operationgate.Gate{}
		controlRoot := filepath.Join(t.TempDir(), "control")
		if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
			t.Fatal(err)
		}
		held, release, err := gate.ExclusiveContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		control, err := gate.ReviewControlEpoch(held, controlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		cleanup, err := control.ReviewExclusiveCleanup(held)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(state, "mihomo", "policy-generations", strings.Repeat("1", 32))
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		options := policyAdditionOptions{boot: func() (string, error) { return i.definition.NetworkIdentity.BootID, nil }}
		if err := applyPolicyAddition(held, &recordedPolicyFakeRunner{}, "ip", i.definition.Policy, path, options); err != nil {
			t.Fatal("modeled initial kernel publication", err)
		}
		o := &mihomoSameBootCleanup{inputs: i, control: control, cleanup: cleanup, controlRoot: controlRoot}
		o.self = o
		c := &mihomoSameBootPolicy{owner: o, path: path}
		c.self = c
		o.policy = c
		defer c.close()
		c.root, err = openBootRetirementRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		c.info, err = c.root.Stat(".")
		if err != nil {
			t.Fatal(err)
		}
		c.marker, err = openMihomoColdRecord(c.root, policyAdditionLock, []byte(policyAdditionMarker))
		if err != nil {
			t.Fatal(err)
		}
		c.record, err = openMihomoColdRecord(c.root, policyAdditionFile, nil)
		if err != nil {
			t.Fatal(err)
		}
		s, err := openPolicyAdditionSession(held, i.definition.Policy, path, options)
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		scoped := context.WithValue(held, mihomoSameBootPolicyKey{}, c)
		if err := s.load(scoped); err != nil {
			t.Fatal(err)
		}
		use(scoped, c, s)
	})
}

func TestMihomoSameBootPolicyRetainsActualWriterAndRetriesACK(t *testing.T) {
	sameBootPolicyFixture(t, func(ctx context.Context, c *mihomoSameBootPolicy, s *policyAdditionSession) {
		original := c.record.info
		lost := errors.New("original receipt publication ACK lost")
		c.fault = func() error { return lost }
		// A modeled terminal transition exercises the REAL session writer only.
		s.doc.Steps[len(s.doc.Steps)-1].State = "removed"
		if err := s.save(ctx); !errors.Is(err, lost) {
			t.Fatal("writer exception hidden", err)
		}
		if !c.pending || c.record.current() != nil || os.SameFile(original, c.record.info) {
			t.Fatal("actual new authored FD was not retained before ACK")
		}
		published := c.record.info
		c.fault = nil
		if err := s.load(ctx); err != nil || c.pending || s.doc.Steps[len(s.doc.Steps)-1].State != "removed" {
			t.Fatal("same cursor cannot repeat actual durable ACK", err)
		}
		named, err := c.root.Lstat(policyAdditionFile)
		if err != nil || !os.SameFile(published, named) {
			t.Fatal("retry reopened/replaced original target", err)
		}
	})
}

func TestMihomoSameBootPolicyRefusesForeignReceiptMarkerRootAndCursor(t *testing.T) {
	for _, kind := range []string{"receipt", "marker", "root", "copied", "expired"} {
		t.Run(kind, func(t *testing.T) {
			sameBootPolicyFixture(t, func(ctx context.Context, c *mihomoSameBootPolicy, s *policyAdditionSession) {
				switch kind {
				case "receipt", "marker":
					r := c.record
					if kind == "marker" {
						r = c.marker
					}
					if err := c.root.WriteFile("foreign", r.data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := c.root.Rename("foreign", r.name); err != nil {
						t.Fatal(err)
					}
				case "root":
					if err := os.Rename(c.path, c.path+"-original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(c.path, 0700); err != nil {
						t.Fatal(err)
					}
				case "copied":
					copy := &mihomoSameBootPolicy{self: c, owner: c.owner, path: c.path, root: c.root, info: c.info, marker: c.marker, record: c.record}
					ctx = context.WithValue(ctx, mihomoSameBootPolicyKey{}, copy)
				case "expired":
					if err := c.close(); err != nil {
						t.Fatal(err)
					}
				}
				if s.load(ctx) == nil || s.save(ctx) == nil {
					t.Fatal("foreign original accepted", kind)
				}
			})
		})
	}
}

func TestMihomoSameBootPolicySessionCloseKeepsOriginalException(t *testing.T) {
	sameBootPolicyFixture(t, func(ctx context.Context, c *mihomoSameBootPolicy, s *policyAdditionSession) {
		copy := *s
		copy.close()
		if err := s.load(ctx); err != nil {
			t.Fatal("copied session closed original", err)
		}
		if err := s.lock.Close(); err != nil {
			t.Fatal(err)
		} // Genuine failed subsequent original Close.
		s.close()
		s.close()
		if !errors.Is(c.closeErr, os.ErrClosed) {
			t.Fatal("original writer-marker close cause lost", c.closeErr)
		}
		if err := s.load(ctx); !errors.Is(err, os.ErrClosed) {
			t.Fatal("closed writer session revived or lost close cause", err)
		}
	})
}
