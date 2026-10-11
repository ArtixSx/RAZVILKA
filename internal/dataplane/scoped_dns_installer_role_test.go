package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Actual full scanner/file/socket/kernel ordering with explicit /proc and
// positive original-role leaf models. No real process is classified here.
func TestScopedDNSInstallerRoleRequiresPositiveBookendedProof(t *testing.T) {
	for _, kind := range []string{"named", "same-inode", "different-installer-image"} {
		t.Run(kind, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			f.process(t, 102, "other")
			switch kind {
			case "named":
				writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "102", "cmdline"), []byte("razvilka\x00"))
			case "same-inode":
				f.proof.sameExecutable = func(string, string) (bool, error) { return true, nil }
			case "different-installer-image":
				writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "102", "cmdline"), []byte("other\x00self-update-bootstrap-old193\x00"+strings.Repeat("a", 32)+"\x00"))
			}
			if err := f.verify(); err == nil {
				t.Fatal("controller accepted without positive original role")
			}
			calls := 0
			f.proof.installerPeerCheck = func(ctx context.Context, pid int) error {
				calls++
				if _, finite := ctx.Deadline(); !finite || pid != 102 {
					return errors.New("wrong original peer or unbounded context")
				}
				return ctx.Err()
			}
			if err := f.verify(); err != nil || calls < 4 || f.kernelCalls == 0 {
				t.Fatal("role skipped process rechecks or complete kernel inventory", calls, f.kernelCalls, err)
			}
		})
	}
}

func TestScopedDNSInstallerRoleCannotSkipRemainingInventory(t *testing.T) {
	for _, failure := range []string{"role-refused", "role-changed", "argv-changed", "stat-changed", "socket-unknown", "other-process-unknown", "kernel-refused"} {
		t.Run(failure, func(t *testing.T) {
			f := newScopedDNSInactiveFixture(t)
			f.process(t, 102, "other")
			path := filepath.Join(f.proof.procRoot, "102")
			writeDNSInactiveFixture(t, filepath.Join(path, "cmdline"), []byte("other\x00self-update-command-helper\x00"))
			calls := 0
			f.proof.installerPeerCheck = func(ctx context.Context, pid int) error {
				calls++
				if failure == "role-refused" || failure == "role-changed" && calls > 1 {
					return errors.New("modeled original role refused")
				}
				if failure == "argv-changed" {
					writeDNSInactiveFixture(t, filepath.Join(path, "cmdline"), []byte("changed\x00"))
				}
				if failure == "stat-changed" {
					data, err := os.ReadFile(filepath.Join(path, "stat"))
					if err != nil {
						return err
					}
					writeDNSInactiveFixture(t, filepath.Join(path, "stat"), []byte(strings.TrimSuffix(string(data), "17")+"18"))
				}
				return ctx.Err()
			}
			switch failure {
			case "socket-unknown":
				writeDNSInactiveFixture(t, filepath.Join(f.proof.netRoot, "tcp"), []byte("unknown socket table\n"))
			case "other-process-unknown":
				f.process(t, 103, "other")
				writeDNSInactiveFixture(t, filepath.Join(f.proof.procRoot, "103", "stat"), []byte("unknown incarnation"))
			case "kernel-refused":
				f.a.InactivityKernelCheck = func(context.Context, netidentity.Identity) error {
					return errors.New("modeled full kernel inventory refused")
				}
			}
			if err := f.verify(); err == nil {
				t.Fatal("positive installer role bypassed complete inventory", failure)
			}
		})
	}
}

func TestScopedDNSInstallerRoleCarrierIsFiniteOriginalAndNoRoleGrant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := &scopedDNSInstallerRole{adapter: updatecheck.NewSelfUpdateFileAdapter(), id: strings.Repeat("a", 32), original: ctx}
	r.deadline, _ = ctx.Deadline()
	r.self = r
	copy := *r
	if copy.current(ctx) == nil || r.check(ctx, 1) == nil {
		t.Fatal("copy or unverified peer supplied a role")
	}
	cancel()
	if r.current(context.Background()) == nil {
		t.Fatal("expired source admitted future classification")
	}
	a := &ScopedDNSAdapter{}
	if a.BindInstallerControllerRoles(context.Background(), nil, strings.Repeat("a", 32)) == nil || a.installerRole != nil {
		t.Fatal("missing original fixed provider or finite context installed role reader")
	}
}

func TestScopedDNSOrdinaryInstallerBindingRequiresVerifiedCurrentController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a := &ScopedDNSAdapter{StateRoot: filepath.Join(installpath.State+"/dataplane", scopedDNSAdapterID)}
	// The finite construction context and canonical path do not replace the
	// actual original caller/group proof, and a refusal installs no reader.
	if err := a.BindOrdinaryInstallerControllerRoles(ctx, &updatecheck.SelfUpdateFileAdapter{}, strings.Repeat("a", 32)); !errors.Is(err, ErrScopedDNSRuntimeInactive) || a.installerRole != nil {
		t.Fatal("unverified current controller installed an ordinary peer reader", err)
	}
	if err := a.BindOrdinaryInstallerControllerRoles(context.Background(), updatecheck.NewSelfUpdateFileAdapter(), strings.Repeat("a", 32)); !errors.Is(err, ErrScopedDNSRuntimeInactive) || a.installerRole != nil {
		t.Fatal("unbounded current controller installed an ordinary peer reader", err)
	}
}
