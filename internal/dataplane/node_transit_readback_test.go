package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func nodeRouterTransitReadbackFixture(t *testing.T) (*nodeRouterTransitReadback, *nodeTransitTestRunner, *nodeTransitAuthority) {
	t.Helper()
	lease, runner, authority := nodeTransitFixture(t)
	info, err := os.Lstat(lease.root)
	if err != nil {
		t.Fatal(err)
	}
	// Windows FileInfo resolves its ID lazily; capture it while the original
	// fixture directory still exists. Linux Lstat already contains the inode.
	if !os.SameFile(info, info) {
		t.Fatal("fixture cannot capture original directory identity")
	}
	readback := &nodeRouterTransitReadback{spec: lease.spec, root: lease.root, info: info, lease: lease,
		owner: func(ctx context.Context) error { return errors.Join(ctx.Err(), authority.guardErr) }}
	return readback, runner, authority
}

// Snapshot all fixture names, modes and bytes; atime changes from reads are not
// metadata authority. No test inspects a real runtime or network namespace.
func nodeRouterTransitReadbackTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += "/" + routeidentity.Hash(data)
		}
		result[name] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func nodeRouterTransitReadbackNoEffects(t *testing.T, runner *nodeTransitTestRunner, callStart, adds, deletes int) {
	t.Helper()
	if runner.adds != adds || runner.deletes != deletes {
		t.Fatal("readback performed a kernel mutation")
	}
	for _, call := range runner.calls[callStart:] {
		if call != "ip -N rule show" && call != "ip -N -6 rule show" {
			t.Fatal("readback widened its read-only command scope", call)
		}
	}
}

func nodeRouterTransitReadbackDetached(lease *nodeTransitLease) {
	lease.runtime.guard = func(context.Context, NodeTransitSpec) error { panic("readback reentered original Manager guard") }
	lease.runtime.register = func(context.Context, NodeTransitSpec, string, string) error {
		panic("readback reentered original registration")
	}
	lease.runtime.preflight = func(context.Context, NodeTransitSpec) error { panic("readback reentered original preflight") }
	lease.runtime.beforeDelete = func(context.Context, NodeTransitSpec) error { panic("readback reentered original deletion guard") }
}

func TestNodeRouterTransitReadbackPreparedOwnerChecksWithoutRPC(t *testing.T) {
	b, runner, _ := nodeRouterTransitReadbackFixture(t)
	before := nodeRouterTransitReadbackTree(t, b.root)
	owners := 0
	b.owner = func(ctx context.Context) error { owners++; return ctx.Err() }
	nodeRouterTransitReadbackDetached(b.lease)
	ctx := context.WithValue(context.Background(), networkPolicyTransitReadbackKey{}, networkPolicyTransitReadback(b.readback))
	readback, ok := ctx.Value(networkPolicyTransitReadbackKey{}).(networkPolicyTransitReadback)
	if !ok {
		t.Fatal("private operation context lost owner readback")
	}
	if err := readback(ctx, b.spec, b.root, b.lease.digest, networkPolicyTransitPrepared); err != nil {
		t.Fatal(err)
	}
	if owners != 2 || len(runner.calls) != 0 || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, b.root)) {
		t.Fatal("prepared identity check mutated or skipped closing owner")
	}
}

func TestNodeRouterTransitReadbackPreparedRejectsChangedBindingAndIdentity(t *testing.T) {
	for _, mode := range []string{"spec", "root", "digest", "mode", "nil-context", "canceled", "nil-readback", "nil-lease", "nil-owner", "nil-info", "lease-spec", "lease-root", "root-incarnation", "owner-revoked", "closing-ifindex"} {
		t.Run(mode, func(t *testing.T) {
			b, runner, authority := nodeRouterTransitReadbackFixture(t)
			spec, root, digest, phase := b.spec, b.root, b.lease.digest, networkPolicyTransitPrepared
			ctx := context.Background()
			switch mode {
			case "spec":
				spec.RuntimeID = strings.Repeat("e", 64)
			case "root":
				root = privateScopedXrayFixtureDir(t)
			case "digest":
				digest = strings.Repeat("f", 64)
			case "mode":
				phase = networkPolicyTransitReadbackMode("applied")
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-readback":
				b = nil
			case "nil-lease":
				b.lease = nil
			case "nil-owner":
				b.owner = nil
			case "nil-info":
				b.info = nil
			case "lease-spec":
				b.lease.spec.RuntimeID = strings.Repeat("e", 64)
			case "lease-root":
				b.lease.root = privateScopedXrayFixtureDir(t)
			case "root-incarnation":
				backup := filepath.Join(privateScopedXrayFixtureDir(t), "old-root")
				if err := os.Rename(root, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			case "owner-revoked":
				authority.guardErr = ErrReviewChanged
			case "closing-ifindex":
				owners := 0
				b.owner = func(context.Context) error {
					owners++
					if owners == 2 {
						authority.iface.Index++
					}
					return nil
				}
			}
			// Snapshot the bound fixture root, rather than a supplied wrong path.
			before := nodeRouterTransitReadbackTree(t, authority.root)
			if err := b.readback(ctx, spec, root, digest, phase); err == nil {
				t.Fatal("changed/missing resource obtained prepared authority")
			}
			if len(runner.calls) != 0 || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, authority.root)) {
				t.Fatal("failed preparation created metadata or called runner")
			}
		})
	}
}

func TestNodeRouterTransitReadbackRemovedUsesIndependentReadonlyMirror(t *testing.T) {
	b, runner, authority := nodeRouterTransitReadbackFixture(t)
	ctx := context.Background()
	if err := b.lease.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.lease.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.adds != 1 || runner.deletes != 1 {
		t.Fatal("fixture did not actually add and remove exact transit")
	}
	before := nodeRouterTransitReadbackTree(t, b.root)
	calls, registrations := len(runner.calls), authority.registrations
	nodeRouterTransitReadbackDetached(b.lease)
	if err := b.readback(ctx, b.spec, b.root, b.lease.digest, networkPolicyTransitRemoved); err != nil {
		t.Fatal("mirror depended on original Manager callback", err)
	}
	nodeRouterTransitReadbackNoEffects(t, runner, calls, 1, 1)
	if len(runner.calls)-calls != 2 || authority.registrations != registrations || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, b.root)) {
		t.Fatal("removed readback skipped both families or changed settlement")
	}
}

func TestNodeRouterTransitReadbackRemovedRejectsForeignUnknownBothFamilies(t *testing.T) {
	for _, mode := range []string{"exact-copy4", "duplicate4", "foreign4", "unknown4", "foreign6", "duplicate6", "unknown6", "read-error4", "read-error6", "missing-receipt", "missing-lock", "corrupt-lock"} {
		t.Run(mode, func(t *testing.T) {
			b, runner, authority := nodeRouterTransitReadbackFixture(t)
			ctx := context.Background()
			if err := b.lease.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			if err := b.lease.Remove(ctx); err != nil {
				t.Fatal(err)
			}
			line := runner.line()
			switch mode {
			case "exact-copy4":
				runner.rules[4] = []string{line}
			case "duplicate4":
				runner.rules[4] = []string{line, line}
			case "foreign4":
				runner.rules[4] = []string{strings.Replace(line, b.spec.Interface, "eth0", 1)}
			case "unknown4":
				runner.rules[4] = []string{line + " not"}
			case "foreign6":
				runner.rules[6] = []string{line}
			case "duplicate6":
				runner.rules[6] = []string{line, line}
			case "unknown6":
				runner.rules[6] = []string{"unrecognized kernel row"}
			case "read-error4":
				runner.readErrors[4] = errors.New("IPv4 unavailable")
			case "read-error6":
				runner.readErrors[6] = errors.New("IPv6 unavailable")
			case "missing-receipt":
				if err := os.Remove(filepath.Join(b.root, policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "missing-lock":
				if err := os.Remove(filepath.Join(b.root, policyAdditionLock)); err != nil {
					t.Fatal(err)
				}
			case "corrupt-lock":
				if err := os.WriteFile(filepath.Join(b.root, policyAdditionLock), []byte("foreign marker"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := nodeRouterTransitReadbackTree(t, b.root)
			calls, registrations := len(runner.calls), authority.registrations
			rows := map[int]string{4: strings.Join(runner.rules[4], "\n"), 6: strings.Join(runner.rules[6], "\n")}
			nodeRouterTransitReadbackDetached(b.lease)
			if err := b.readback(ctx, b.spec, b.root, b.lease.digest, networkPolicyTransitRemoved); err == nil {
				t.Fatal("foreign/unknown state obtained removed settlement")
			}
			nodeRouterTransitReadbackNoEffects(t, runner, calls, 1, 1)
			closingRows := map[int]string{4: strings.Join(runner.rules[4], "\n"), 6: strings.Join(runner.rules[6], "\n")}
			if authority.registrations != registrations || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, b.root)) || !reflect.DeepEqual(rows, closingRows) {
				t.Fatal("negative readback adopted or changed foreign state")
			}
		})
	}
}

func nodeRouterTransitReadbackUnusedFixture(t *testing.T, verify bool) (*nodeRouterTransitReadback, *nodeTransitTestRunner, *nodeTransitAuthority) {
	t.Helper()
	b, runner, authority := nodeRouterTransitReadbackFixture(t)
	authority.registerErr = errors.New("original registration refusal")
	applyErr := b.lease.Apply(context.Background())
	if !errors.As(errors.Join(errors.New("outer result"), applyErr), &b.unused) || !isNodeTransitBeforeEffects(applyErr) {
		t.Fatal("fixture lost original typed before-effects error", applyErr)
	}
	if verify {
		if err := b.lease.VerifyUnused(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return b, runner, authority
}

func TestNodeRouterTransitReadbackUnusedRequiresVerifiedOriginalOneShotProof(t *testing.T) {
	for _, mode := range []string{"before-VerifyUnused", "no-error-pointer", "other-lease"} {
		t.Run(mode, func(t *testing.T) {
			b, runner, _ := nodeRouterTransitReadbackUnusedFixture(t, mode != "before-VerifyUnused")
			proof := b.unused
			if mode == "no-error-pointer" {
				b.unused = nil
			}
			if mode == "other-lease" {
				other, err := newNodeTransitLeaseWithOptions(b.spec, b.root, b.lease.runtime, b.lease.options)
				if err != nil {
					t.Fatal(err)
				}
				b.lease = other
			}
			calls := len(runner.calls)
			before := nodeRouterTransitReadbackTree(t, b.root)
			nodeRouterTransitReadbackDetached(b.lease)
			if err := b.readback(context.Background(), b.spec, b.root, b.lease.digest, networkPolicyTransitUnused); err == nil || proof.claimed.Load() {
				t.Fatal("unverified/substituted proof settled unused resource", err)
			}
			nodeRouterTransitReadbackNoEffects(t, runner, calls, 0, 0)
			if !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, b.root)) {
				t.Fatal("failed unused proof created a lock or receipt")
			}
		})
	}
	b, runner, authority := nodeRouterTransitReadbackUnusedFixture(t, true)
	before := nodeRouterTransitReadbackTree(t, b.root)
	calls, registrations := len(runner.calls), authority.registrations
	nodeRouterTransitReadbackDetached(b.lease)
	if err := b.readback(context.Background(), b.spec, b.root, b.lease.digest, networkPolicyTransitUnused); err != nil || !b.unused.claimed.Load() {
		t.Fatal("matching verified live proof was not consumed", err)
	}
	if err := b.readback(context.Background(), b.spec, b.root, b.lease.digest, networkPolicyTransitUnused); err == nil {
		t.Fatal("spent live proof replayed settlement")
	}
	nodeRouterTransitReadbackNoEffects(t, runner, calls, 0, 0)
	if authority.registrations != registrations || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, b.root)) {
		t.Fatal("unused metadata readback mutated kernel, receipt or registration")
	}
}

func TestNodeRouterTransitReadbackUnusedClosingOwnerCannotInsertMarkerOrReplaceRoot(t *testing.T) {
	for _, mode := range []string{policyAdditionFile, policyAdditionLock, "root-incarnation"} {
		t.Run(mode, func(t *testing.T) {
			b, runner, _ := nodeRouterTransitReadbackUnusedFixture(t, true)
			calls := len(runner.calls)
			readsClosed, inserted := false, false
			runner.beforeRead = func(_ context.Context, family int) error {
				if family == 6 {
					readsClosed = true
				}
				return nil
			}
			b.owner = func(context.Context) error {
				if readsClosed && !inserted {
					inserted = true
					if mode == "root-incarnation" {
						backup := filepath.Join(privateScopedXrayFixtureDir(t), "old-root")
						if err := os.Rename(b.root, backup); err != nil {
							return err
						}
						return os.Mkdir(b.root, 0700)
					}
					return os.WriteFile(filepath.Join(b.root, mode), []byte("fixture-owned late foreign marker"), 0600)
				}
				return nil
			}
			nodeRouterTransitReadbackDetached(b.lease)
			if err := b.readback(context.Background(), b.spec, b.root, b.lease.digest, networkPolicyTransitUnused); err == nil || !inserted || b.unused.claimed.Load() {
				t.Fatal("closing marker/root change acquired live unused settlement", err)
			}
			nodeRouterTransitReadbackNoEffects(t, runner, calls, 0, 0)
			entries, err := os.ReadDir(b.root)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "root-incarnation" {
				if len(entries) != 0 {
					t.Fatal("readback created metadata in replacement root")
				}
			} else {
				data, err := os.ReadFile(filepath.Join(b.root, mode))
				if err != nil || string(data) != "fixture-owned late foreign marker" || len(entries) != 1 {
					t.Fatal("readback changed or supplemented fixture's explicit marker", err)
				}
			}
		})
	}
}

func TestNodeRouterTransitReadbackPolicyGenerationRejectsMissingCorruptMarkerWithoutWrites(t *testing.T) {
	for _, kind := range []string{"candidate", "committed"} {
		for _, marker := range []string{"valid", "missing", "corrupt"} {
			t.Run(kind+"/"+marker, func(t *testing.T) {
				state, root, runner, options := additionFixture(t)
				ctx := context.Background()
				if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
					t.Fatal(err)
				}
				doc := readAdditionFixture(t, state, root, options)
				a := &ProxyTunnelAdapter{EngineID: "sing-box", StateRoot: filepath.Join(privateScopedXrayFixtureDir(t), "sing-box"), bootIdentity: options.boot}
				resource, argument, generation := root, root, doc.ID
				if kind == "candidate" {
					if err := writeProxyPolicyReceipt(root, proxyPolicyReceipt{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Boot: doc.Boot, Phase: "complete"}); err != nil {
						t.Fatal(err)
					}
				} else {
					// A retained restoration allocates its directory independently of
					// the receipt's nonce. The immutable binding stores both identities.
					generation = strings.Repeat("d", 32)
					if generation == doc.ID {
						generation = strings.Repeat("e", 32)
					}
					destination, err := a.createPolicyGeneration(generation)
					if err != nil {
						t.Fatal(err)
					}
					if err := promotePolicyAddition(ctx, state, root, destination, options); err != nil {
						t.Fatal(err)
					}
					if err := a.writePolicyBinding(proxyPolicyBinding{Schema: 1, Engine: a.ID(), Digest: proxyPolicyDigest(state), Generation: generation, ReceiptID: doc.ID, Phase: "active"}); err != nil {
						t.Fatal(err)
					}
					resource, argument = destination, ""
				}
				if marker == "missing" {
					if err := os.Remove(filepath.Join(resource, policyAdditionLock)); err != nil {
						t.Fatal(err)
					}
				}
				if marker == "corrupt" {
					if err := os.WriteFile(filepath.Join(resource, policyAdditionLock), []byte("foreign marker"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before := nodeRouterTransitReadbackTree(t, resource)
				calls := len(runner.calls)
				got, err := a.nodeRouterPolicyGeneration(ctx, state, argument)
				if marker == "valid" {
					if err != nil || got != generation {
						t.Fatal("valid generation or independent receipt ID rejected", got, err)
					}
				} else if err == nil {
					t.Fatal("missing/corrupt lock acquired policy-generation proof")
				}
				if len(runner.calls) != calls || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, resource)) {
					t.Fatal("policy-generation readback wrote or recreated permanent marker")
				}
			})
		}
	}
}

func TestNodeRouterTransitReadbackReceiptRejectsLoadedDocumentABA(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	ctx := context.Background()
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	doc := readAdditionFixture(t, state, root, options)
	path := filepath.Join(root, policyAdditionFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initialInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := range doc.Steps {
		doc.Steps[index].State = "removed"
	}
	doc.Checksum = policyAdditionChecksum(doc)
	alternate, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	before := nodeRouterTransitReadbackTree(t, root)
	calls, loadedAlternate := len(runner.calls), false
	_, readErr := nodeTransitReadReceipt(ctx, root, options.boot, func(session *policyAdditionSession) error {
		// In-place A->B->A keeps both inode and final hash identical. Only
		// comparing the actually loaded B with the initial A closes this gap.
		if err := os.WriteFile(path, alternate, 0600); err != nil {
			return err
		}
		session.state = state
		loadErr := session.load(ctx)
		loadedAlternate = loadErr == nil && session.status().Removed
		return errors.Join(loadErr, os.WriteFile(path, original, 0600))
	})
	closingInfo, err := os.Stat(path)
	if readErr == nil || !loadedAlternate || err != nil || !os.SameFile(initialInfo, closingInfo) {
		t.Fatal("loaded different valid document escaped ABA fence", loadedAlternate, readErr, err)
	}
	if len(runner.calls) != calls || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, root)) {
		t.Fatal("fixture's restored initial document/tree changed")
	}
	status, err := nodeTransitReadAddition(ctx, state, root, options.boot)
	if err != nil || !status.Complete || status.Removed {
		t.Fatal("initial valid receipt was not restored", status, err)
	}
}
