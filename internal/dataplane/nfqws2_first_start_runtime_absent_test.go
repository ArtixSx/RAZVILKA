package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Models the actual first-start consumer sequence with the original bound
// source. These leaves do not claim native process or kernel evidence.
func TestNFQWSFirstStartRuntimeAbsentPreservesInventoryCauseAndStage(t *testing.T) {
	private := errors.New("private path, process, address and command text")
	for _, cause := range []struct {
		name string
		err  error
		text string
	}{
		{"backend", backendInventoryAt("TOOLS_A", private), "NFQWS runtime inactivity: observation/kernel/inventory.source/backend.TOOLS_A"},
		{"unknown-backend", backendInventoryAt("private-stage", private), "NFQWS runtime inactivity: observation/kernel/inventory.source/backend.unknown"},
		{"deadline", context.DeadlineExceeded, "NFQWS runtime inactivity: observation/kernel/inventory.source"},
		{"canceled", context.Canceled, "NFQWS runtime inactivity: observation/kernel/inventory.source"},
	} {
		t.Run(cause.name, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			err := f.a.firstStartRuntimeAbsentWithSources(nfqws2InactiveTestContext(t), f.proof,
				func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					return use(c, f.source.identity)
				},
				func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					f.reads++
					return BackendInventorySnapshot{}, cause.err
				})
			if !errors.Is(err, cause.err) || !errors.Is(err, ErrNFQWSManagedKernelOwner) || f.reads != 1 || err.Error() != cause.text ||
				NFQWSRuntimeInactiveStage(err) != "inventory.source" || strings.Contains(err.Error(), private.Error()) {
				t.Fatal("first-start consumer lost its actual refusal or exposed foreign text", err, f.reads)
			}
		})
	}
}

func TestNFQWSFirstStartRuntimeAbsentSourceAndIdentityRemainDistinct(t *testing.T) {
	for _, which := range []string{"missing", "copy", "changed-identity", "changed-inventory"} {
		t.Run(which, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			if which == "missing" || which == "copy" {
				if which == "missing" {
					f.a.inactivity = nil
				} else {
					copy := *f.source
					f.a.inactivity = &copy
				}
				err := f.a.firstStartRuntimeAbsent(ctx)
				if !errors.Is(err, ErrNFQWSManagedKernelOwner) || NFQWSRuntimeInactiveStage(err) != "source" {
					t.Fatal("missing original source was not identified", err)
				}
				return
			}
			err := f.a.firstStartRuntimeAbsentWithSources(ctx, f.proof,
				func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					identity := f.source.identity
					if which == "changed-identity" {
						identity.BootID = "11234567-89ab-cdef-0123-456789abcdef"
					}
					return use(c, identity)
				},
				func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					f.reads++
					image := nfqwsDirectStockTestClone(f.image)
					image.Scope.ToolReviewID = strings.Repeat("f", 64)
					return image, nil
				})
			stage, reads := "identity", 0
			if which == "changed-inventory" {
				stage, reads = "inventory.source", 1
			}
			if !errors.Is(err, ErrNFQWSManagedKernelOwner) || NFQWSRuntimeInactiveStage(err) != stage || f.reads != reads {
				t.Fatal("source mismatch was mislabeled or admitted", err, f.reads)
			}
		})
	}
}

func TestNFQWSFirstStartRuntimeAbsentKeepsCompleteSequenceAndCallerLifetime(t *testing.T) {
	for _, which := range []string{"complete", "cancel-second-read", "late-process", "closure-drift", "kernel-queue"} {
		t.Run(which, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), "first-start-operation", "original"), time.Second)
			defer cancel()
			parentDeadline, _ := ctx.Deadline()
			queues, sockets := 0, 0
			f.proof.queues = func(context.Context) ([]nfqwsScopedQueue, error) {
				queues++
				if which == "kernel-queue" {
					return []nfqwsScopedQueue{{number: 300, portID: 99}}, nil
				}
				return nil, nil
			}
			f.proof.sockets = func(context.Context) (string, error) {
				sockets++
				if which == "late-process" && sockets == 2 {
					f.process(t, 42, "nfqws2", 'S', 0, "nfqws2\x00--qnum=300\x00")
				}
				return "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n", nil
			}
			err := f.a.firstStartRuntimeAbsentWithSources(ctx, f.proof,
				func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					f.uses++
					deadline, finite := c.Deadline()
					if !finite || deadline.After(parentDeadline) || c.Value("first-start-operation") != "original" {
						t.Fatal("original finite caller authority was replaced")
					}
					err := use(c, f.source.identity)
					if which == "closure-drift" {
						f.a.ConfigPath += ".foreign"
					}
					return err
				},
				func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
					f.reads++
					if id != f.source.identity {
						t.Fatal("collector observed a different identity")
					}
					if which == "cancel-second-read" && f.reads == 2 {
						cancel()
					}
					return nfqwsDirectStockTestClone(f.image), c.Err()
				})
			stage := map[string]string{"cancel-second-read": "participants", "late-process": "processes", "closure-drift": "participants", "kernel-queue": "kernel"}[which]
			if which == "complete" {
				if err != nil || f.uses != 1 || f.reads != 2 || queues != 2 || sockets != 2 {
					t.Fatal("complete independent observations were not retained", err, f.uses, f.reads, queues, sockets)
				}
			} else if !errors.Is(err, ErrNFQWSManagedKernelOwner) || NFQWSRuntimeInactiveStage(err) != stage {
				t.Fatal("unknown observation became absence or lost its stage", err)
			}
			if which == "cancel-second-read" && !errors.Is(err, context.Canceled) {
				t.Fatal("caller cancellation was discarded", err)
			}
		})
	}
}
