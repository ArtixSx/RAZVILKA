package dataplane

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

func TestNFQWSScopedQueueReadinessInventoryTransitions(t *testing.T) {
	readyRow := "40321 4294967000 0 2 65531 0 0 0 1\n"
	foreignRow := "40322 4294967000 0 2 65531 0 0 0 1\n"
	for _, tc := range []struct {
		name   string
		rows   []string
		inodes []string
		ready  bool
		fail   bool
	}{
		{name: "stable-empty", rows: []string{"", ""}},
		{name: "stable-owned", rows: []string{readyRow, readyRow}, ready: true},
		{name: "empty-to-owned", rows: []string{"", readyRow, readyRow}, ready: true},
		{name: "owned-to-empty", rows: []string{readyRow, ""}, fail: true},
		{name: "foreign-then-empty", rows: []string{foreignRow, ""}, fail: true},
		{name: "empty-to-foreign", rows: []string{"", foreignRow}, fail: true},
		{name: "empty-to-owned-to-empty", rows: []string{"", readyRow, ""}, fail: true},
		{name: "empty-to-owned-to-foreign", rows: []string{"", readyRow, foreignRow}, fail: true},
		{name: "multiple-queues", rows: []string{readyRow + foreignRow}, fail: true},
		{name: "malformed-then-empty", rows: []string{"40321 broken\n", ""}, fail: true},
		{name: "unconfigured-then-ready", rows: []string{strings.Replace(readyRow, " 2 65531 ", " 0 0 ", 1), readyRow}, fail: true},
		{name: "short-copy-range", rows: []string{strings.Replace(readyRow, "65531", "65530", 1)}, fail: true},
		{name: "different-port", rows: []string{readyRow, strings.Replace(readyRow, "4294967000", "4294967001", 1)}, fail: true},
		{name: "different-socket", rows: []string{readyRow, readyRow}, inodes: []string{"100", "101"}, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, owners, identities := 0, 0, 0
			o := nfqwsScopedQueueReadinessObserver{
				identity: func() error { identities++; return nil },
				read: func(context.Context) ([]nfqwsScopedQueue, error) {
					if reads >= len(tc.rows) {
						t.Fatal("unexpected inventory retry", reads)
					}
					text := tc.rows[reads]
					reads++
					return nfqwsScopedQueues(text)
				},
				owner: func(_ context.Context, q nfqwsScopedQueue) (string, error) {
					owners++
					if q.portID < 4294967000 {
						t.Fatal("port ID became numeric process PID")
					}
					if len(tc.inodes) > 0 {
						return tc.inodes[owners-1], nil
					}
					return "100", nil
				},
			}
			ready, err := nfqwsScopedQueueReadinessObserve(context.Background(), 40321, o)
			if tc.fail {
				if err == nil || ready {
					t.Fatal("unknown/foreign transition granted readiness", ready, err)
				}
			} else if err != nil || ready != tc.ready || identities != 2 {
				t.Fatal("positive inventory observation refused", ready, err, identities)
			}
			if strings.HasSuffix(tc.name, "then-empty") || tc.name == "unconfigured-then-ready" {
				if reads != 1 {
					t.Fatal("observed foreign/unknown was retried", reads)
				}
			}
		})
	}
}

func TestNFQWSScopedQueueReadinessUnknownsRemainErrors(t *testing.T) {
	for _, cut := range []string{"missing-inventory", "owner", "empty-inode", "changed-identity", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads, identities := 0, 0
			o := nfqwsScopedQueueReadinessObserver{
				identity: func() error {
					identities++
					if cut == "changed-identity" && identities == 2 {
						return ErrNFQWSManagedProcessUnknown
					}
					return nil
				},
				read: func(context.Context) ([]nfqwsScopedQueue, error) {
					reads++
					if cut == "missing-inventory" {
						return nil, errors.Join(ErrNFQWSScopedQueueInventory, os.ErrNotExist)
					}
					return nfqwsScopedQueues("40321 999 0 2 65531 0 0 0 1\n")
				},
				owner: func(context.Context, nfqwsScopedQueue) (string, error) {
					if cut == "owner" {
						return "", ErrNFQWSScopedOwner
					}
					if cut == "empty-inode" {
						return "", nil
					}
					if cut == "cancel" {
						cancel()
					}
					return "100", nil
				},
			}
			ready, err := nfqwsScopedQueueReadinessObserve(ctx, 40321, o)
			if err == nil || ready {
				t.Fatal("unknown observation granted readiness", ready, err)
			}
			if cut == "missing-inventory" && (!errors.Is(err, ErrNFQWSScopedQueueInventory) || reads != 1) {
				t.Fatal("missing inventory became transient", err, reads)
			}
		})
	}
}

func TestNFQWSScopedAfterStartQueueAppearsDuringCaptureRead(t *testing.T) {
	for _, cut := range []string{"empty", "owned", "empty-to-owned", "owned-to-empty", "foreign-capture", "foreign-queue", "unknown-queue", "changed-child", "late-current", "late-LAN", "cancel", "unbounded", "nil-readiness"} {
		t.Run(cut, func(t *testing.T) {
			b, m, root := nfqwsScopedBindingFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			queueReady := cut == "owned" || cut == "owned-to-empty"
			reads, queueReads, processReads, currents := 0, 0, 0, 0
			b.Runner = networkCleanupRunner(func(c context.Context, tool string, args ...string) ([]byte, error) {
				reads++
				if cut == "empty-to-owned" {
					queueReady = true // actual first -S overlaps queue registration
				}
				if cut == "owned-to-empty" {
					queueReady = false
				}
				if cut == "changed-child" {
					m.changedChild = true
				}
				return m.Run(c, tool, args...)
			})
			process := b.ProcessRunning
			b.ProcessRunning = func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
				processReads++
				return process(c, p)
			}
			b.QueueCheck = func(context.Context, string, uint16, *components.NFQWSRuntimeProcessIdentity) error {
				t.Fatal("after-Start borrowed empty-only/strict QueueCheck")
				return ErrNFQWSScopedOwner
			}
			b.queueReadiness = func(_ context.Context, ns string, q uint16, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
				queueReads++
				if ns != m.p.resources.NetNamespace || q != m.p.resources.Queue || child == nil || *child != m.proof(false).Child {
					return false, ErrNFQWSScopedOwner
				}
				if cut == "foreign-queue" || cut == "unknown-queue" {
					return false, ErrNFQWSScopedQueueInventory
				}
				if cut == "cancel" && queueReads == 2 {
					cancel()
				}
				return queueReady, nil
			}
			if cut == "changed-child" {
				// Queue proof stays for the opening exact child; the closing
				// lease must independently reject its changed birth.
				b.queueReadiness = func(context.Context, string, uint16, *components.NFQWSRuntimeProcessIdentity) (bool, error) {
					queueReads++
					return false, nil
				}
			}
			if cut == "foreign-capture" {
				m.foreign["ip6tables:security"] = "-A FOREIGN -j NFQUEUE --queue-num 99\n"
			}
			if cut == "late-LAN" {
				lan := b.VerifyLAN
				b.VerifyLAN = func(c context.Context, p *LANPolicyRuntimePlan) error {
					if reads > 0 {
						return ErrLANPolicyRuntime
					}
					return lan(c, p)
				}
			}
			if cut == "unbounded" {
				ctx = context.Background()
			}
			if cut == "nil-readiness" {
				b.queueReadiness = nil
			}
			current := func(c context.Context, p *NFQWSScopedPlan) error {
				currents++
				if cut == "late-current" && reads > 0 || p != m.p {
					return ErrReviewChanged
				}
				return c.Err()
			}
			ready, err := nfqwsScopedAfterStartCurrent(ctx, b, m.p, current)
			positive := cut == "empty" || cut == "owned" || cut == "empty-to-owned"
			if positive {
				if err != nil || ready != (cut != "empty") || reads != 10 || queueReads != 2 || processReads != 2 || currents != 3 || m.lanReads != 2 {
					t.Fatal("after-Start lost complete closure", ready, err, reads, queueReads, processReads, currents, m.lanReads)
				}
			} else if err == nil || ready {
				t.Fatal("changed/unknown evidence granted readiness", ready, err)
			}
			if (cut == "unknown-queue" || cut == "foreign-queue") && (queueReads != 1 || reads != 0) {
				t.Fatal("unknown queue was retried", queueReads, reads)
			}
			entries, readErr := os.ReadDir(root)
			if readErr != nil || len(entries) != 0 || len(m.calls) != 0 {
				t.Fatal("after-Start readiness mutated kernel or receipt", entries, readErr, m.calls)
			}
		})
	}
}
