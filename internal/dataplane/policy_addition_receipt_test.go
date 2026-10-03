package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func additionFixture(t *testing.T) (PolicyState, string, *recordedPolicyFakeRunner, policyAdditionOptions) {
	t.Helper()
	return testEarlyPolicy(), privateScopedXrayFixtureDir(t), &recordedPolicyFakeRunner{}, policyAdditionOptions{boot: func() (string, error) { return "receipt-test-boot", nil }}
}
func readAdditionFixture(t *testing.T, state PolicyState, root string, options policyAdditionOptions) policyAdditionDocument {
	t.Helper()
	s, err := openPolicyAdditionSession(context.Background(), state, root, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := s.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s.doc
}
func receiptMutationCalls(calls []string) []string {
	var out []string
	for _, call := range calls {
		if strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.Contains(call, " replace ") || strings.Contains(call, " flush") {
			out = append(out, call)
		}
	}
	return out
}

func TestPolicyAdditionReceiptLifecycleNeverReplaysGeneration(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	ctx := context.Background()
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	doc := readAdditionFixture(t, state, root, options)
	for _, step := range doc.Steps {
		if step.State != "added" {
			t.Fatal(step)
		}
	}
	before := len(runner.calls)
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionExists) || len(runner.calls) != before {
		t.Fatal("old generation replayed", err)
	}
	if err := removePolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	if len(runner.kernel.defaults) != 0 || len(runner.kernel.entries) != 0 {
		t.Fatal("owned tuples remain")
	}
	before = len(runner.calls)
	if err := removePolicyAddition(ctx, runner, "ip", state, root, options); err != nil || len(runner.calls) != before {
		t.Fatal("removed generation replayed", err)
	}
	if _, err := os.Stat(filepath.Join(root, policyAdditionLock)); err != nil {
		t.Fatal("permanent lock marker removed")
	}
}

func TestPolicyAdditionReceiptEEXISTPreservesUnknownAndOnlyCleansProvenSubset(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	const foreign = "default dev rz-sing proto boot metric 1024\n"
	runner.beforeAdd = func(family int) {
		if family == 6 {
			runner.kernel.defaults["6/203"] = foreign
		}
	}
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal(err)
	}
	doc := readAdditionFixture(t, state, root, options)
	if doc.Steps[0].State != "removed" || doc.Steps[1].State != "intent" {
		t.Fatal(doc.Steps)
	}
	before := len(runner.calls)
	if err := removePolicyAddition(context.Background(), runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || runner.kernel.defaults["6/203"] != foreign || len(receiptMutationCalls(runner.calls[before:])) != 0 {
		t.Fatal("EEXIST granted foreign tuple authority", err)
	}
}

func TestPolicyAdditionReceiptUnknownRuleKeepsDefaultsToPreventDirectFallback(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	options.fault = func(point string, index int) error {
		if point == "add" && index == 2 {
			return errors.New("crash after selector add before acknowledgement")
		}
		return nil
	}
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err == nil {
		t.Fatal("lost add acknowledgement accepted")
	}
	// CORE in-call compensation may attempt defaults; it too must preserve
	// them while an unknown selector can still reference their table.
	options.fault = nil
	if err := removePolicyAddition(context.Background(), runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal(err)
	}
	if len(runner.kernel.entries) == 0 || len(runner.kernel.defaults) != 2 {
		t.Fatal("unknown selector opened a direct fallback", runner.kernel)
	}
}

func TestPolicyAdditionReceiptPostAcknowledgementErrorKeepsDefaultsUntilKnownRuleRemoved(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	options.fault = func(point string, index int) error {
		if point == "added" && index == 2 {
			return errors.New("failure after durable rule acknowledgement")
		}
		return nil
	}
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err == nil {
		t.Fatal("post-ack failure ignored")
	}
	// CORE cannot include this rule in its in-memory compensation list because
	// its runner returned an error. The durable ledger still acknowledges it.
	doc := readAdditionFixture(t, state, root, options)
	if doc.Steps[2].State != "added" || len(runner.kernel.entries) != 1 || len(runner.kernel.defaults) != 2 {
		t.Fatal("default dropped while acknowledged selector remains", doc.Steps, runner.kernel)
	}
	options.fault = nil
	if err := removePolicyAddition(context.Background(), runner, "ip", state, root, options); err != nil {
		t.Fatal("fresh reader failed known cleanup", err)
	}
	if len(runner.kernel.entries) != 0 || len(runner.kernel.defaults) != 0 {
		t.Fatal("known additions remain after settlement")
	}
}

func TestPolicyAdditionReceiptCleanupIntentCannotDeleteAgainAfterLostAcknowledgement(t *testing.T) {
	for _, point := range []string{"cleanup-intent", "delete"} {
		t.Run(point, func(t *testing.T) {
			state, root, runner, options := additionFixture(t)
			ctx := context.Background()
			if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
				t.Fatal(err)
			}
			options.fault = func(got string, index int) error {
				if got == point && index == 2 {
					return errors.New("power cut")
				}
				return nil
			}
			if err := removePolicyAddition(ctx, runner, "ip", state, root, options); err == nil {
				t.Fatal("cleanup acknowledgement lost without fence")
			}
			options.fault = nil
			before := len(runner.calls)
			if err := removePolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(receiptMutationCalls(runner.calls[before:])) != 0 {
				t.Fatal("cleanup intent replayed", err)
			}
			if len(runner.kernel.defaults) != 2 {
				t.Fatal("uncertain rule dropped defaults")
			}
		})
	}
}

func TestPolicyAdditionReceiptCorruptionMismatchAndBootNeverMutate(t *testing.T) {
	for _, mode := range []string{"missing", "checksum", "argv", "duplicate-key", "unknown-field", "policy", "boot", "copied-root", "lock"} {
		t.Run(mode, func(t *testing.T) {
			state, root, runner, options := additionFixture(t)
			ctx := context.Background()
			if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, policyAdditionFile)
			doc := readAdditionFixture(t, state, root, options)
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "checksum":
				doc.Checksum = strings.Repeat("0", 64)
				data, _ := json.Marshal(doc)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "argv":
				doc.Steps[0].Add[4] = "foreign"
				doc.Checksum = policyAdditionChecksum(doc)
				data, _ := json.Marshal(doc)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate-key", "unknown-field":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				prefix := `{"schema":1,`
				if mode == "unknown-field" {
					prefix = `{"unexpected":true,`
				}
				if err := os.WriteFile(path, append([]byte(prefix), data[1:]...), 0600); err != nil {
					t.Fatal(err)
				}
			case "policy":
				state.Prefixes = []string{"8.8.8.8/32"}
			case "boot":
				options.boot = func() (string, error) { return "another-boot", nil }
			case "copied-root":
				dest := privateScopedXrayFixtureDir(t)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dest, policyAdditionFile), data, 0600); err != nil {
					t.Fatal(err)
				}
				root = dest
			case "lock":
				if err := os.WriteFile(filepath.Join(root, policyAdditionLock), []byte("unexpected"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := len(runner.calls)
			if err := removePolicyAddition(ctx, runner, "ip", state, root, options); err == nil || len(runner.calls) != before {
				t.Fatal("invalid receipt acquired authority", err)
			}
		})
	}
}

func TestPolicyAdditionReceiptLockIsNonblockingAcrossSessions(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	ctx := context.Background()
	held, err := openPolicyAdditionSession(ctx, state, root, options)
	if err != nil {
		t.Fatal(err)
	}
	defer held.close()
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionBusy) || len(runner.calls) != 0 {
		t.Fatal("contending generation acquired lock", err)
	}
}

func TestPolicyAdditionReceiptPromotionTransfersOneCleanupGrant(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	ctx := context.Background()
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	dest := privateScopedXrayFixtureDir(t)
	before := len(runner.calls)
	if err := promotePolicyAddition(ctx, state, root, dest, options); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != before {
		t.Fatal("promotion executed kernel commands")
	}
	src, target := readAdditionFixture(t, state, root, options), readAdditionFixture(t, state, dest, options)
	if src.Phase != "promoted" || src.ID != target.ID || target.RootHash == src.RootHash {
		t.Fatal("promotion duplicated authority")
	}
	if err := removePolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("source retained cleanup grant", err)
	}
	if err := promotePolicyAddition(ctx, state, root, dest, options); err != nil {
		t.Fatal("matching settled promotion was not idempotent", err)
	}
	if err := removePolicyAddition(ctx, runner, "ip", state, dest, options); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyAdditionReceiptInterruptedPromotionCannotCopyOrReplaySource(t *testing.T) {
	for _, point := range []string{"promotion-intent", "promotion-copy"} {
		t.Run(point, func(t *testing.T) {
			state, root, runner, options := additionFixture(t)
			ctx := context.Background()
			if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
				t.Fatal(err)
			}
			dest := privateScopedXrayFixtureDir(t)
			options.fault = func(got string, _ int) error {
				if got == point {
					return errors.New("promotion cut")
				}
				return nil
			}
			if err := promotePolicyAddition(ctx, state, root, dest, options); err == nil {
				t.Fatal("unknown promotion accepted")
			}
			options.fault = nil
			before := len(runner.calls)
			if err := removePolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(runner.calls) != before {
				t.Fatal("promotion source replayed", err)
			}
			if err := promotePolicyAddition(ctx, state, root, dest, options); !errors.Is(err, ErrPolicyAdditionUnknown) {
				t.Fatal("promotion intent retried", err)
			}
		})
	}
}

func TestPolicyAdditionReceiptPromotionRetryRejectsConsumedOrTransferredTarget(t *testing.T) {
	for _, mode := range []string{"removed", "promoted"} {
		t.Run(mode, func(t *testing.T) {
			state, source, runner, options := additionFixture(t)
			ctx, target := context.Background(), privateScopedXrayFixtureDir(t)
			if err := applyPolicyAddition(ctx, runner, "ip", state, source, options); err != nil {
				t.Fatal(err)
			}
			if err := promotePolicyAddition(ctx, state, source, target, options); err != nil {
				t.Fatal(err)
			}
			if mode == "removed" {
				if err := removePolicyAddition(ctx, runner, "ip", state, target, options); err != nil {
					t.Fatal(err)
				}
			} else if err := promotePolicyAddition(ctx, state, target, privateScopedXrayFixtureDir(t), options); err != nil {
				t.Fatal(err)
			}
			before := len(runner.calls)
			if err := promotePolicyAddition(ctx, state, source, target, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(runner.calls) != before {
				t.Fatal("stale promotion target accepted", err)
			}
		})
	}
}

func TestPolicyAdditionReceiptReadOnlyStatusCannotGrantPermission(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	ctx := context.Background()
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	s, err := openPolicyAdditionSession(ctx, state, root, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := s.load(ctx); err != nil {
		t.Fatal(err)
	}
	status := s.status()
	if !status.Complete || status.Removed || status.Unknown {
		t.Fatal(status)
	}
	before := reflect.ValueOf(runner.kernel).Interface()
	_ = s.status()
	if !reflect.DeepEqual(before, runner.kernel) {
		t.Fatal("status mutated kernel")
	}
}

func TestPolicyAdditionReceiptCannotAcknowledgeWhenJournalWriteFails(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	options.fault = func(point string, index int) error {
		if point == "add" && index == 0 {
			// Netlink succeeded, but a broken journal target makes the following
			// atomic acknowledgement fail. Matching kernel contents cannot grant
			// cleanup authority to a fresh reader with an unavailable receipt.
			path := filepath.Join(root, policyAdditionFile)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err == nil {
		t.Fatal("unwritten acknowledgement accepted")
	}
	if len(runner.kernel.defaults) != 1 {
		t.Fatal("unknown addition was deleted")
	}
	before := len(runner.calls)
	options.fault = nil
	if err := removePolicyAddition(context.Background(), runner, "ip", state, root, options); err == nil || len(runner.calls) != before {
		t.Fatal("unavailable journal granted cleanup", err)
	}
}

func TestPolicyAdditionReceiptCancellationAfterIntentNeverRunsMutation(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options.fault = func(point string, index int) error {
		if point == "intent" && index == 0 {
			cancel()
		}
		return nil
	}
	if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, context.Canceled) || len(receiptMutationCalls(runner.calls)) != 0 {
		t.Fatal("cancellation after intent ran netlink", err)
	}
	options.fault = nil
	if err := removePolicyAddition(context.Background(), runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(receiptMutationCalls(runner.calls)) != 0 {
		t.Fatal("canceled intent was replayed", err)
	}
}
