//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Actual original five private leases, retained file descriptors and protected
// publishers. Completed native effects/home/process absence are MODELED; these
// tests cannot issue a command or replace the original parent/ACK native gate.
func sameBootRetainedACKFixture(t *testing.T, kind string, use func(*MihomoSameBootRetirement, *mihomoSameBootACKResume)) {
	t.Helper()
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		a, err := newMihomoSameBootArchive(i)
		if err != nil {
			t.Fatal(err)
		}
		defer a.close()
		after, err := mihomoLiveRetirementTerminal(e, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(after)
		if err != nil {
			t.Fatal(err)
		}
		proxy := &ProxyTunnelAdapter{}
		c := &mihomoSameBootRetirementCursor{ctx: ctx, archive: a, owner: &mihomoSameBootCleanup{inputs: i, effectsClosed: true, read: &mihomoColdReadRunner{proxy: proxy}}, effectProxy: proxy, history: &updatecheck.ExecutionHistoryAdmission{}, home: &mihomoColdHomeArchive{}, runtimeAfter: &mihomoColdRuntimeArchive{}, finalTree: &mihomoSameBootStatic{}, sidecarDone: true, policyDone: true, forwardingDone: true, terminal: after}
		c.self, c.owner.self = c, c.owner
		c.intent = mihomoSameBootIntent{Schema: 1, Before: bytes.Clone(i.records[0].data), After: wire, Configuration: bytes.Clone(i.records[2].data)}
		current := func() error { return i.current(ctx) }
		if err := c.publishArchive("retirement.json", c.intent, current); err != nil {
			t.Fatal(err)
		}
		if err := c.publishArchive("runtime-history", struct {
			Schema  int
			Runtime mihomoColdRuntimeArchive
			Home    *mihomoColdHomeArchive
		}{1, *c.runtimeAfter, c.home}, current); err != nil {
			t.Fatal(err)
		}
		cut := errors.New("same original publisher ACK cut")
		for n := range 2 {
			if kind == "terminal-transaction" && n == 0 || kind == "terminal-global" && n == 1 {
				c.terminalFault = func(int) error { return cut }
				if err := c.publishTerminal(n, current); !errors.Is(err, cut) || c.retryTerminal != n+1 {
					t.Fatal("original pending writer not issued", err)
				}
				break
			}
			if err := c.publishTerminal(n, current); err != nil {
				t.Fatal(err)
			}
		}
		if kind == "completed.json" {
			a.fault = func(string) error { return cut }
			err := c.publishArchive("completed.json", struct {
				Schema                    int
				BeforeSHA256, AfterSHA256 string
			}{1, nodeDefaultSourceMaterialHash(c.intent.Before), nodeDefaultSourceMaterialHash(c.intent.After)}, current)
			if !errors.Is(err, cut) || c.retryArchive != kind {
				t.Fatal("original completed ACK not issued", err)
			}
		}
		h := &MihomoSameBootRetirement{ctx: ctx, cursor: c, open: true, attempted: true, lastErr: errors.Join(cut, ErrMihomoSameBootRetainedRetry), retryTerminal: c.retryTerminal, retryArchive: c.retryArchive}
		h.self = h
		r, err := h.retainedACKResume()
		if err != nil || r.bound() != nil || r.documentsCurrent() != nil {
			t.Fatal("original publisher continuation refused", err)
		}
		use(h, r)
	})
}

func TestMihomoSameBootRetainedACKOriginalPublisherAndSuffix(t *testing.T) {
	for _, kind := range []string{"terminal-transaction", "terminal-global", "completed.json"} {
		t.Run(kind, func(t *testing.T) {
			sameBootRetainedACKFixture(t, kind, func(h *MihomoSameBootRetirement, r *mihomoSameBootACKResume) {
				c := h.cursor
				// Only this documentary test substitutes metadata for native
				// terminalCurrent. Production resume always calls the full body.
				current := func() error { return errors.Join(r.bound(), r.documentsCurrent()) }
				c.terminalFault, c.archive.fault = nil, nil
				c.retryArchive, c.retryTerminal = "", 0
				for n := range 2 {
					if bytes.Equal(c.owner.inputs.records[n].data, c.intent.After) && !c.terminalPending[n] {
						continue
					}
					original := c.owner.inputs.records[n].info
					pending := c.terminalPending[n]
					if err := r.beforeTerminal(n); err != nil {
						t.Fatal(err)
					}
					if err := c.publishTerminal(n, current); err != nil {
						t.Fatal("same publisher refused continuation", err)
					}
					if err := r.afterTerminal(n); err != nil {
						t.Fatal("authored suffix transition not retained", err)
					}
					if os.SameFile(original, c.owner.inputs.records[n].info) != pending {
						t.Fatal("ACK replaced original inode or new suffix adopted old inode")
					}
				}
				var original os.FileInfo
				if prior := c.archive.records["completed.json"]; prior != nil {
					original = prior.info
				}
				if err := c.publishArchive("completed.json", struct {
					Schema                    int
					BeforeSHA256, AfterSHA256 string
				}{1, nodeDefaultSourceMaterialHash(c.intent.Before), nodeDefaultSourceMaterialHash(c.intent.After)}, current); err != nil {
					t.Fatal(err)
				}
				if original != nil && !os.SameFile(original, c.archive.records["completed.json"].info) {
					t.Fatal("completed ACK replaced original file")
				}
				if err := current(); err != nil || c.terminalPending != [2]bool{} {
					t.Fatal("completed original suffix not current", err)
				}
			})
		})
	}
}

func TestMihomoSameBootRetainedACKRefusesChangedBindings(t *testing.T) {
	for _, cut := range []string{"terminal-transaction", "terminal-global", "completed.json"} {
		for _, kind := range []string{"copied", "foreign-context", "unknown", "effect-unknown", "effects-open", "closed", "pending-flag", "record-copy", "same-byte-replacement", "home-value", "home-pointer", "runtime-value", "intent-value", "canceled"} {
			t.Run(cut+"/"+kind, func(t *testing.T) {
				sameBootRetainedACKFixture(t, cut, func(h *MihomoSameBootRetirement, r *mihomoSameBootACKResume) {
					c := h.cursor
					switch kind {
					case "copied":
						copy := *r
						r = &copy
					case "foreign-context":
						h.ctx = context.WithValue(h.ctx, struct{}{}, 1)
					case "unknown":
						c.unknown = errors.New("unknown native result")
					case "effect-unknown":
						c.owner.effectUnknown = true
					case "effects-open":
						c.owner.effectsClosed = false
					case "closed":
						c.closed = true
					case "pending-flag":
						c.terminalPending[0] = !c.terminalPending[0]
					case "record-copy":
						copy := *c.owner.inputs.records[0]
						c.owner.inputs.records[0] = &copy
					case "same-byte-replacement":
						prior := c.archive.records["runtime-history"]
						if err := prior.root.WriteFile("foreign", prior.data, 0600); err != nil {
							t.Fatal(err)
						}
						if err := prior.root.Rename("foreign", prior.name); err != nil {
							t.Fatal(err)
						}
					case "home-value":
						c.home.State = "foreign"
					case "home-pointer":
						copy := *c.home
						c.home = &copy
					case "runtime-value":
						c.runtimeAfter.Present = !c.runtimeAfter.Present
					case "intent-value":
						c.intent.Configuration = []byte("changed")
					case "canceled":
						ctx, cancel := context.WithCancel(r.ctx)
						cancel()
						r.ctx, h.ctx, c.ctx = ctx, ctx, ctx
					}
					if r.bound() == nil && r.documentsCurrent() == nil {
						t.Fatal("changed continuation remained usable")
					}
				})
			})
		}
	}
}

func TestMihomoSameBootRetainedACKModelCannotSkipFreshNativeAdmission(t *testing.T) {
	for _, kind := range []string{"terminal-transaction", "terminal-global", "completed.json"} {
		t.Run(kind, func(t *testing.T) {
			sameBootRetainedACKFixture(t, kind, func(h *MihomoSameBootRetirement, r *mihomoSameBootACKResume) {
				before := h.lastErr
				files := [2]*os.File{h.cursor.owner.inputs.records[0].file, h.cursor.owner.inputs.records[1].file}
				if _, err := h.runAtRetainedACKLocked(r); err == nil || !errors.Is(err, before) {
					t.Fatal("documentary state bypassed original history/native source admission", err)
				}
				if h.retryTerminal != 0 || h.retryArchive != "" || h.retrySidecar || !r.used {
					t.Fatal("observed failure retained a retry opportunity")
				}
				for n := range 2 {
					if files[n] != h.cursor.owner.inputs.records[n].file {
						t.Fatal("failed admission performed publication")
					}
				}
				if _, err := r.run(h); err == nil {
					t.Fatal("consumed descriptor reused")
				}
			})
		})
	}
}

func TestMihomoSameBootRetainedACKActiveSuffixCannotRebindRecord(t *testing.T) {
	for _, field := range []string{"root", "name"} {
		t.Run(field, func(t *testing.T) {
			sameBootRetainedACKFixture(t, "terminal-transaction", func(h *MihomoSameBootRetirement, r *mihomoSameBootACKResume) {
				c := h.cursor
				c.terminalFault = nil
				current := func() error { return errors.Join(r.bound(), r.documentsCurrent()) }
				if err := r.beforeTerminal(0); err != nil {
					t.Fatal(err)
				}
				if err := c.publishTerminal(0, current); err != nil {
					t.Fatal(err)
				}
				if err := r.afterTerminal(0); err != nil {
					t.Fatal(err)
				}
				if err := r.beforeTerminal(1); err != nil {
					t.Fatal(err)
				}
				// Use the original publisher to reach the legitimate later-slot
				// transition, then attack ONLY its frozen path association during
				// the publisher's closing callback. No outside fallback is tested.
				var observed bool
				closing := func() error {
					actual := c.owner.inputs.records[1]
					if c.terminalPending[1] && bytes.Equal(actual.data, c.intent.After) {
						observed = true
						root, name := actual.root, actual.name
						if field == "root" {
							alias, err := root.OpenRoot(".")
							if err != nil {
								t.Fatal(err)
							}
							defer func() {
								if err := alias.Close(); err != nil {
									t.Error(err)
								}
							}()
							actual.root = alias
							if err := actual.current(); err != nil {
								t.Fatal("alias must preserve actual file bytes/inode before association refusal", err)
							}
						} else {
							actual.name = "foreign"
						}
						defer func() { actual.root, actual.name = root, name }()
						if err := r.bound(); err == nil {
							t.Fatal("active later-slot adopted a rebound path")
						}
						c.terminalPending[1] = false
						if err := r.afterTerminal(1); err == nil {
							t.Fatal("completed later-slot adopted a rebound path")
						}
						c.terminalPending[1] = true
						return ErrMihomoLiveRetirement
					}
					return current()
				}
				if err := c.publishTerminal(1, closing); err == nil || !observed {
					t.Fatal("closing attack did not refuse", err, observed)
				}
			})
		})
	}
}
