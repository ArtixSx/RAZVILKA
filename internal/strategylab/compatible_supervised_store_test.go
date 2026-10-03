package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// All receipts here are data-model fixtures. These tests neither launch a
// helper nor award native NFQWS compatibility from a modeled zero exit.
func compatibilityStoreFixture(t *testing.T) (*Manager, compatibilitySession, Candidate) {
	t.Helper()
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.Now = func() time.Time { return packTime }
	session := compatibilityRecordFixture(t)
	args := session.DryRun.Command.Args[2+len(session.DryRun.Command.Review.BaseArguments):]
	candidate, err := m.AddCandidate("tcp-tls", "existing draft", strings.Join(args, " "), "expert")
	if err != nil {
		t.Fatal(err)
	}
	// Store tests model the single admitted validation owner. No process or
	// validator is invoked by setting this admission state.
	m.nativeRunning = true
	return m, session, candidate
}

func compatibilityStoreBegin(m *Manager, ctx context.Context, session compatibilitySession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.beginCompatibilitySessionLocked(ctx, session)
}

func compatibilityStoreBytes(t *testing.T, m *Manager) []byte {
	t.Helper()
	data, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func compatibilityStoreStateClone(t *testing.T, state State) State {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var result State
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func compatibilityStoreRawCAS(t *testing.T, m *Manager, before restorejournal.Image, data []byte) restorejournal.Image {
	t.Helper()
	target, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	after := restorejournal.Image{Exists: true, Data: data}
	if err := target.CompareAndSwap(context.Background(), before, after); err != nil {
		t.Fatal(err)
	}
	return after
}

func compatibilityStoreRawState(t *testing.T, m *Manager, state State) restorejournal.Image {
	t.Helper()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return compatibilityStoreRawCAS(t, m, m.image, append(data, '\n'))
}

func compatibilityStorePublishReceipt(t *testing.T, m *Manager, state string, exit int) {
	t.Helper()
	active := compatibilityActiveInvocation(m.state.CompatibilitySession)
	lease, err := openCompatibilityStateLease(context.Background(), m.Path, active.Command.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.close()
	i := compatibilityActiveInvocation(lease.state.CompatibilitySession)
	compatibilityRecordReceipt(i, state, false, exit)
	if compatibilityReceiptTerminal(i.Receipt) {
		i.Output = "modeled terminal diagnostics"
	}
	if err := lease.publish(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func compatibilityStoreRead(t *testing.T, m *Manager, expected compatibilitySession) (State, restorejournal.Image) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	state, image, err := m.readCompatibilityResultLocked(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	return state, image
}

func compatibilityStoreAck(m *Manager, ctx context.Context, state State, image restorejournal.Image) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acknowledgeCompatibilityResultLocked(ctx, state, image)
}

func compatibilityStoreLuaSession(t *testing.T, dry compatibilitySession) compatibilitySession {
	t.Helper()
	session := compatibilityRecordClone(t, dry)
	command := session.DryRun.Command
	command.ID, command.Phase = strings.Repeat("4", 32), "lua-init"
	command.Args = closedCompatibilityCommand(t, command.Review.BaseArguments, command.Args[2+len(command.Review.BaseArguments):], false)
	session.Active = "lua-init"
	session.LuaInit = &compatibilityInvocation{Command: command, CommandSHA256: compatibilityCommandDigest(command), Receipt: compatibilityReceipt{State: "intent"}}
	return session
}

func TestCompatibilityStoreIntentPersistsBeforeAdmission(t *testing.T) {
	m, session, _ := compatibilityStoreFixture(t)
	before := append([]byte(nil), m.image.Data...)
	if _, err := openCompatibilityStateLease(context.Background(), m.Path, session.DryRun.Command.ID); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatalf("helper admission before intent: %v", err)
	}
	if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
		t.Fatal(err)
	}
	durable := compatibilityStoreBytes(t, m)
	if bytes.Equal(before, durable) || !m.image.Exists || !bytes.Equal(m.image.Data, durable) || !m.Snapshot().QuiescenceUnknown || !m.state.CompatibilityFinalizing {
		t.Fatal("successful intent admission did not retain its exact durable image")
	}
	lease, err := openCompatibilityStateLease(context.Background(), m.Path, session.DryRun.Command.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active := compatibilityActiveInvocation(lease.state.CompatibilitySession); active.CommandSHA256 != session.DryRun.CommandSHA256 || active.Receipt.State != "intent" || active.Acknowledged {
		lease.close()
		t.Fatal("helper admission did not load the exact pre-spawn intent")
	}
	lease.close()
	if _, err := openCompatibilityStateLease(context.Background(), m.Path, strings.Repeat("f", 32)); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatalf("different invocation acquired helper admission: %v", err)
	}
}

func TestCompatibilityStorePendingAndUnacknowledgedReloadUnknown(t *testing.T) {
	for _, state := range []string{"intent", "armed", "running", "reaped", "not-started"} {
		t.Run(state, func(t *testing.T) {
			m, session, _ := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
				t.Fatal(err)
			}
			if state != "intent" {
				compatibilityStorePublishReceipt(t, m, state, 0)
			}
			reloaded, err := New(m.Path)
			if err != nil || !reloaded.Snapshot().QuiescenceUnknown {
				t.Fatalf("reload cleared pending or unacknowledged completion: %v", err)
			}
			if actual := compatibilityActiveInvocation(reloaded.state.CompatibilitySession); actual.Receipt.State != state || actual.Acknowledged || actual.CommandSHA256 != session.DryRun.CommandSHA256 {
				t.Fatal("reload lost exact invocation or receipt state")
			}
			if state != "intent" {
				if _, err := openCompatibilityStateLease(context.Background(), m.Path, session.DryRun.Command.ID); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
					t.Fatalf("helper admission replayed a non-intent invocation: %v", err)
				}
			}
		})
	}
}

func TestCompatibilityStoreReadbackRejectsDifferentIdentityOrState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*State)
	}{
		{"session", func(s *State) {
			s.CompatibilitySession.ID = strings.Repeat("5", 32)
			s.CompatibilitySession.DryRun.Command.SessionID = s.CompatibilitySession.ID
			compatibilityRecordReseal(s.CompatibilitySession.DryRun)
		}},
		{"invocation", func(s *State) {
			s.CompatibilitySession.DryRun.Command.ID = strings.Repeat("5", 32)
			compatibilityRecordReseal(s.CompatibilitySession.DryRun)
		}},
		{"command-resealed", func(s *State) {
			s.CompatibilitySession.DryRun.Command.Args[2+len(s.CompatibilitySession.DryRun.Command.Review.BaseArguments)] = "--filter-tcp=80"
			compatibilityRecordReseal(s.CompatibilitySession.DryRun)
		}},
		{"hash", func(s *State) { s.CompatibilitySession.DryRun.CommandSHA256 = strings.Repeat("0", 64) }},
		{"receipt-command", func(s *State) { s.CompatibilitySession.DryRun.Receipt.CommandSHA256 = strings.Repeat("0", 64) }},
		{"receipt-boot", func(s *State) { s.CompatibilitySession.DryRun.Receipt.BootID = "11234567-89ab-cdef-0123-456789abcdef" }},
		{"still-running", func(s *State) { compatibilityRecordReceipt(s.CompatibilitySession.DryRun, "running", false, 0) }},
		{"already-acknowledged", func(s *State) { s.CompatibilitySession.DryRun.Acknowledged = true }},
		{"missing-direct-status", func(s *State) { s.CompatibilitySession.DryRun.Receipt.DirectReaped = false }},
		{"missing-echild", func(s *State) { s.CompatibilitySession.DryRun.Receipt.WaitECHILD = false }},
		{"retained-unknown", func(s *State) { s.CompatibilitySession.Unknown = true }},
		{"helper-clears-finalizing", func(s *State) { s.CompatibilityFinalizing = false }},
		{"candidate", func(s *State) {
			for id, c := range s.Candidates {
				c.Name = "helper changed draft"
				s.Candidates[id] = c
			}
		}},
		{"evidence", func(s *State) { s.Evidence = append(s.Evidence, Evidence{CandidateID: "forged evidence"}) }},
		{"pack-receipt", func(s *State) {
			s.PackReceipts = map[string]PackReceipt{"unexpected": {Sequence: 1, SHA256: strings.Repeat("a", 64)}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, session, _ := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
				t.Fatal(err)
			}
			expected := compatibilityRecordClone(t, session)
			state := compatibilityStoreStateClone(t, m.state)
			compatibilityRecordReceipt(state.CompatibilitySession.DryRun, "reaped", false, 0)
			tc.mutate(&state)
			image := compatibilityStoreRawState(t, m, state)
			m.mu.Lock()
			_, _, err := m.readCompatibilityResultLocked(context.Background(), expected)
			m.mu.Unlock()
			if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !m.Snapshot().QuiescenceUnknown || !bytes.Equal(compatibilityStoreBytes(t, m), image.Data) {
				t.Fatalf("different helper image was accepted or overwritten: %v", err)
			}
			if m.state.CompatibilitySession.DryRun.Receipt.State != "intent" || m.state.CompatibilitySession.DryRun.Acknowledged {
				t.Fatal("rejected readback changed the parent's committed intent")
			}
		})
	}
}

func TestCompatibilityStoreAcknowledgementRefreshesCASAndAdvancesPhase(t *testing.T) {
	m, session, _ := compatibilityStoreFixture(t)
	if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
		t.Fatal(err)
	}
	intentImage := append([]byte(nil), m.image.Data...)
	compatibilityStorePublishReceipt(t, m, "reaped", 0)
	if !bytes.Equal(m.image.Data, intentImage) || !m.Snapshot().QuiescenceUnknown {
		t.Fatal("unread helper completion changed the Manager's committed image")
	}
	state, image := compatibilityStoreRead(t, m, session)
	if state.CompatibilitySession.DryRun.Output != "modeled terminal diagnostics" {
		t.Fatal("exact terminal diagnostic output changed during readback")
	}
	if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.image.Data, compatibilityStoreBytes(t, m)) || !m.Snapshot().QuiescenceUnknown || !m.state.CompatibilityFinalizing || !m.state.CompatibilitySession.DryRun.Acknowledged {
		t.Fatal("terminal acknowledgement failed to refresh Manager's image or cleared the final publication fence")
	}
	if _, err := m.AddCandidate("tcp-tls", "draft after dry receipt", "--filter-tcp=80", "expert"); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatalf("ordinary writer admitted an ACKed but finalizing session: %v", err)
	}
	lua := compatibilityStoreLuaSession(t, *m.state.CompatibilitySession)
	if err := compatibilityStoreBegin(m, context.Background(), lua); err != nil || !m.Snapshot().QuiescenceUnknown {
		t.Fatalf("closed dry-to-Lua progression rejected: %v", err)
	}
	compatibilityStorePublishReceipt(t, m, "reaped", 7)
	state, image = compatibilityStoreRead(t, m, lua)
	if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(m.Path)
	if err != nil || !reloaded.Snapshot().QuiescenceUnknown || !reloaded.state.CompatibilityFinalizing || !reloaded.state.CompatibilitySession.LuaInit.Acknowledged || compatibilityInvocationSucceeded(*reloaded.state.CompatibilitySession.LuaInit) {
		t.Fatalf("phase ACK cleared final publication fence or modeled Lua rejection became success: %v", err)
	}
	for _, candidate := range reloaded.Snapshot().Candidates {
		if candidate.Validation.OK || candidate.Validation.Native {
			t.Fatal("receipt storage fabricated native compatibility for a draft")
		}
	}
}

func TestCompatibilityStorePhaseProgressionKeepsAcknowledgedDryRun(t *testing.T) {
	t.Run("no-retained-dry-run", func(t *testing.T) {
		m, _, _ := compatibilityStoreFixture(t)
		lua := compatibilityRecordLuaFixture(t)
		before := compatibilityStoreBytes(t, m)
		if err := compatibilityStoreBegin(m, context.Background(), lua); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
			t.Fatalf("Lua intent admitted an unretained acknowledged dry-run: %v", err)
		}
	})
	for _, mutation := range []string{"dry-output", "both-candidates", "both-review", "repeat-lua"} {
		t.Run(mutation, func(t *testing.T) {
			m, session, _ := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
				t.Fatal(err)
			}
			compatibilityStorePublishReceipt(t, m, "reaped", 0)
			state, image := compatibilityStoreRead(t, m, session)
			if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
				t.Fatal(err)
			}
			lua := compatibilityStoreLuaSession(t, *m.state.CompatibilitySession)
			switch mutation {
			case "dry-output":
				lua.DryRun.Output = "changed old phase diagnostics"
			case "both-candidates":
				lua.DryRun.Command.Args[2+len(lua.DryRun.Command.Review.BaseArguments)] = "--filter-tcp=80"
				lua.LuaInit.Command.Args[1+len(lua.LuaInit.Command.Review.BaseArguments)] = "--filter-tcp=80"
				compatibilityRecordReseal(lua.DryRun)
				compatibilityRecordReseal(lua.LuaInit)
			case "both-review":
				lua.DryRun.Command.Review.Binary.SHA256 = strings.Repeat("c", 64)
				lua.LuaInit.Command.Review.Binary.SHA256 = strings.Repeat("c", 64)
				compatibilityRecordReseal(lua.DryRun)
				compatibilityRecordReseal(lua.LuaInit)
			case "repeat-lua":
				if err := compatibilityStoreBegin(m, context.Background(), lua); err != nil {
					t.Fatal(err)
				}
				compatibilityStorePublishReceipt(t, m, "reaped", 7)
				state, image = compatibilityStoreRead(t, m, lua)
				if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
					t.Fatal(err)
				}
				lua = compatibilityRecordClone(t, *m.state.CompatibilitySession)
				lua.LuaInit.Command.ID = strings.Repeat("6", 32)
				lua.LuaInit.Receipt, lua.LuaInit.Acknowledged, lua.LuaInit.Output = compatibilityReceipt{State: "intent"}, false, ""
				compatibilityRecordReseal(lua.LuaInit)
			}
			if err := validateCompatibilitySession(lua); err != nil {
				t.Fatalf("fixture must be structurally valid so CAS progression is tested: %v", err)
			}
			before := compatibilityStoreBytes(t, m)
			if err := compatibilityStoreBegin(m, context.Background(), lua); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
				t.Fatalf("CAS progression replaced an acknowledged phase or replayed Lua: %v", err)
			}
		})
	}
}

func TestCompatibilityStoreLateAcknowledgementRefusesRetainedUnknown(t *testing.T) {
	for _, condition := range []string{"cancelled-context", "memory-latch", "session-latch", "candidate-latch", "write-blocked"} {
		t.Run(condition, func(t *testing.T) {
			m, session, candidate := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
				t.Fatal(err)
			}
			compatibilityStorePublishReceipt(t, m, "reaped", 0)
			state, image := compatibilityStoreRead(t, m, session)
			ctx := context.Background()
			m.mu.Lock()
			switch condition {
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "memory-latch":
				m.compatibilityUnknown = true
			case "session-latch":
				m.state.CompatibilitySession.Unknown = true
			case "candidate-latch":
				candidate.Validation.QuiescenceUnknown = true
				m.state.Candidates[candidate.ID] = candidate
			case "write-blocked":
				m.writeBlocked = true
			}
			m.mu.Unlock()
			before := compatibilityStoreBytes(t, m)
			if err := compatibilityStoreAck(m, ctx, state, image); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) || m.state.CompatibilitySession.DryRun.Acknowledged {
				t.Fatalf("late acknowledgement cleared a retained fence: %v", err)
			}
		})
	}
}

func TestCompatibilityStoreAcknowledgementRequiresExactReadbackImage(t *testing.T) {
	for _, mutation := range []string{"receipt", "output", "command", "candidate", "intent-image", "forged-state-and-image"} {
		t.Run(mutation, func(t *testing.T) {
			m, session, _ := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
				t.Fatal(err)
			}
			compatibilityStorePublishReceipt(t, m, "reaped", 0)
			state, image := compatibilityStoreRead(t, m, session)
			switch mutation {
			case "receipt":
				state.CompatibilitySession.DryRun.Receipt.ChildPID++
			case "output":
				state.CompatibilitySession.DryRun.Output = "caller substituted diagnostics"
			case "command":
				state.CompatibilitySession.DryRun.Command.ParentStart = "999"
				compatibilityRecordReseal(state.CompatibilitySession.DryRun)
			case "candidate", "forged-state-and-image":
				for id, candidate := range state.Candidates {
					candidate.Name = "caller substituted draft"
					state.Candidates[id] = candidate
				}
				if mutation == "forged-state-and-image" {
					var err error
					image, err = compatibilityStateImage(state)
					if err != nil {
						t.Fatal(err)
					}
				}
			case "intent-image":
				image = m.image
			}
			before := compatibilityStoreBytes(t, m)
			if err := compatibilityStoreAck(m, context.Background(), state, image); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) || m.state.CompatibilitySession.DryRun.Acknowledged || state.CompatibilitySession.DryRun.Acknowledged {
				t.Fatalf("caller-substituted result/image acquired acknowledgement: %v", err)
			}
		})
	}
}

func TestCompatibilityStoreLuaReadbackCannotAlterPriorReceipt(t *testing.T) {
	for _, mutation := range []string{"prior-output", "prior-reap-count"} {
		t.Run(mutation, func(t *testing.T) {
			m, dry, _ := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), dry); err != nil {
				t.Fatal(err)
			}
			compatibilityStorePublishReceipt(t, m, "reaped", 0)
			state, image := compatibilityStoreRead(t, m, dry)
			if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
				t.Fatal(err)
			}
			lua := compatibilityStoreLuaSession(t, *m.state.CompatibilitySession)
			if err := compatibilityStoreBegin(m, context.Background(), lua); err != nil {
				t.Fatal(err)
			}
			changed := compatibilityStoreStateClone(t, m.state)
			compatibilityRecordReceipt(changed.CompatibilitySession.LuaInit, "reaped", false, 7)
			if mutation == "prior-output" {
				changed.CompatibilitySession.DryRun.Output = "late helper changed prior diagnostics"
			} else {
				changed.CompatibilitySession.DryRun.Receipt.Reaped++
			}
			if err := validateCompatibilitySession(*changed.CompatibilitySession); err != nil {
				t.Fatalf("fixture must remain structurally valid: %v", err)
			}
			published := compatibilityStoreRawState(t, m, changed)
			m.mu.Lock()
			_, _, err := m.readCompatibilityResultLocked(context.Background(), lua)
			m.mu.Unlock()
			if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(published.Data, compatibilityStoreBytes(t, m)) || m.state.CompatibilitySession.LuaInit.Acknowledged {
				t.Fatalf("active helper changed the acknowledged prior phase: %v", err)
			}
		})
	}
}

func TestCompatibilityStoreCASConflictCannotAdmitOrAcknowledge(t *testing.T) {
	t.Run("intent-conflict", func(t *testing.T) {
		m, session, _ := compatibilityStoreFixture(t)
		other, err := New(m.Path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.AddCandidate("tcp-tls", "other writer", "--filter-tcp=80", "expert"); err != nil {
			t.Fatal(err)
		}
		before := compatibilityStoreBytes(t, m)
		if err := compatibilityStoreBegin(m, context.Background(), session); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !errors.Is(err, restorejournal.ErrConflict) || !m.writeBlocked || !m.Snapshot().QuiescenceUnknown || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
			t.Fatalf("stale intent CAS acquired launch admission: %v", err)
		}
	})
	t.Run("ack-conflict", func(t *testing.T) {
		m, session, _ := compatibilityStoreFixture(t)
		if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
			t.Fatal(err)
		}
		compatibilityStorePublishReceipt(t, m, "reaped", 0)
		state, image := compatibilityStoreRead(t, m, session)
		other := compatibilityStoreStateClone(t, state)
		for id, candidate := range other.Candidates {
			candidate.Name = "external writer after readback"
			other.Candidates[id] = candidate
		}
		data, err := json.Marshal(other)
		if err != nil {
			t.Fatal(err)
		}
		changed := compatibilityStoreRawCAS(t, m, image, data)
		if err := compatibilityStoreAck(m, context.Background(), state, image); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !errors.Is(err, restorejournal.ErrConflict) || !m.writeBlocked || !m.Snapshot().QuiescenceUnknown || !bytes.Equal(changed.Data, compatibilityStoreBytes(t, m)) || m.state.CompatibilitySession.DryRun.Acknowledged {
			t.Fatalf("stale acknowledgement overwrote later state: %v", err)
		}
		reloaded, err := New(m.Path)
		if err != nil || !reloaded.Snapshot().QuiescenceUnknown {
			t.Fatalf("CAS conflict lost unacknowledged completion after reopen: %v", err)
		}
	})
}

func TestCompatibilityStoreOrdinaryWritersPreservePendingSession(t *testing.T) {
	for _, operation := range []string{"add", "delete", "reset-selection", "import-pack"} {
		t.Run(operation, func(t *testing.T) {
			m, session, candidate := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
				t.Fatal(err)
			}
			before := compatibilityStoreBytes(t, m)
			var err error
			switch operation {
			case "add":
				_, err = m.AddCandidate("tcp-tls", "new draft during pending", "--filter-tcp=80", "expert")
			case "delete":
				err = m.DeleteCandidate(candidate.ID)
			case "reset-selection":
				err = m.ResetSelection("service", "tcp", "ipv4")
			case "import-pack":
				pack := testPack(t, 1)
				review, reviewErr := ReviewPack(pack, false, nil, packTime)
				if reviewErr != nil {
					t.Fatal(reviewErr)
				}
				_, err = m.ImportPack(pack, false, review.SHA256)
			}
			if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) || !m.Snapshot().QuiescenceUnknown || m.state.CompatibilitySession == nil || m.state.CompatibilitySession.DryRun.CommandSHA256 != session.DryRun.CommandSHA256 {
				t.Fatalf("ordinary writer discarded or changed pending session: %v", err)
			}
			if len(m.Snapshot().Candidates) != 1 || m.Snapshot().Candidates[0].ID != candidate.ID {
				t.Fatal("failed pending writer published uncommitted draft mutation")
			}
		})
	}
	t.Run("stale-manager", func(t *testing.T) {
		m, session, _ := compatibilityStoreFixture(t)
		stale, err := New(m.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
			t.Fatal(err)
		}
		before := compatibilityStoreBytes(t, m)
		if _, err := stale.AddCandidate("tcp-tls", "stale draft writer", "--filter-tcp=80", "expert"); !errors.Is(err, restorejournal.ErrConflict) || !stale.writeBlocked || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
			t.Fatalf("ordinary stale manager overwrote durable intent: %v", err)
		}
	})
	t.Run("reloaded-unacknowledged", func(t *testing.T) {
		m, session, _ := compatibilityStoreFixture(t)
		if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
			t.Fatal(err)
		}
		compatibilityStorePublishReceipt(t, m, "reaped", 0)
		reloaded, err := New(m.Path)
		if err != nil {
			t.Fatal(err)
		}
		before := compatibilityStoreBytes(t, m)
		if _, err := reloaded.AddCandidate("tcp-tls", "draft after crash before ACK", "--filter-tcp=80", "expert"); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
			t.Fatalf("reopened writer discarded an unacknowledged receipt: %v", err)
		}
		if active := compatibilityActiveInvocation(reloaded.state.CompatibilitySession); active == nil || active.Acknowledged || active.Receipt.State != "reaped" {
			t.Fatal("failed ordinary writer changed the retained terminal receipt")
		}
	})
}

func TestCompatibilityStorePhaseACKRetainsFinalizingAfterCrash(t *testing.T) {
	for _, phase := range []string{"dry-run", "lua-init"} {
		t.Run(phase, func(t *testing.T) {
			m, session, _ := compatibilityStoreFixture(t)
			if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
				t.Fatal(err)
			}
			compatibilityStorePublishReceipt(t, m, "reaped", 0)
			state, image := compatibilityStoreRead(t, m, session)
			if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
				t.Fatal(err)
			}
			if phase == "lua-init" {
				session = compatibilityStoreLuaSession(t, *m.state.CompatibilitySession)
				if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
					t.Fatal(err)
				}
				compatibilityStorePublishReceipt(t, m, "reaped", 0)
				state, image = compatibilityStoreRead(t, m, session)
				if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := New(m.Path)
			if err != nil || !reopened.state.CompatibilityFinalizing || !reopened.Snapshot().QuiescenceUnknown || compatibilitySessionUnknown(*reopened.state.CompatibilitySession) {
				t.Fatalf("phase ACK survived crash as a finalized validation: %v", err)
			}
			before := compatibilityStoreBytes(t, m)
			if _, err := reopened.AddCandidate("tcp-tls", "draft after phase ACK", "--filter-tcp=80", "expert"); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
				t.Fatalf("ordinary writer discarded acknowledged finalizing marker: %v", err)
			}
			if err := compatibilityStoreBegin(reopened, context.Background(), compatibilityRecordFixture(t)); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatalf("new session replayed an ACKed but unpublished validation: %v", err)
			}
			if phase == "dry-run" {
				if reopened.nativeRunning {
					t.Fatal("reopened Manager has no inherited native admission")
				}
				lua := compatibilityStoreLuaSession(t, *reopened.state.CompatibilitySession)
				if err := compatibilityStoreBegin(reopened, context.Background(), lua); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
					t.Fatalf("reopened Manager resumed Lua from an ACKed phase without its original owner: %v", err)
				}
			}
		})
	}
}

// Construct a trusted parent-side completion token without running a provider.
// Native=true below is modeled persisted data, never a real compatibility PASS.
func compatibilityStoreFinalizationFixture(t *testing.T, phase string, exit int) (*Manager, *SupervisedCompatibilityProvider, Candidate, Validation) {
	t.Helper()
	m, session, candidate := compatibilityStoreFixture(t)
	controlPath := filepath.Join(filepath.Dir(m.Path), "authority")
	control, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlPath)
	if err != nil {
		t.Fatal(err)
	}
	review := &session.DryRun.Command.Review
	review.ControlPath, review.InstallationID, review.Sequence = controlPath, control.InstallationID, control.Sequence
	compatibilityRecordReseal(session.DryRun)
	if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
		t.Fatal(err)
	}
	dryExit := exit
	if phase == "lua-init" {
		dryExit = 0
	}
	compatibilityStorePublishReceipt(t, m, "reaped", dryExit)
	state, image := compatibilityStoreRead(t, m, session)
	if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
		t.Fatal(err)
	}
	if phase == "lua-init" {
		session = compatibilityStoreLuaSession(t, *m.state.CompatibilitySession)
		if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
			t.Fatal(err)
		}
		compatibilityStorePublishReceipt(t, m, "reaped", exit)
		state, image = compatibilityStoreRead(t, m, session)
		if err := compatibilityStoreAck(m, context.Background(), state, image); err != nil {
			t.Fatal(err)
		}
	}
	completed := compatibilityRecordClone(t, *m.state.CompatibilitySession)
	provider := &SupervisedCompatibilityProvider{manager: m, review: completed.DryRun.Command.Review, session: &completed}
	m.Validator = CompatibleValidator{Provider: provider}
	arguments, err := parseArguments(candidate.Arguments)
	if err != nil {
		t.Fatal(err)
	}
	validation := Validation{Code: "COMPATIBILITY_REJECTED", Arguments: arguments}
	if phase == "lua-init" && exit == 0 {
		validation.OK, validation.Native, validation.LuaChecked, validation.Code = true, true, true, "COMPATIBLE"
	}
	return m, provider, candidate, validation
}

func TestCompatibilityStoreModeledFinalPublicationIsOneAtomicImage(t *testing.T) {
	for _, outcome := range []struct {
		name, phase string
		exit        int
	}{{"dry-rejected", "dry-run", 7}, {"lua-rejected", "lua-init", 7}, {"modeled-lua-pass", "lua-init", 0}} {
		t.Run(outcome.name, func(t *testing.T) {
			m, _, candidate, validation := compatibilityStoreFinalizationFixture(t, outcome.phase, outcome.exit)
			before := compatibilityStoreBytes(t, m)
			m.mu.Lock()
			err := m.prepareCompatibilityPublicationLocked(context.Background(), validation)
			m.mu.Unlock()
			if err != nil || m.state.CompatibilityFinalizing || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
				t.Fatalf("preparing publication changed its durable crash fence: %v", err)
			}
			reopened, err := New(m.Path)
			if err != nil || !reopened.Snapshot().QuiescenceUnknown || reopened.state.Candidates[candidate.ID].Validation.Native {
				t.Fatalf("crash before publication forgot finalizing marker: %v", err)
			}
			candidate.Validation = validation
			m.mu.Lock()
			m.state.Candidates[candidate.ID] = candidate
			err = m.saveLocked()
			m.mu.Unlock()
			if err != nil || !bytes.Equal(m.image.Data, compatibilityStoreBytes(t, m)) {
				t.Fatalf("candidate and marker were not published by one exact CAS: %v", err)
			}
			reopened, err = New(m.Path)
			if err != nil || reopened.Snapshot().QuiescenceUnknown || reopened.state.CompatibilityFinalizing || !compatibilityJSONEqual(reopened.state.Candidates[candidate.ID].Validation, validation) {
				t.Fatalf("final image lost its accepted modeled result: %v", err)
			}
		})
	}
}

func TestCompatibilityStoreModeledFinalPublicationRejectsUnknownOrMismatch(t *testing.T) {
	for _, condition := range []string{"cancelled", "retained-unknown", "unbound-validator", "other-manager", "provider-running", "provider-unknown", "different-session", "wrong-arguments", "cancelled-result", "unknown-result", "missing-native-proof", "no-admission", "stopped"} {
		t.Run(condition, func(t *testing.T) {
			m, provider, _, validation := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
			ctx := context.Background()
			switch condition {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "retained-unknown":
				m.compatibilityUnknown = true
			case "unbound-validator":
				m.Validator = fakeValidator{}
			case "other-manager":
				provider.manager = &Manager{}
			case "provider-running":
				provider.running = true
			case "provider-unknown":
				provider.unknown = true
			case "different-session":
				provider.session.ID = strings.Repeat("f", 32)
			case "wrong-arguments":
				validation.Arguments = []string{"--lua-desync=fake:blob=0x00000000"}
			case "cancelled-result":
				validation.Code = "VALIDATION_CANCELLED"
			case "unknown-result":
				validation.QuiescenceUnknown = true
			case "missing-native-proof":
				validation.Native = false
			case "no-admission":
				m.nativeRunning = false
			case "stopped":
				if _, err := operationgate.RequestSelfUpdateStop(ctx, provider.review.ControlPath, strings.Repeat("e", 32), 1); err != nil {
					t.Fatal(err)
				}
			}
			before := compatibilityStoreBytes(t, m)
			m.mu.Lock()
			err := m.prepareCompatibilityPublicationLocked(ctx, validation)
			m.mu.Unlock()
			if !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !m.state.CompatibilityFinalizing || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
				t.Fatalf("unaccepted modeled result cleared publication fence: %v", err)
			}
		})
	}
}

func TestCompatibilityStoreFinalPublicationConflictRestoresCrashFence(t *testing.T) {
	m, _, candidate, validation := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
	durable, err := decodeCompatibilityState(m.image)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	err = m.prepareCompatibilityPublicationLocked(context.Background(), validation)
	if err == nil {
		candidate.Validation = validation
		m.state.Candidates[candidate.ID] = candidate
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an independent protected-file writer after preparation. Its
	// image retains the marker; our stale publication must not replace it.
	changed := durable.Candidates[candidate.ID]
	changed.Name = "independent writer before final publication"
	durable.Candidates[candidate.ID] = changed
	image := compatibilityStoreRawState(t, m, durable)
	m.mu.Lock()
	err = m.saveLocked()
	m.mu.Unlock()
	if !errors.Is(err, restorejournal.ErrConflict) || !m.writeBlocked || !m.state.CompatibilityFinalizing || !m.Snapshot().QuiescenceUnknown || m.state.Candidates[candidate.ID].Validation.Native || !bytes.Equal(image.Data, compatibilityStoreBytes(t, m)) {
		t.Fatalf("failed final publication dropped its preexisting crash fence: %v", err)
	}
	reopened, err := New(m.Path)
	if err != nil || !reopened.Snapshot().QuiescenceUnknown || !reopened.state.CompatibilityFinalizing || reopened.state.Candidates[candidate.ID].Validation.Native {
		t.Fatalf("publication conflict became known or fabricated native validation on restart: %v", err)
	}
}

func TestCompatibilityStoreRejectsAmbiguousJSON(t *testing.T) {
	m, session, _ := compatibilityStoreFixture(t)
	if err := compatibilityStoreBegin(m, context.Background(), session); err != nil {
		t.Fatal(err)
	}
	image := m.image
	terminal := compatibilityStoreStateClone(t, m.state)
	compatibilityRecordReceipt(terminal.CompatibilitySession.DryRun, "reaped", false, 0)
	terminal.CompatibilitySession.DryRun.Output = "terminal"
	terminalImage, err := compatibilityStateImage(terminal)
	if err != nil {
		t.Fatal(err)
	}
	malformedOutput := append([]byte(`"output": "`), 0xff)
	malformedOutput = append(malformedOutput, '"')
	cases := []struct {
		name string
		data []byte
	}{
		{"duplicate-schema", bytes.Replace(image.Data, []byte(`"schema_version": 3`), []byte(`"schema_version": 3, "schema_version": 3`), 1)},
		{"duplicate-command-parent", bytes.Replace(image.Data, []byte(`"parent_pid": 20`), []byte(`"parent_pid": 20, "parent_pid": 20`), 1)},
		{"duplicate-case-folded-parent", bytes.Replace(image.Data, []byte(`"parent_pid": 20`), []byte(`"parent_pid": 20, "PARENT_PID": 20`), 1)},
		{"malformed-utf8-output", bytes.Replace(terminalImage.Data, []byte(`"output": "terminal"`), malformedOutput, 1)},
		{"unknown-field", append([]byte(`{"unexpected": true,`), image.Data[1:]...)},
		{"trailing-json", append(append([]byte(nil), image.Data...), []byte(`{}`)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.data, image.Data) {
				t.Fatal("ambiguous JSON fixture was not altered")
			}
			if _, err := decodeCompatibilityState(restorejournal.Image{Exists: true, Data: tc.data}); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatalf("ambiguous helper state parsed as an authorized intent: %v", err)
			}
			current, err := restorejournal.ReadFileImage(context.Background(), m.Path)
			if err != nil {
				t.Fatal(err)
			}
			compatibilityStoreRawCAS(t, m, current, tc.data)
			if reloaded, err := New(m.Path); err == nil || reloaded != nil {
				t.Fatalf("Manager reopen admitted corrupted supervised state: %v", err)
			}
		})
	}
}
