package strategylab

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// This fixture models reviewed identities and helper receipts without reading
// those files or executing a command. A modeled PASS has no native authority.
func compatibilityRecordFixture(t *testing.T) compatibilitySession {
	t.Helper()
	root := t.TempDir()
	base := compatibilityBase(root)
	assets := make([]compatibilityFileBinding, len(base))
	for i, arg := range base {
		path := strings.TrimPrefix(arg, "--lua-init=@")
		if strings.HasPrefix(arg, "--blob=") {
			_, path, _ = strings.Cut(arg, ":@")
		}
		assets[i] = compatibilityFileBinding{Path: path, SHA256: strings.Repeat("a", 64), Size: 2}
	}
	command := compatibilityCommand{
		ID: strings.Repeat("1", 32), SessionID: strings.Repeat("2", 32), Phase: "dry-run",
		BootID: "01234567-89ab-cdef-0123-456789abcdef", ParentStart: "123", ParentPID: 20,
		Deadline: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
		Review: compatibilityReview{
			Binary: compatibilityFileBinding{Path: filepath.Join(root, "nfqws2"), SHA256: strings.Repeat("b", 64), Size: 1},
			Assets: assets, BaseArguments: base, ControlPath: filepath.Join(root, "installed.json"),
			InstallationID: strings.Repeat("3", 32), Sequence: 1,
		},
	}
	command.Args = closedCompatibilityCommand(t, base, []string{"--filter-tcp=443", "--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}, true)
	invocation := &compatibilityInvocation{Command: command, CommandSHA256: compatibilityCommandDigest(command), Receipt: compatibilityReceipt{State: "intent"}}
	return compatibilitySession{Schema: 1, ID: command.SessionID, Active: "dry-run", DryRun: invocation}
}

func compatibilityRecordClone(t *testing.T, session compatibilitySession) compatibilitySession {
	t.Helper()
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	var cloned compatibilitySession
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func compatibilityRecordReseal(invocation *compatibilityInvocation) {
	previous := invocation.CommandSHA256
	invocation.CommandSHA256 = compatibilityCommandDigest(invocation.Command)
	if invocation.Receipt.CommandSHA256 == previous {
		invocation.Receipt.CommandSHA256 = invocation.CommandSHA256
	}
}

func compatibilityRecordReceipt(invocation *compatibilityInvocation, state string, acknowledged bool, exit int) {
	r := compatibilityReceipt{State: state, BootID: invocation.Command.BootID, CommandSHA256: invocation.CommandSHA256, PID: 21, Group: 21, Start: "124", ExitCode: exit}
	switch state {
	case "running":
		r.Started, r.ChildPID = true, 22
	case "reaped":
		r.Started, r.ChildPID, r.DirectReaped, r.Reaped, r.WaitECHILD = true, 22, true, 1, true
	case "not-started":
		r.WaitECHILD = true
	}
	invocation.Receipt, invocation.Acknowledged = r, acknowledged
}

func compatibilityRecordLuaFixture(t *testing.T) compatibilitySession {
	t.Helper()
	session := compatibilityRecordFixture(t)
	compatibilityRecordReceipt(session.DryRun, "reaped", true, 0)
	command := session.DryRun.Command
	command.ID, command.Phase = strings.Repeat("4", 32), "lua-init"
	command.Review.Assets = slices.Clone(command.Review.Assets)
	command.Review.BaseArguments = slices.Clone(command.Review.BaseArguments)
	command.Args = closedCompatibilityCommand(t, command.Review.BaseArguments, session.DryRun.Command.Args[2+len(command.Review.BaseArguments):], false)
	session.Active, session.LuaInit = "lua-init", &compatibilityInvocation{Command: command, CommandSHA256: compatibilityCommandDigest(command), Receipt: compatibilityReceipt{State: "intent"}}
	return session
}

func TestCompatibilityRecordUnknownRequiresAcknowledgedTerminal(t *testing.T) {
	fixture := compatibilityRecordFixture(t)
	cases := []struct {
		name    string
		mutate  func(*compatibilityInvocation)
		unknown bool
		success bool
	}{
		{"intent", func(*compatibilityInvocation) {}, true, false},
		{"bound-intent", func(i *compatibilityInvocation) {
			i.Receipt.BootID, i.Receipt.CommandSHA256 = i.Command.BootID, i.CommandSHA256
		}, true, false},
		{"armed", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "armed", false, 0) }, true, false},
		{"running", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "running", false, 0) }, true, false},
		{"direct-reaped-descendants-pending", func(i *compatibilityInvocation) {
			compatibilityRecordReceipt(i, "running", false, 7)
			i.Receipt.DirectReaped, i.Receipt.Reaped = true, 1
		}, true, false},
		{"reaped-unacknowledged", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "reaped", false, 0) }, true, false},
		{"reaped-acknowledged", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "reaped", true, 0) }, false, true},
		{"rejected-acknowledged", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "reaped", true, 7) }, false, false},
		{"cancelled-acknowledged", func(i *compatibilityInvocation) {
			compatibilityRecordReceipt(i, "reaped", true, 125)
			i.Receipt.Cancelled = true
		}, false, false},
		{"not-started-unacknowledged", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "not-started", false, 0) }, true, false},
		{"not-started-zero-exit", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "not-started", true, 0) }, false, false},
		{"not-started-rejected", func(i *compatibilityInvocation) { compatibilityRecordReceipt(i, "not-started", true, 126) }, false, false},
		{"not-started-cancelled", func(i *compatibilityInvocation) {
			compatibilityRecordReceipt(i, "not-started", true, 125)
			i.Receipt.Cancelled = true
		}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := compatibilityRecordClone(t, fixture)
			tc.mutate(session.DryRun)
			if err := validateCompatibilitySession(session); err != nil {
				t.Fatal(err)
			}
			if compatibilitySessionUnknown(session) != tc.unknown || compatibilityInvocationSucceeded(*session.DryRun) != tc.success {
				t.Fatalf("wrong modeled receipt interpretation: %+v", session.DryRun)
			}
			session.Unknown = true
			if !compatibilitySessionUnknown(session) {
				t.Fatal("a retained unknown fence was cleared by receipt parsing")
			}
		})
	}
}

func TestCompatibilityRecordRejectsCorruption(t *testing.T) {
	fixture := compatibilityRecordFixture(t)
	compatibilityRecordReceipt(fixture.DryRun, "reaped", true, 0)
	unclean := fixture.DryRun.Command.Review.Binary.Path + string(filepath.Separator) + ".." + string(filepath.Separator) + "nfqws2"
	cases := []struct {
		name       string
		mutate     func(*compatibilitySession)
		keepDigest bool
	}{
		{"schema", func(s *compatibilitySession) { s.Schema = 2 }, false},
		{"session-id", func(s *compatibilitySession) { s.ID = "invalid" }, false},
		{"active-phase", func(s *compatibilitySession) { s.Active = "completed" }, false},
		{"missing-dry-run", func(s *compatibilitySession) { s.DryRun = nil }, false},
		{"command-id-uppercase", func(s *compatibilitySession) { s.DryRun.Command.ID = strings.Repeat("A", 32) }, false},
		{"session-replay", func(s *compatibilitySession) { s.DryRun.Command.SessionID = strings.Repeat("f", 32) }, false},
		{"phase", func(s *compatibilitySession) { s.DryRun.Command.Phase = "lua-init" }, false},
		{"boot", func(s *compatibilitySession) { s.DryRun.Command.BootID = "0123456789abcdef0123456789abcdef" }, false},
		{"parent-pid", func(s *compatibilitySession) { s.DryRun.Command.ParentPID = 1 }, false},
		{"parent-start-zero", func(s *compatibilitySession) { s.DryRun.Command.ParentStart = "0" }, false},
		{"parent-start-noncanonical", func(s *compatibilitySession) { s.DryRun.Command.ParentStart = "0123" }, false},
		{"parent-start-overflow", func(s *compatibilitySession) { s.DryRun.Command.ParentStart = "18446744073709551616" }, false},
		{"zero-deadline", func(s *compatibilitySession) { s.DryRun.Command.Deadline = time.Time{} }, false},
		{"non-utc-deadline", func(s *compatibilitySession) {
			s.DryRun.Command.Deadline = s.DryRun.Command.Deadline.In(time.FixedZone("offset", 3600))
		}, false},
		{"noncanonical-zero-zone", func(s *compatibilitySession) {
			s.DryRun.Command.Deadline = s.DryRun.Command.Deadline.In(time.FixedZone("not UTC", 0))
		}, false},
		{"digest", func(s *compatibilitySession) { s.DryRun.CommandSHA256 = strings.Repeat("0", 64) }, true},
		{"changed-command-with-old-digest", func(s *compatibilitySession) {
			s.DryRun.Command.Args[2+len(s.DryRun.Command.Review.BaseArguments)] = "--filter-tcp=80"
		}, true},
		{"arbitrary-interception", func(s *compatibilitySession) { s.DryRun.Command.Args[1] = "--intercept=1" }, false},
		{"installation-id", func(s *compatibilitySession) { s.DryRun.Command.Review.InstallationID = strings.Repeat("g", 32) }, false},
		{"sequence", func(s *compatibilitySession) { s.DryRun.Command.Review.Sequence = 0 }, false},
		{"control-relative", func(s *compatibilitySession) { s.DryRun.Command.Review.ControlPath = "installed.json" }, false},
		{"binary-relative", func(s *compatibilitySession) { s.DryRun.Command.Review.Binary.Path = "nfqws2" }, false},
		{"binary-unclean", func(s *compatibilitySession) { s.DryRun.Command.Review.Binary.Path = unclean }, false},
		{"binary-size-zero", func(s *compatibilitySession) { s.DryRun.Command.Review.Binary.Size = 0 }, false},
		{"binary-size-limit", func(s *compatibilitySession) { s.DryRun.Command.Review.Binary.Size = 64<<20 + 1 }, false},
		{"binary-hash-uppercase", func(s *compatibilitySession) { s.DryRun.Command.Review.Binary.SHA256 = strings.Repeat("B", 64) }, false},
		{"asset-size-zero", func(s *compatibilitySession) { s.DryRun.Command.Review.Assets[0].Size = 0 }, false},
		{"asset-size-limit", func(s *compatibilitySession) { s.DryRun.Command.Review.Assets[0].Size = 4<<20 + 1 }, false},
		{"asset-hash", func(s *compatibilitySession) { s.DryRun.Command.Review.Assets[0].SHA256 = strings.Repeat("0", 63) }, false},
		{"asset-order", func(s *compatibilitySession) { a := s.DryRun.Command.Review.Assets; a[0], a[1] = a[1], a[0] }, false},
		{"missing-asset", func(s *compatibilitySession) { s.DryRun.Command.Review.Assets = s.DryRun.Command.Review.Assets[1:] }, false},
		{"duplicate-asset", func(s *compatibilitySession) {
			s.DryRun.Command.Review.Assets = append(s.DryRun.Command.Review.Assets, s.DryRun.Command.Review.Assets[0])
		}, false},
		{"extra-asset", func(s *compatibilitySession) {
			a := s.DryRun.Command.Review.Assets[0]
			a.Path += ".extra"
			s.DryRun.Command.Review.Assets = append(s.DryRun.Command.Review.Assets, a)
		}, false},
		{"too-many-assets", func(s *compatibilitySession) {
			s.DryRun.Command.Review.Assets = slices.Repeat(s.DryRun.Command.Review.Assets[:1], 17)
		}, false},
		{"too-many-base", func(s *compatibilitySession) {
			s.DryRun.Command.Review.BaseArguments = slices.Repeat(s.DryRun.Command.Review.BaseArguments[:1], 17)
		}, false},
		{"receipt-boot", func(s *compatibilitySession) { s.DryRun.Receipt.BootID = "11234567-89ab-cdef-0123-456789abcdef" }, false},
		{"receipt-hash", func(s *compatibilitySession) { s.DryRun.Receipt.CommandSHA256 = strings.Repeat("0", 64) }, false},
		{"receipt-pid", func(s *compatibilitySession) { s.DryRun.Receipt.PID = 1 }, false},
		{"receipt-group", func(s *compatibilitySession) { s.DryRun.Receipt.Group++ }, false},
		{"receipt-start", func(s *compatibilitySession) { s.DryRun.Receipt.Start = "+124" }, false},
		{"receipt-state", func(s *compatibilitySession) { s.DryRun.Receipt.State = "complete" }, false},
		{"missing-started", func(s *compatibilitySession) { s.DryRun.Receipt.Started = false }, false},
		{"missing-child", func(s *compatibilitySession) { s.DryRun.Receipt.ChildPID = 0 }, false},
		{"missing-direct-status", func(s *compatibilitySession) { s.DryRun.Receipt.DirectReaped = false }, false},
		{"missing-echild", func(s *compatibilitySession) { s.DryRun.Receipt.WaitECHILD = false }, false},
		{"missing-reaped", func(s *compatibilitySession) { s.DryRun.Receipt.Reaped = 0 }, false},
		{"cancelled-success", func(s *compatibilitySession) { s.DryRun.Receipt.Cancelled = true }, false},
		{"output-limit", func(s *compatibilitySession) { s.DryRun.Output = strings.Repeat("x", 8193) }, false},
		{"output-invalid-utf8", func(s *compatibilitySession) { s.DryRun.Output = string([]byte{0xff}) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := compatibilityRecordClone(t, fixture)
			tc.mutate(&session)
			if session.DryRun != nil && !tc.keepDigest {
				compatibilityRecordReseal(session.DryRun)
			}
			if err := validateCompatibilitySession(session); err == nil || !compatibilitySessionUnknown(session) {
				t.Fatalf("corruption accepted as known: error=%v session=%+v", err, session)
			}
		})
	}
}

func TestCompatibilityRecordPendingCannotAcquireProof(t *testing.T) {
	fixture := compatibilityRecordFixture(t)
	cases := []struct {
		name   string
		state  string
		mutate func(*compatibilityInvocation)
	}{
		{"intent-ack", "intent", func(i *compatibilityInvocation) { i.Acknowledged = true }},
		{"intent-child", "intent", func(i *compatibilityInvocation) { i.Receipt.ChildPID = 22 }},
		{"intent-helper", "intent", func(i *compatibilityInvocation) { i.Receipt.PID = 21 }},
		{"intent-proof", "intent", func(i *compatibilityInvocation) { i.Receipt.WaitECHILD = true }},
		{"intent-hash-mismatch", "intent", func(i *compatibilityInvocation) { i.Receipt.CommandSHA256 = strings.Repeat("0", 64) }},
		{"intent-output", "intent", func(i *compatibilityInvocation) { i.Output = "diagnostic" }},
		{"armed-ack", "armed", func(i *compatibilityInvocation) { i.Acknowledged = true }},
		{"armed-started", "armed", func(i *compatibilityInvocation) { i.Receipt.Started = true }},
		{"armed-output", "armed", func(i *compatibilityInvocation) { i.Output = "diagnostic" }},
		{"running-ack", "running", func(i *compatibilityInvocation) { i.Acknowledged = true }},
		{"running-echild", "running", func(i *compatibilityInvocation) { i.Receipt.WaitECHILD = true }},
		{"running-output", "running", func(i *compatibilityInvocation) { i.Output = "diagnostic" }},
		{"running-no-started", "running", func(i *compatibilityInvocation) { i.Receipt.Started = false }},
		{"running-status-without-direct", "running", func(i *compatibilityInvocation) { i.Receipt.ExitCode = 7 }},
		{"not-started-direct-status", "not-started", func(i *compatibilityInvocation) { i.Receipt.DirectReaped = true }},
		{"not-started-no-echild", "not-started", func(i *compatibilityInvocation) { i.Receipt.WaitECHILD = false }},
		{"not-started-child", "not-started", func(i *compatibilityInvocation) { i.Receipt.ChildPID = 22 }},
		{"not-started-reaped", "not-started", func(i *compatibilityInvocation) { i.Receipt.Reaped = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := compatibilityRecordClone(t, fixture)
			if tc.state != "intent" {
				compatibilityRecordReceipt(session.DryRun, tc.state, false, 0)
			}
			tc.mutate(session.DryRun)
			if err := validateCompatibilitySession(session); err == nil || !compatibilitySessionUnknown(session) {
				t.Fatalf("impossible pending/proof receipt accepted: error=%v receipt=%+v", err, session.DryRun.Receipt)
			}
		})
	}
}

func TestCompatibilityRecordLuaRequiresExactAcknowledgedDryRun(t *testing.T) {
	fixture := compatibilityRecordLuaFixture(t)
	if err := validateCompatibilitySession(fixture); err != nil || !compatibilitySessionUnknown(fixture) {
		t.Fatalf("valid pending Lua model rejected: %v", err)
	}
	compatibilityRecordReceipt(fixture.LuaInit, "reaped", true, 7)
	fixture.LuaInit.Output = "modeled Lua assertion rejection"
	if err := validateCompatibilitySession(fixture); err != nil || compatibilitySessionUnknown(fixture) {
		t.Fatalf("acknowledged Lua rejection not known inactive: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*compatibilitySession)
	}{
		{"rewind", func(s *compatibilitySession) { s.Active = "dry-run" }},
		{"missing-lua", func(s *compatibilitySession) { s.LuaInit = nil }},
		{"dry-unacknowledged", func(s *compatibilitySession) { s.DryRun.Acknowledged = false }},
		{"dry-reject", func(s *compatibilitySession) { s.DryRun.Receipt.ExitCode = 7 }},
		{"dry-cancelled", func(s *compatibilitySession) { s.DryRun.Receipt.Cancelled, s.DryRun.Receipt.ExitCode = true, 125 }},
		{"dry-not-started-zero-exit", func(s *compatibilitySession) { compatibilityRecordReceipt(s.DryRun, "not-started", true, 0) }},
		{"reused-invocation", func(s *compatibilitySession) { s.LuaInit.Command.ID = s.DryRun.Command.ID }},
		{"review-binary", func(s *compatibilitySession) { s.LuaInit.Command.Review.Binary.SHA256 = strings.Repeat("c", 64) }},
		{"review-asset", func(s *compatibilitySession) { s.LuaInit.Command.Review.Assets[0].SHA256 = strings.Repeat("c", 64) }},
		{"review-sequence", func(s *compatibilitySession) { s.LuaInit.Command.Review.Sequence++ }},
		{"review-installation", func(s *compatibilitySession) { s.LuaInit.Command.Review.InstallationID = strings.Repeat("5", 32) }},
		{"review-control", func(s *compatibilitySession) { s.LuaInit.Command.Review.ControlPath += ".other" }},
		{"different-candidate", func(s *compatibilitySession) {
			s.LuaInit.Command.Args[1+len(s.LuaInit.Command.Review.BaseArguments)] = "--filter-tcp=80"
		}},
		{"different-assertion", func(s *compatibilitySession) { s.LuaInit.Command.Args[len(s.LuaInit.Command.Args)-1] += ";os.exit(0)" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := compatibilityRecordClone(t, fixture)
			tc.mutate(&session)
			if session.LuaInit != nil {
				compatibilityRecordReseal(session.LuaInit)
			}
			if err := validateCompatibilitySession(session); err == nil || !compatibilitySessionUnknown(session) {
				t.Fatalf("phase replay or changed review accepted: error=%v", err)
			}
		})
	}
}

func TestCompatibilityRecordBoundsAndRoundTrip(t *testing.T) {
	session := compatibilityRecordFixture(t)
	i := session.DryRun
	i.Command.Review.Binary.Size = 64 << 20
	for j := range i.Command.Review.Assets {
		i.Command.Review.Assets[j].Size = 4 << 20
	}
	// Repeated base paths retain one reviewed binding in first-occurrence
	// order; the complete argv still binds all 16 immutable base tokens.
	for len(i.Command.Review.BaseArguments) < 16 {
		i.Command.Review.BaseArguments = append(i.Command.Review.BaseArguments, i.Command.Review.BaseArguments[0])
	}
	i.Command.Args = closedCompatibilityCommand(t, i.Command.Review.BaseArguments, []string{"--lua-desync=fake:blob=tls_clienthello"}, true)
	compatibilityRecordReseal(i)
	compatibilityRecordReceipt(i, "reaped", true, 1)
	i.Output = strings.Repeat("я", 4096) // 8192 UTF-8 bytes, not 4096 bytes.
	if err := validateCompatibilitySession(session); err != nil || compatibilitySessionUnknown(session) {
		t.Fatalf("valid upper bounds rejected: %v", err)
	}
	cloned := compatibilityRecordClone(t, session)
	if err := validateCompatibilitySession(cloned); err != nil || compatibilitySessionUnknown(cloned) || cloned.DryRun.CommandSHA256 != session.DryRun.CommandSHA256 || cloned.DryRun.Output != i.Output {
		t.Fatalf("durable JSON round trip changes exact binding: %v", err)
	}
	i.Output += "я"
	if validateCompatibilitySession(session) == nil || !compatibilitySessionUnknown(session) {
		t.Fatal("output limit was counted in runes instead of bytes")
	}
}
