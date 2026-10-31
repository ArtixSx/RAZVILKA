package strategylab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/components"
)

// This fixture binds data-only files and an ordinary draft state. It supplies
// neither a native helper nor live control authority and never executes Lua.
func compatibilityProviderPreflightFixture(t *testing.T) (*SupervisedCompatibilityProvider, CompatibilityApproval, []byte) {
	t.Helper()
	approval := compatibilityApprovalFixture(t)
	review, err := compatibilityReviewApproved(approval)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(approval.BinaryPath), "strategy-lab.json")
	before := []byte("{\"schema_version\":1,\"candidates\":{},\"evidence\":[],\"selections\":{}}\n")
	if err := os.WriteFile(statePath, before, 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	return &SupervisedCompatibilityProvider{manager: manager, review: review}, approval, before
}

func compatibilityProviderHasNoIntent(t *testing.T, p *SupervisedCompatibilityProvider, before []byte, result CompatibilityCompletion, err error) {
	t.Helper()
	if err == nil || result.Started || !result.Quiescent || len(result.Output) != 0 {
		t.Fatalf("pre-intent refusal acquired execution or lost inactivity: result=%+v err=%v", result, err)
	}
	if p.running || p.unknown || p.session != nil {
		t.Fatalf("pre-intent refusal changed provider session: running=%t unknown=%t session=%+v", p.running, p.unknown, p.session)
	}
	m := p.manager
	if m.state.CompatibilitySession != nil || m.state.SchemaVersion != legacyStrategySchema || m.nativeRunning || m.compatibilityUnknown || m.writeBlocked {
		t.Fatalf("pre-intent refusal changed Manager authority: session=%+v schema=%d native=%t unknown=%t blocked=%t", m.state.CompatibilitySession, m.state.SchemaVersion, m.nativeRunning, m.compatibilityUnknown, m.writeBlocked)
	}
	after, readErr := os.ReadFile(m.Path)
	if readErr != nil || !bytes.Equal(before, after) || !bytes.Equal(before, m.image.Data) {
		t.Fatalf("pre-intent refusal changed durable draft state: read=%v", readErr)
	}
}

func TestCompatibilitySupervisedRefusesUnapprovedBinaryBeforeIntent(t *testing.T) {
	p, _, before := compatibilityProviderPreflightFixture(t)
	args := closedCompatibilityCommand(t, p.review.BaseArguments, []string{"--lua-desync=fake:blob=tls_clienthello"}, true)
	result, err := p.Run(context.Background(), p.review.Binary.Path+".unapproved", args...)
	compatibilityProviderHasNoIntent(t, p, before, result, err)
	if !strings.Contains(err.Error(), "binary differs") {
		t.Fatal("unapproved binary was not refused by the binary gate", err)
	}
}

func TestCompatibilitySupervisedRefusesRawArgumentsBeforeIntent(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, []string, []string) []string
		cause  string
	}{
		{"interception-enabled", func(_ *testing.T, _ []string, args []string) []string { args[1] = "--intercept=1"; return args }, "no-intercept prefix"},
		{"unapproved-base", func(_ *testing.T, _ []string, args []string) []string { args[2] += ".changed"; return args }, "immutable base"},
		{"runtime-option", func(_ *testing.T, _ []string, args []string) []string { return append(args, "--qnum=0") }, "unsupported candidate"},
		{"custom-lua", func(_ *testing.T, _ []string, args []string) []string { return append(args, "--lua-init=os.exit(0)") }, "unsupported candidate"},
		{"packed-argv", func(t *testing.T, base, _ []string) []string {
			return closedCompatibilityCommand(t, base, []string{"--filter-tcp=443 --lua-desync=fake:blob=tls_clienthello"}, true)
		}, "exact data-only tokens"},
		{"quoted-token", func(t *testing.T, base, _ []string) []string {
			return closedCompatibilityCommand(t, base, []string{"\"--filter-tcp=443\"", "--lua-desync=fake:blob=tls_clienthello"}, true)
		}, "exact data-only tokens"},
		{"assertion-tamper", func(t *testing.T, base, _ []string) []string {
			args := closedCompatibilityCommand(t, base, []string{"--lua-desync=fake:blob=tls_clienthello"}, false)
			args[len(args)-1] += ";os.exit(0)"
			return args
		}, "generated Lua assertions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, before := compatibilityProviderPreflightFixture(t)
			args := closedCompatibilityCommand(t, p.review.BaseArguments, []string{"--lua-desync=fake:blob=tls_clienthello"}, true)
			args = tc.change(t, p.review.BaseArguments, args)
			frozen := slices.Clone(args)
			result, err := p.Run(context.Background(), p.review.Binary.Path, args...)
			compatibilityProviderHasNoIntent(t, p, before, result, err)
			if !strings.Contains(err.Error(), tc.cause) {
				t.Fatal("raw argv was not refused by its closed grammar gate", err)
			}
			if !slices.Equal(args, frozen) {
				t.Fatal("provider changed caller arguments during refusal")
			}
		})
	}
}

func TestCompatibilitySupervisedRefusesLuaWithoutCurrentDryRun(t *testing.T) {
	p, _, before := compatibilityProviderPreflightFixture(t)
	args := closedCompatibilityCommand(t, p.review.BaseArguments, []string{"--lua-desync=fake:blob=tls_clienthello"}, false)
	result, err := p.Run(context.Background(), p.review.Binary.Path, args...)
	// The portable fixture has no live control authority. Platform/path/control
	// refusal can precede the current dry-run check, but cannot publish intent.
	compatibilityProviderHasNoIntent(t, p, before, result, err)
}

func TestCompatibilitySupervisedRefusesCancelledContextBeforeIntent(t *testing.T) {
	p, _, before := compatibilityProviderPreflightFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	args := closedCompatibilityCommand(t, p.review.BaseArguments, []string{"--lua-desync=fake:blob=tls_clienthello"}, true)
	result, err := p.Run(ctx, p.review.Binary.Path, args...)
	compatibilityProviderHasNoIntent(t, p, before, result, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context was not preserved", err)
	}
}

func TestCompatibilitySupervisedRefusesNilContextBeforeIntent(t *testing.T) {
	p, _, before := compatibilityProviderPreflightFixture(t)
	result, err := p.Run(nil, p.review.Binary.Path)
	compatibilityProviderHasNoIntent(t, p, before, result, err)
}

func TestCompatibilitySupervisedConstructorUnavailableOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux constructor refusal only")
	}
	p, approval, before := compatibilityProviderPreflightFixture(t)
	provider, err := NewSupervisedCompatibilityProvider(p.manager, approval)
	if provider != nil || err == nil {
		t.Fatalf("non-Linux constructor acquired a supervised provider: provider=%+v err=%v", provider, err)
	}
	if !errors.Is(err, components.ErrNFQWSSupervisionUnavailable) && !strings.Contains(err.Error(), "Linux ownership proof") {
		t.Fatal("valid explicit bytes were refused for a reason other than platform ownership availability", err)
	}
	compatibilityProviderHasNoIntent(t, p, before, CompatibilityCompletion{Quiescent: true}, err)
}

func TestCompatibilitySupervisedDiagnosticUTF8Tail(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", nil, ""},
		{"short-text", []byte("first\nlast\n"), "first\nlast\n"},
		{"invalid-byte-run", []byte{'a', 0xff, 0xfe, 'b'}, "a?b"},
		{"exact-ascii-bound", []byte(strings.Repeat("x", 8192)), strings.Repeat("x", 8192)},
		{"ascii-tail", []byte("discarded-prefix" + strings.Repeat("x", 8192)), strings.Repeat("x", 8192)},
		{"exact-unicode-tail", []byte("discarded-prefix" + strings.Repeat("Ж", 4096)), strings.Repeat("Ж", 4096)},
		{"split-three-byte-rune", []byte("discarded-prefix€" + strings.Repeat("x", 8191)), strings.Repeat("x", 8191)},
		{"split-four-byte-rune", []byte("discarded-prefix🙂" + strings.Repeat("x", 8190)), strings.Repeat("x", 8190)},
		{"invalid-output-run", bytes.Repeat([]byte{0xff}, 8194), "?"},
		{"sanitized-tail", append([]byte(strings.Repeat("x", 8200)), 0xff, 'Z'), strings.Repeat("x", 8190) + "?Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.input)
			got := compatibilityDiagnostic(tc.input)
			if got != tc.want || len(got) > 8192 || !utf8.ValidString(got) {
				t.Fatalf("wrong bounded UTF-8 tail: bytes=%d valid=%t want-bytes=%d", len(got), utf8.ValidString(got), len(tc.want))
			}
			if !bytes.Equal(tc.input, before) {
				t.Fatal("diagnostic formatting changed caller output bytes")
			}
		})
	}
}
func TestCompatibilityJSONUnicodeFieldAliases(t *testing.T) {
	for _, data := range []string{
		`{"state":1,"STATE":2}`,
		`{"state":1,"\u017ftate":2}`,
		`{"acknowledged":true,"ac\u212anowledged":false}`,
		`{"outer":[{"parent_start":"1","parent_\u017ftart":"2"}]}`,
	} {
		if compatibilityJSONUnique([]byte(data)) == nil {
			t.Fatalf("ambiguous typed JSON keys accepted: %s", data)
		}
	}
	if err := compatibilityJSONUnique([]byte(`{"state":"intent","parent_start":"1"}`)); err != nil {
		t.Fatalf("distinct keys rejected: %v", err)
	}
}
