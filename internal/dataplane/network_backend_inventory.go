package dataplane

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

var errBackendInventory = errors.New("network backend inventory unknown or incomplete")

const (
	backendInventoryTimeout = 2 * time.Second
	backendClassicBytes     = 1 << 20
	backendClassicRows      = 8192
	backendClassicTokens    = 65536
)

// These private values describe an observation at one held owner boundary.
// They are not a capability, an ownership receipt, or a persisted grant.
type backendInventoryScope struct {
	BootID, NetNamespace, ToolReviewID string
}

type backendInventoryCoverage struct {
	LegacyFixedFiveBothFamilies bool
	NativeNFTAllFamilies        bool
	// Fixed table reads do not prove arbitrary registered classic table coverage.
	// This slice deliberately never sets this field to true.
	RegisteredTablesComplete bool
}

type backendNFTState uint8

const (
	backendNFTUnknown backendNFTState = iota
	backendNFTEmpty
	backendNFTPresent
)

type backendInventoryRow struct {
	Family int
	Table  string
	Tokens []string
}

type backendNFTTable struct {
	Family     uint8
	Name       string
	Flags, Use uint32
}

type backendInventorySnapshot struct {
	Scope               backendInventoryScope
	IPTables, IP6Tables string
	Coverage            backendInventoryCoverage
	NFTState            backendNFTState
	NFTGeneration       uint32
	NFTTables           []backendNFTTable
	Rows                []backendInventoryRow
}

// Full LAN NamespaceCheck must use this coverage gate in addition to its
// own pure exact predicates. A complete-empty NFT dump alone cannot pass it.
func (s backendInventorySnapshot) requireLANBackendCoverage() error {
	if !s.Coverage.LegacyFixedFiveBothFamilies || !s.Coverage.NativeNFTAllFamilies || !s.Coverage.RegisteredTablesComplete || s.NFTState != backendNFTEmpty {
		return errBackendInventory
	}
	return nil
}

type backendNFTSession interface {
	Generation(context.Context) (uint32, error)
	Tables(context.Context, uint32) ([]backendNFTTable, error)
	Close() error
}

type backendInventoryPlatform struct {
	endpoint func(context.Context) (backendInventoryScope, error)
	openNFT  func(context.Context) (backendNFTSession, error)
}

// Runner must be the existing admitted read-only runner. CheckTools is
// mandatory: it must recheck the held protected tool review, exact paths,
// loader/extensions/environment and legacy backend identity for both aliases.
// Neither a version suffix nor ToolReviewID alone establishes that proof.
// The collector never invokes authority/registrar/consumer Verify callbacks.
type backendInventoryReader struct {
	Runner              NFQWS2Runner
	IPTables, IP6Tables string
	CheckTools          func(context.Context, backendInventoryScope) error
}

// The plain []byte-returning Run contract cannot cap output before allocation.
// A held admitted runner must also implement this private bounded read seam.
type backendInventoryBoundedRunner interface {
	RunBounded(context.Context, string, int, ...string) ([]byte, error)
}

func (r *backendInventoryReader) Read(ctx context.Context, scope backendInventoryScope) (backendInventorySnapshot, error) {
	// Keep socket creation, reads and both endpoint samples in the same
	// inherited thread namespace. This function never changes namespaces.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return r.read(ctx, scope, backendInventorySystemPlatform())
}

func (r *backendInventoryReader) read(ctx context.Context, scope backendInventoryScope, platform backendInventoryPlatform) (backendInventorySnapshot, error) {
	var unknown backendInventorySnapshot
	if ctx == nil || r == nil || r.Runner == nil || r.CheckTools == nil || r.IPTables == "" || r.IP6Tables == "" || !nfqws2ManagedBoot(scope.BootID) || !nfqwsScopedNamespace(scope.NetNamespace) || !lanPolicyHash(scope.ToolReviewID) || platform.endpoint == nil || platform.openNFT == nil {
		return unknown, errBackendInventory
	}
	// The private owner creates/fixes this descriptor before the held read.
	frozen := *r
	r = &frozen
	runner, ok := r.Runner.(backendInventoryBoundedRunner)
	if !ok {
		return unknown, errBackendInventory
	}
	ctx, cancel := context.WithTimeout(ctx, backendInventoryTimeout)
	defer cancel()
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.CheckTools(ctx, scope); err != nil {
			return err
		}
		got, err := platform.endpoint(ctx)
		if err != nil || got.BootID != scope.BootID || got.NetNamespace != scope.NetNamespace {
			return errors.Join(errBackendInventory, err)
		}
		return ctx.Err()
	}
	fail := func(err error) (backendInventorySnapshot, error) {
		return unknown, errors.Join(errBackendInventory, err, ctx.Err())
	}
	if err := check(); err != nil {
		return fail(err)
	}
	nft, err := platform.openNFT(ctx)
	if err != nil {
		if nft != nil {
			_ = nft.Close()
		}
		return fail(err)
	}
	if nft == nil {
		return fail(errBackendInventory)
	}
	// Close exactly once on every return. Close errors must not leave a
	// successful snapshot; explicit close occurs before final endpoint checks.
	closed := false
	defer func() {
		if !closed {
			_ = nft.Close()
		}
	}()
	first, err := nft.Generation(ctx)
	if err != nil {
		return fail(err)
	}
	tables, err := nft.Tables(ctx, first)
	if err != nil {
		return fail(err)
	}
	result := backendInventorySnapshot{Scope: scope, IPTables: r.IPTables, IP6Tables: r.IP6Tables, NFTGeneration: first, NFTState: backendNFTEmpty, NFTTables: append([]backendNFTTable(nil), tables...)}
	if len(tables) != 0 {
		result.NFTState = backendNFTPresent
	}
	budget := backendClassicBudget{}
	for _, tool := range []struct {
		family int
		path   string
	}{{4, r.IPTables}, {6, r.IP6Tables}} {
		for _, table := range []string{"raw", "mangle", "nat", "filter", "security"} {
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			data, err := runner.RunBounded(ctx, tool.path, backendClassicBytes-budget.bytes, "-t", table, "-S")
			if err != nil || ctx.Err() != nil {
				return fail(errors.Join(err, ctx.Err()))
			}
			rows, err := backendXTablesRows(data, &budget)
			if err != nil {
				return fail(err)
			}
			for _, tokens := range rows {
				result.Rows = append(result.Rows, backendInventoryRow{Family: tool.family, Table: table, Tokens: tokens})
			}
		}
	}
	last, err := nft.Generation(ctx)
	if err != nil || first != last {
		return fail(errors.Join(errBackendInventory, err))
	}
	closed = true
	if err := nft.Close(); err != nil {
		return fail(err)
	}
	if err := check(); err != nil {
		return fail(err)
	}
	result.Coverage.LegacyFixedFiveBothFamilies = true
	result.Coverage.NativeNFTAllFamilies = true
	return result, nil
}

type backendClassicBudget struct{ bytes, rows, tokens int }

// Aggregate caps are checked before splitting/collecting. Successful command
// output must be nonempty and newline-terminated; a truncated final row is
// unknown even if it would otherwise look like a valid rule.
func backendXTablesRows(data []byte, budget *backendClassicBudget) ([][]string, error) {
	if budget == nil || len(data) == 0 || len(data) > backendClassicBytes-budget.bytes || data[len(data)-1] != '\n' || !utf8.Valid(data) {
		return nil, errBackendInventory
	}
	budget.bytes += len(data)
	if strings.Count(string(data), "\n") > backendClassicRows-budget.rows {
		return nil, errBackendInventory
	}
	budget.rows += strings.Count(string(data), "\n")
	var rows [][]string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields, err := backendXTablesRowTokens(line)
		if err != nil || len(fields) > backendClassicTokens-budget.tokens {
			return nil, errBackendInventory
		}
		budget.tokens += len(fields)
		rows = append(rows, fields)
	}
	if len(rows) == 0 {
		return nil, errBackendInventory
	}
	return rows, nil
}

func backendXTablesRowTokens(line string) ([]string, error) {
	fields, err := backendXTablesTokens(line)
	if err != nil || len(fields) < 2 || fields[1] == "" || len(fields[1]) > 128 || strings.IndexFunc(fields[1], func(c rune) bool { return c <= 32 || c == 127 }) >= 0 {
		return nil, errBackendInventory
	}
	switch fields[0] {
	case "-N":
		if len(fields) != 2 {
			return nil, errBackendInventory
		}
	case "-P":
		if len(fields) != 3 || fields[2] == "" {
			return nil, errBackendInventory
		}
	case "-A":
		if len(fields) < 4 {
			return nil, errBackendInventory
		}
	default:
		return nil, errBackendInventory
	}
	return fields, nil
}

// Single shared lexical primitive for iptables -S. No shell expansion and no
// semantic normalization: a quoted comment remains one inert argument.
func backendXTablesTokens(line string) ([]string, error) {
	if len(line) > 16384 || !utf8.ValidString(line) {
		return nil, errBackendInventory
	}
	var out []string
	var token strings.Builder
	quote, escape, started := rune(0), false, false
	push := func() error {
		if len(out) >= 128 {
			return errBackendInventory
		}
		out = append(out, token.String())
		token.Reset()
		started = false
		return nil
	}
	for _, c := range line {
		if c < 32 && c != '\t' || c == 127 {
			return nil, errBackendInventory
		}
		if escape {
			token.WriteRune(c)
			escape = false
			continue
		}
		if c == '\\' && quote != '\'' {
			escape, started = true, true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				token.WriteRune(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote, started = c, true
			continue
		}
		if c == ' ' || c == '\t' {
			if started {
				if err := push(); err != nil {
					return nil, err
				}
			}
			continue
		}
		started = true
		token.WriteRune(c)
	}
	if escape || quote != 0 {
		return nil, errBackendInventory
	}
	if started {
		if err := push(); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errBackendInventory
	}
	return out, nil
}

// Even a sealed valid GET failure is only diagnostic, never unsupported proof.
type backendNFTKernelError struct{ Code int32 }

func (e *backendNFTKernelError) Error() string {
	return fmt.Sprintf("nft read-only GET refused: errno %d", e.Code)
}
func (e *backendNFTKernelError) Unwrap() error { return errBackendInventory }
