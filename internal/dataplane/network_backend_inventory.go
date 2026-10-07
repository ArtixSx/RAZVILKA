package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/netidentity"
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
	Network      netidentity.Identity
	ToolReviewID string
}

type backendInventoryCoverage struct {
	LegacyRegisteredBothFamilies bool
	NativeNFTAllFamilies         bool
	// All enumerated tables in both families were read twice with stable closure.
	RegisteredTablesComplete bool
}

type backendNFTState uint8

const (
	backendNFTUnknown backendNFTState = iota
	backendNFTEmpty
	backendNFTPresent
	backendNFTNoRegisteredSubsystemAtCapture
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
	Schema              int
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
	if s.Schema != 1 || s.Scope.Network.Validate() != nil || !lanPolicyHash(s.Scope.ToolReviewID) || !s.Coverage.LegacyRegisteredBothFamilies || !s.Coverage.NativeNFTAllFamilies || !s.Coverage.RegisteredTablesComplete || len(s.NFTTables) != 0 || (s.NFTState != backendNFTEmpty && s.NFTState != backendNFTNoRegisteredSubsystemAtCapture) {
		return errBackendInventory
	}
	if s.NFTState == backendNFTNoRegisteredSubsystemAtCapture && (s.NFTGeneration != 0 || s.Scope.Network.Kind != netidentity.ReviewedSingleInitNet || s.Scope.Network.PlatformReviewSHA256 != backendNFTStockScopeSHA256) {
		return errBackendInventory
	}
	return nil
}

type backendNFTSession interface {
	Registration(context.Context, backendNFTABI) (backendNFTRegistration, error)
	Generation(context.Context) (uint32, error)
	Tables(context.Context, uint32) ([]backendNFTTable, error)
	Close() error
}

type backendInventoryPlatform struct {
	withCurrent      func(context.Context, func(context.Context, netidentity.Identity) error) error
	registeredTables func(context.Context, int) ([]byte, error)
	openNFT          func(context.Context) (backendNFTSession, error)
}

// Runner must be the existing admitted read-only runner. CheckTools is
// mandatory: it must recheck the held protected tool review, exact paths,
// loader/extensions/environment and legacy backend identity for both aliases.
// Neither a version suffix nor ToolReviewID alone establishes that proof.
// The collector never invokes authority/registrar/consumer Verify callbacks.
type backendInventoryReader struct {
	Provider            *netidentity.Provider
	NFTABI              backendNFTABI
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
	if r == nil || r.Provider == nil {
		return backendInventorySnapshot{}, errBackendInventory
	}
	return r.read(ctx, scope, backendInventorySystemPlatform(r.Provider))
}

func (r *backendInventoryReader) read(ctx context.Context, scope backendInventoryScope, platform backendInventoryPlatform) (backendInventorySnapshot, error) {
	var unknown backendInventorySnapshot
	if ctx == nil || r == nil || r.Runner == nil || r.CheckTools == nil || r.IPTables == "" || r.IP6Tables == "" || scope.Network.Validate() != nil || !lanPolicyHash(scope.ToolReviewID) || platform.withCurrent == nil || platform.registeredTables == nil || platform.openNFT == nil || !r.NFTABI.inventoryABI() {
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
	var result backendInventorySnapshot
	uses := 0
	err := platform.withCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		uses++
		if uses != 1 {
			return errBackendInventory
		}
		if current != scope.Network || current.Validate() != nil || held == nil || held.Err() != nil || (r.NFTABI == backendNFTABIStockNC1812 && (current.Kind != netidentity.ReviewedSingleInitNet || current.PlatformReviewSHA256 != backendNFTStockScopeSHA256)) {
			return errBackendInventory
		}
		var err error
		result, err = r.capture(held, scope, platform, runner)
		return err
	})
	if err != nil || ctx.Err() != nil || uses != 1 {
		failure := errors.Join(errBackendInventory, err, ctx.Err())
		var staged *backendInventoryFailure
		if !errors.As(failure, &staged) {
			failure = backendInventoryAt("SCOPE", failure)
		}
		return unknown, failure
	}
	return result, nil
}

func (r *backendInventoryReader) capture(ctx context.Context, scope backendInventoryScope, platform backendInventoryPlatform, runner backendInventoryBoundedRunner) (backendInventorySnapshot, error) {
	var unknown backendInventorySnapshot
	fail := func(err error) (backendInventorySnapshot, error) {
		return unknown, errors.Join(errBackendInventory, err, ctx.Err())
	}
	if err := r.CheckTools(ctx, scope); err != nil || ctx.Err() != nil {
		return fail(backendInventoryAt("TOOLS_A", errors.Join(err, ctx.Err())))
	}
	nft, err := platform.openNFT(ctx)
	if err != nil {
		if nft != nil {
			_ = nft.Close()
		}
		return fail(backendInventoryAt("OPEN_A", err))
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
	first, err := nft.Registration(ctx, r.NFTABI)
	if err != nil {
		return fail(backendInventoryAt("GETGEN_A", err))
	}
	if !first.valid(r.NFTABI) {
		return fail(errBackendInventory)
	}
	var tables []backendNFTTable
	if !first.noRegistered {
		tables, err = nft.Tables(ctx, first.generation)
		if err != nil {
			return fail(backendInventoryAt("GETTABLE", err))
		}
	} else {
		// Each sole-negative proof belongs to the first request of a fresh socket.
		closed = true
		if err := nft.Close(); err != nil {
			return fail(err)
		}
	}
	result := backendInventorySnapshot{Schema: 1, Scope: scope, IPTables: r.IPTables, IP6Tables: r.IP6Tables, NFTGeneration: first.generation, NFTState: backendNFTEmpty, NFTTables: append([]backendNFTTable(nil), tables...)}
	if first.noRegistered {
		result.NFTState = backendNFTNoRegisteredSubsystemAtCapture
	}
	if len(tables) != 0 {
		result.NFTState = backendNFTPresent
	}
	result.Rows, err = r.classic(ctx, platform, runner, func() error { return backendInventoryAt("TOOLS_B", errors.Join(r.CheckTools(ctx, scope), ctx.Err())) })
	if err != nil {
		var staged *backendInventoryFailure
		if !errors.As(err, &staged) {
			err = backendInventoryAt("CLASSIC", err)
		}
		return fail(err)
	}
	if first.noRegistered {
		nft, err = platform.openNFT(ctx)
		if err != nil || nft == nil {
			if nft != nil {
				_ = nft.Close()
			}
			return fail(backendInventoryAt("OPEN_B", errors.Join(errBackendInventory, err)))
		}
		closed = false
	}
	last, err := nft.Registration(ctx, r.NFTABI)
	if err != nil || first != last {
		return fail(backendInventoryAt("GETGEN_B", errors.Join(errBackendInventory, err)))
	}
	closed = true
	if err := nft.Close(); err != nil {
		return fail(backendInventoryAt("CLOSE", err))
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	result.Coverage.LegacyRegisteredBothFamilies = true
	result.Coverage.NativeNFTAllFamilies = true
	result.Coverage.RegisteredTablesComplete = true
	return result, nil
}

type backendInventoryFailure struct {
	stage string
	cause error
}

func (e *backendInventoryFailure) Error() string {
	return "network backend inventory refused at " + e.stage
}
func (e *backendInventoryFailure) Unwrap() error { return errors.Join(errBackendInventory, e.cause) }
func backendInventoryAt(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &backendInventoryFailure{stage: stage, cause: err}
}

const backendClassicNamesBytes = 4096
const backendClassicTables = 64

func backendClassicTableName(name string) bool {
	if len(name) == 0 || len(name) > 31 || name[0] == '-' {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func backendClassicNames(data []byte) ([]string, error) {
	if len(data) > backendClassicNamesBytes || len(data) != 0 && data[len(data)-1] != '\n' {
		return nil, errBackendInventory
	}
	var names []string
	if len(data) == 0 {
		return names, nil
	} // Only a successfully read EOF can prove an empty list.
	for _, name := range strings.Split(string(data[:len(data)-1]), "\n") {
		if !backendClassicTableName(name) || len(names) >= backendClassicTables || slices.Contains(names, name) {
			return nil, errBackendInventory
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

func (r *backendInventoryReader) classic(ctx context.Context, p backendInventoryPlatform, runner backendInventoryBoundedRunner, between func() error) ([]backendInventoryRow, error) {
	type image struct {
		names  [2][]string
		bodies [][]byte
		rows   []backendInventoryRow
	}
	budget := backendClassicBudget{}
	read := func() (image, error) {
		var result image
		for i, family := range []int{4, 6} {
			data, err := p.registeredTables(ctx, family)
			if err != nil || ctx.Err() != nil {
				return image{}, errors.Join(errBackendInventory, err, ctx.Err())
			}
			result.names[i], err = backendClassicNames(data)
			if err != nil {
				return image{}, err
			}
		}
		for i, path := range []string{r.IPTables, r.IP6Tables} {
			for _, table := range result.names[i] {
				if ctx.Err() != nil {
					return image{}, ctx.Err()
				}
				data, err := runner.RunBounded(ctx, path, backendClassicBytes-budget.bytes, "-t", table, "-S")
				if err != nil || ctx.Err() != nil {
					return image{}, errors.Join(errBackendInventory, err, ctx.Err())
				}
				rows, err := backendXTablesRows(data, &budget)
				if err != nil {
					return image{}, err
				}
				result.bodies = append(result.bodies, append([]byte(nil), data...))
				for _, tokens := range rows {
					result.rows = append(result.rows, backendInventoryRow{Family: []int{4, 6}[i], Table: table, Tokens: tokens})
				}
			}
		}
		for i, family := range []int{4, 6} {
			data, err := p.registeredTables(ctx, family)
			if err != nil || ctx.Err() != nil {
				return image{}, errors.Join(errBackendInventory, err, ctx.Err())
			}
			closing, err := backendClassicNames(data)
			if err != nil || !slices.Equal(closing, result.names[i]) {
				return image{}, errBackendInventory
			}
		}
		return result, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	// Closing tool callbacks precede the final complete classic image. They
	// cannot invalidate the image subsequently returned as the observation.
	if between == nil {
		return nil, errBackendInventory
	}
	if err := between(); err != nil || ctx.Err() != nil {
		return nil, errors.Join(errBackendInventory, err, ctx.Err())
	}
	last, err := read()
	if err != nil {
		return nil, err
	}
	if !slices.Equal(first.names[0], last.names[0]) || !slices.Equal(first.names[1], last.names[1]) || len(first.bodies) != len(last.bodies) {
		return nil, errBackendInventory
	}
	for i := range first.bodies {
		if !bytes.Equal(first.bodies[i], last.bodies[i]) {
			return nil, errBackendInventory
		}
	}
	return last.rows, nil
}

func backendInventoryProcMountID(data []byte) (string, error) {
	if len(data) == 0 || len(data) > 4096 || data[len(data)-1] != '\n' || !utf8.Valid(data) {
		return "", errBackendInventory
	}
	value := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.IndexFunc(line, func(c rune) bool { return c < 32 && c != '\t' || c == 127 }) >= 0 {
			return "", errBackendInventory
		}
		if strings.HasPrefix(line, "mnt_id:") {
			if value != "" || !strings.HasPrefix(line, "mnt_id:\t") {
				return "", errBackendInventory
			}
			value = strings.TrimPrefix(line, "mnt_id:\t")
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
				return "", errBackendInventory
			}
		}
	}
	if value == "" {
		return "", errBackendInventory
	}
	return value, nil
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
