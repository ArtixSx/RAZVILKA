package strategylab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	compatibilityRecordSchema   = 1
	compatibilityMaxFiles       = 16
	compatibilityMaxPathBytes   = 4096
	compatibilityMaxOutputBytes = 8192
	compatibilityMaxArgBytes    = 8192
	compatibilityMaxArgs        = compatibilityMaxFiles + 96 + 2
)

// These records bind an owner-reviewed command and its helper receipt. Parsing
// them grants neither provenance nor native compatibility; the launch owner
// must separately establish authority and acknowledge the exact durable result.
type compatibilityFileBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type compatibilityReview struct {
	Binary         compatibilityFileBinding   `json:"binary"`
	Assets         []compatibilityFileBinding `json:"assets"`
	BaseArguments  []string                   `json:"base_arguments"`
	ControlPath    string                     `json:"control_path"`
	InstallationID string                     `json:"installation_id"`
	Sequence       uint64                     `json:"sequence"`
}

type compatibilityCommand struct {
	ID          string              `json:"id"`
	SessionID   string              `json:"session_id"`
	Phase       string              `json:"phase"`
	BootID      string              `json:"boot_id"`
	ParentStart string              `json:"parent_start"`
	ParentPID   int                 `json:"parent_pid"`
	Deadline    time.Time           `json:"deadline"`
	Args        []string            `json:"args"`
	Review      compatibilityReview `json:"review"`
}

type compatibilityReceipt struct {
	State         string `json:"state"`
	BootID        string `json:"boot_id,omitempty"`
	Start         string `json:"start,omitempty"`
	CommandSHA256 string `json:"command_sha256,omitempty"`
	PID           int    `json:"pid,omitempty"`
	Group         int    `json:"group,omitempty"`
	ChildPID      int    `json:"child_pid,omitempty"`
	Reaped        int    `json:"reaped,omitempty"`
	ExitCode      int    `json:"exit_code,omitempty"`
	WaitECHILD    bool   `json:"wait_echild,omitempty"`
	DirectReaped  bool   `json:"direct_reaped,omitempty"`
	Started       bool   `json:"started,omitempty"`
	Cancelled     bool   `json:"cancelled,omitempty"`
}

type compatibilityInvocation struct {
	Command       compatibilityCommand `json:"command"`
	CommandSHA256 string               `json:"command_sha256"`
	Receipt       compatibilityReceipt `json:"receipt"`
	Output        string               `json:"output,omitempty"`
	Acknowledged  bool                 `json:"acknowledged,omitempty"`
}

type compatibilitySession struct {
	Schema  int                      `json:"schema"`
	ID      string                   `json:"id"`
	Active  string                   `json:"active"` // dry-run or lua-init
	DryRun  *compatibilityInvocation `json:"dry_run,omitempty"`
	LuaInit *compatibilityInvocation `json:"lua_init,omitempty"`
	Unknown bool                     `json:"unknown,omitempty"`
}

// Struct field order, exact argv and review order define the canonical digest.
// An invalid time cannot be encoded and therefore has no command digest.
func compatibilityCommandDigest(command compatibilityCommand) string {
	data, err := json.Marshal(command)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validateCompatibilitySession(session compatibilitySession) error {
	if session.Schema != compatibilityRecordSchema || !compatibilityHex(session.ID, 32) {
		return errors.New("invalid compatibility session schema or identity")
	}
	if session.DryRun == nil {
		return errors.New("compatibility session requires its dry-run invocation")
	}
	if err := validateCompatibilityInvocation(*session.DryRun, session.ID, "dry-run"); err != nil {
		return fmt.Errorf("compatibility dry-run: %w", err)
	}
	switch session.Active {
	case "dry-run":
		if session.LuaInit != nil {
			return errors.New("compatibility session cannot return to dry-run after Lua-init")
		}
	case "lua-init":
		if session.LuaInit == nil || !compatibilityInvocationSucceeded(*session.DryRun) {
			return errors.New("compatibility Lua-init requires an acknowledged successful dry-run")
		}
		if err := validateCompatibilityInvocation(*session.LuaInit, session.ID, "lua-init"); err != nil {
			return fmt.Errorf("compatibility Lua-init: %w", err)
		}
		dry, lua := session.DryRun.Command, session.LuaInit.Command
		if dry.ID == lua.ID || !compatibilityReviewsEqual(dry.Review, lua.Review) {
			return errors.New("compatibility phases change their invocation or review binding")
		}
		// Both command shapes have already passed the closed grammar. Strip
		// only its dry-run prefix and final generated Lua assertions.
		if !slices.Equal(dry.Args[1:], lua.Args[:len(lua.Args)-1]) {
			return errors.New("compatibility phases change their exact candidate arguments")
		}
	default:
		return errors.New("invalid compatibility active phase")
	}
	return nil
}

// Unacknowledged durable completion stays unknown until its owner reads back
// the exact receipt. An acknowledged rejection is quiescent, not a dry-run PASS.
func compatibilitySessionUnknown(session compatibilitySession) bool {
	if validateCompatibilitySession(session) != nil || session.Unknown {
		return true
	}
	for _, invocation := range []*compatibilityInvocation{session.DryRun, session.LuaInit} {
		if invocation != nil && (!invocation.Acknowledged || !compatibilityReceiptTerminal(invocation.Receipt)) {
			return true
		}
	}
	return false
}

func validateCompatibilityInvocation(invocation compatibilityInvocation, sessionID, phase string) error {
	command := invocation.Command
	if !compatibilityHex(command.ID, 32) || command.SessionID != sessionID || command.Phase != phase {
		return errors.New("invalid command identity, session or phase")
	}
	if !compatibilityBootID(command.BootID) || command.ParentPID <= 1 || !compatibilityPositiveDecimal(command.ParentStart) {
		return errors.New("invalid command boot or parent identity")
	}
	if command.Deadline.IsZero() || command.Deadline.Location() != time.UTC || command.Deadline.Year() < 1 || command.Deadline.Year() > 9999 {
		return errors.New("command deadline must be a nonzero UTC time")
	}
	if err := validateCompatibilityReview(command.Review); err != nil {
		return err
	}
	if len(command.Args) == 0 || len(command.Args) > compatibilityMaxArgs {
		return errors.New("compatibility command exceeds its argument count bound")
	}
	for _, arg := range command.Args {
		if len(arg) == 0 || len(arg) > compatibilityMaxArgBytes || !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return errors.New("compatibility command has an invalid or oversized argument")
		}
	}
	actualPhase, err := compatibilityCommandPhase(command.Review.BaseArguments, command.Args)
	if err != nil || actualPhase != phase {
		return errors.New("compatibility command does not match its closed phase grammar")
	}
	if !compatibilityHex(invocation.CommandSHA256, 64) || compatibilityCommandDigest(command) != invocation.CommandSHA256 {
		return errors.New("compatibility command digest does not match its exact contents")
	}
	if len(invocation.Output) > compatibilityMaxOutputBytes || !utf8.ValidString(invocation.Output) {
		return errors.New("compatibility diagnostic output exceeds its byte bound or is invalid UTF-8")
	}
	r := invocation.Receipt
	if r.State == "intent" {
		if (r.BootID != "" && r.BootID != command.BootID) || (r.CommandSHA256 != "" && r.CommandSHA256 != invocation.CommandSHA256) || r.Start != "" || r.PID != 0 || r.Group != 0 || r.ChildPID != 0 || r.Reaped != 0 || r.ExitCode != 0 || r.WaitECHILD || r.DirectReaped || r.Started || r.Cancelled || invocation.Acknowledged || invocation.Output != "" {
			return errors.New("compatibility intent contains a receipt mismatch or helper execution proof")
		}
		return nil
	}
	if r.BootID != command.BootID || r.CommandSHA256 != invocation.CommandSHA256 || r.PID <= 1 || r.Group != r.PID || !compatibilityPositiveDecimal(r.Start) {
		return errors.New("compatibility helper receipt does not match its command or helper identity")
	}
	if r.Reaped < 0 || (r.Cancelled && r.ExitCode == 0) {
		return errors.New("invalid compatibility reaping or cancellation status")
	}
	switch r.State {
	case "armed":
		if r.Started || r.ChildPID != 0 || r.Reaped != 0 || r.DirectReaped || r.WaitECHILD || r.ExitCode != 0 || r.Cancelled {
			return errors.New("compatibility armed receipt already contains child execution proof")
		}
	case "running":
		if !r.Started || r.ChildPID <= 1 || r.WaitECHILD || (r.DirectReaped && r.Reaped < 1) || (!r.DirectReaped && r.ExitCode != 0 && !r.Cancelled) {
			return errors.New("invalid compatibility running receipt")
		}
	case "reaped":
		if !r.Started || r.ChildPID <= 1 || !r.DirectReaped || r.Reaped < 1 || !r.WaitECHILD {
			return errors.New("compatibility terminal receipt lacks direct status or ECHILD")
		}
	case "not-started":
		if r.Started || r.ChildPID != 0 || r.Reaped != 0 || r.DirectReaped || !r.WaitECHILD {
			return errors.New("invalid compatibility not-started receipt")
		}
	default:
		return errors.New("invalid compatibility receipt state")
	}
	if !compatibilityReceiptTerminal(r) && (invocation.Acknowledged || invocation.Output != "") {
		return errors.New("compatibility pending receipt cannot be acknowledged or contain terminal output")
	}
	return nil
}

func validateCompatibilityReview(review compatibilityReview) error {
	if !compatibilityHex(review.InstallationID, 32) || review.Sequence == 0 || !compatibilityCleanPath(review.ControlPath) {
		return errors.New("invalid compatibility installation or control binding")
	}
	if !compatibilityFileValid(review.Binary, 64<<20) || len(review.Assets) > compatibilityMaxFiles || len(review.BaseArguments) == 0 || len(review.BaseArguments) > compatibilityMaxFiles {
		return errors.New("invalid or oversized compatibility binary, assets or base")
	}
	seen := map[string]bool{}
	paths := make([]string, 0, len(review.BaseArguments))
	for _, arg := range review.BaseArguments {
		var path string
		if strings.HasPrefix(arg, "--lua-init=@") {
			path = strings.TrimPrefix(arg, "--lua-init=@")
		} else if strings.HasPrefix(arg, "--blob=") {
			_, path, _ = strings.Cut(arg, ":@")
		} else {
			return errors.New("compatibility base contains an unsupported reviewed file option")
		}
		if !compatibilityCleanPath(path) {
			return errors.New("compatibility base requires clean absolute reviewed paths")
		}
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	if len(paths) != len(review.Assets) {
		return errors.New("compatibility assets do not exactly match reviewed base paths")
	}
	for i, asset := range review.Assets {
		if !compatibilityFileValid(asset, 4<<20) || asset.Path != paths[i] {
			return errors.New("compatibility asset identity or first-occurrence order mismatch")
		}
	}
	return nil
}

func compatibilityReviewsEqual(a, b compatibilityReview) bool {
	return a.Binary == b.Binary && slices.Equal(a.Assets, b.Assets) && slices.Equal(a.BaseArguments, b.BaseArguments) && a.ControlPath == b.ControlPath && a.InstallationID == b.InstallationID && a.Sequence == b.Sequence
}

func compatibilityReceiptTerminal(receipt compatibilityReceipt) bool {
	return receipt.State == "reaped" || receipt.State == "not-started"
}

func compatibilityInvocationSucceeded(invocation compatibilityInvocation) bool {
	r := invocation.Receipt
	return invocation.Acknowledged && r.State == "reaped" && r.Started && r.DirectReaped && r.ChildPID > 1 && r.Reaped >= 1 && r.WaitECHILD && r.ExitCode == 0 && !r.Cancelled
}

func compatibilityFileValid(binding compatibilityFileBinding, limit int64) bool {
	return compatibilityCleanPath(binding.Path) && compatibilityHex(binding.SHA256, 64) && binding.Size > 0 && binding.Size <= limit
}

func compatibilityCleanPath(path string) bool {
	return len(path) > 0 && len(path) <= compatibilityMaxPathBytes && utf8.ValidString(path) && !strings.ContainsAny(path, "\x00\r\n") && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func compatibilityHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, digit := range value {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

func compatibilityBootID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	return compatibilityHex(strings.ReplaceAll(value, "-", ""), 32)
}

func compatibilityPositiveDecimal(value string) bool {
	if len(value) == 0 || len(value) > 20 || value[0] < '1' || value[0] > '9' {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0
}
