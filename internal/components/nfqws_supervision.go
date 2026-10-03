package components

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	ErrNFQWSSupervisionUnavailable = errors.New("NFQWS process supervision is unavailable")
	ErrNFQWSSupervisionUnknown     = errors.New("NFQWS process outcome is unknown; command must not be replayed")
)

// NFQWSSupervisionIdentity binds a dedicated helper to its kernel process birth.
// PID absence, process-group absence, and this identity alone are not receipts.
type NFQWSSupervisionIdentity struct {
	BootID, Start string
	PID, Group    int
}

// NFQWSSupervisionCommand is a trusted, already reviewed command. It must come
// from the durable StrategyLab record, never from supervisor CLI arguments.
// The caller binds Program and Args to approved immutable file digests.
type NFQWSSupervisionCommand struct {
	Program, BootID, ParentStart, CommandSHA256 string
	Args                                        []string
	ParentPID                                   int
	Deadline                                    time.Time
}

// NFQWSSupervisionReceipt is kernel evidence. The caller must durably publish
// it before acknowledging the invocation; helper exit status is not evidence.
type NFQWSSupervisionReceipt struct {
	State, BootID, Start, CommandSHA256          string
	PID, Group, ChildPID, Reaped, ExitCode       int
	Started, DirectReaped, WaitECHILD, Cancelled bool
}

// NFQWSSupervisionHooks bind the bridge to the existing StrategyLab lease and
// common Stop authority. All hooks are required. StartAdmission must invoke
// begin exactly once under that authority's admission lock. Only Cmd.Start is
// performed by begin; journal writes and waiting occur outside the lock.
type NFQWSSupervisionHooks struct {
	Armed          func(NFQWSSupervisionIdentity) error
	Started        func(int) error
	Result         func(NFQWSSupervisionReceipt, []byte) error
	StartAdmission func(begin func() error) error
	StopCheck      func() error
}

func validateNFQWSSupervision(ctx context.Context, command NFQWSSupervisionCommand, hooks NFQWSSupervisionHooks) error {
	if ctx == nil || hooks.Armed == nil || hooks.Started == nil || hooks.Result == nil || hooks.StartAdmission == nil || hooks.StopCheck == nil {
		return ErrNFQWSSupervisionUnknown
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	start, err := strconv.ParseUint(command.ParentStart, 10, 64)
	if err != nil || start == 0 || strconv.FormatUint(start, 10) != command.ParentStart || command.ParentPID <= 1 || !validBootID(command.BootID) || command.Deadline.IsZero() || !time.Now().Before(command.Deadline) {
		return ErrNFQWSSupervisionUnknown
	}
	if !filepath.IsAbs(command.Program) || filepath.Clean(command.Program) != command.Program || len(command.Program) > 4096 || strings.ContainsRune(command.Program, 0) || len(command.Args) > 128 {
		return ErrNFQWSSupervisionUnknown
	}
	decoded, err := hex.DecodeString(command.CommandSHA256)
	if err != nil || len(decoded) != 32 || strings.ToLower(command.CommandSHA256) != command.CommandSHA256 {
		return ErrNFQWSSupervisionUnknown
	}
	total := 0
	for _, arg := range command.Args {
		total += len(arg)
		if len(arg) > 8192 || total > 32768 || strings.ContainsRune(arg, 0) {
			return ErrNFQWSSupervisionUnknown
		}
	}
	return nil
}
