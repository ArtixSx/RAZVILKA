package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var ErrExecutionHistoryAdmission = errors.New("retained dataplane execution reader requires review")

const ExecutionHistoryReadVersion = 6

type ExecutionHistoryReader func(context.Context, string) (int, string, error)

// Adapters without a trusted scanner may only handle installations with no
// execution directory. Existing bytes never imply a legacy format by default.
func (a *SelfUpdateFileAdapter) inspectExecutionHistory(ctx context.Context, root string) (int, string, error) {
	if ctx == nil || a == nil {
		return 0, "", ErrExecutionHistoryAdmission
	}
	if err := ctx.Err(); err != nil {
		return 0, "", err
	}
	if a.ExecutionHistoryReader != nil {
		return a.ExecutionHistoryReader(ctx, root)
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return 1, "absent", nil
	}
	return 0, "", ErrExecutionHistoryAdmission
}

type ExecutionHistoryAdmission struct {
	// Only the existing real controller inventory is shared. No package
	// reader number, package history scanner or package probe grants admission.
	inventory *ComponentHistoryAdmission
	root      string
	reader    int
	inspect   func(context.Context, string) (int, string, error)
	probe     func(context.Context, selfupdatejournal.BinaryImage) (int, error)
}

func NewExecutionHistoryAdmission(inspect ExecutionHistoryReader) *ExecutionHistoryAdmission {
	return &ExecutionHistoryAdmission{inventory: NewComponentHistoryAdmission(1), root: filepath.Join(installpath.State, "dataplane"), reader: ExecutionHistoryReadVersion, inspect: inspect, probe: probeExecutionHistoryBinary}
}

func parseExecutionReadVersion(value string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSuffix(value, "\n"))
	if err != nil || n < 1 || n > ExecutionHistoryReadVersion || value != strconv.Itoa(n)+"\n" {
		return 0, ErrExecutionHistoryAdmission
	}
	return n, nil
}

func probeExecutionHistoryBinary(ctx context.Context, image selfupdatejournal.BinaryImage) (int, error) {
	value, err := probeRetainedControllerFlag(ctx, image, "-dataplane-execution-read-version")
	if err != nil {
		return 0, errors.Join(ErrExecutionHistoryAdmission, err)
	}
	return parseExecutionReadVersion(value)
}

func (a *ExecutionHistoryAdmission) CheckReadable(ctx context.Context) error {
	if a == nil || ctx == nil || a.inspect == nil || a.reader != ExecutionHistoryReadVersion {
		return ErrExecutionHistoryAdmission
	}
	required, _, err := a.inspect(ctx, a.root)
	if err != nil || required < 1 || required > a.reader {
		return errors.Join(ErrExecutionHistoryAdmission, err)
	}
	return ctx.Err()
}

// CheckWrite runs under the caller's original exclusive operation, before any
// component, StrategyLab or execution-file leaf lock is taken.
func (a *ExecutionHistoryAdmission) CheckWrite(ctx context.Context, requested ...int) error {
	if a == nil || ctx == nil || a.inventory == nil || a.probe == nil || a.inspect == nil || a.reader != ExecutionHistoryReadVersion {
		return ErrExecutionHistoryAdmission
	}
	wanted := ExecutionHistoryReadVersion
	if len(requested) > 1 {
		return ErrExecutionHistoryAdmission
	}
	if len(requested) == 1 {
		wanted = requested[0]
	}
	if wanted < 1 || wanted > a.reader {
		return ErrExecutionHistoryAdmission
	}
	i := a.inventory
	if err := ctx.Err(); err != nil {
		return err
	}
	if i.identity == nil || i.owned == nil || i.layout == nil || i.identity(i.executable) != nil {
		return ErrExecutionHistoryAdmission
	}
	required, seal, err := a.inspect(ctx, a.root)
	if err != nil || required < 1 || required > a.reader {
		return errors.Join(ErrExecutionHistoryAdmission, err)
	}
	minimum := max(required, wanted)
	current, err := hashRegularFile(i.executable, MaximumBinaryBytes)
	if err != nil {
		return err
	}
	images, err := i.controllerImages(ctx, current)
	if err != nil {
		return err
	}
	for _, image := range images {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i.owned(image.Path) != nil {
			return ErrExecutionHistoryAdmission
		}
		before, err := hashRegularFile(image.Path, MaximumBinaryBytes)
		if err != nil || before != image.SHA256 {
			return ErrExecutionHistoryAdmission
		}
		version := a.reader
		if before != current {
			version, err = a.probe(ctx, image)
		}
		if err != nil || version < minimum || version > a.reader {
			return errors.Join(ErrExecutionHistoryAdmission, err)
		}
		after, err := hashRegularFile(image.Path, MaximumBinaryBytes)
		if err != nil || after != before || i.owned(image.Path) != nil {
			return ErrExecutionHistoryAdmission
		}
	}
	if i.identity(i.executable) != nil {
		return ErrExecutionHistoryAdmission
	}
	after, err := hashRegularFile(i.executable, MaximumBinaryBytes)
	if err != nil || after != current {
		return ErrExecutionHistoryAdmission
	}
	fresh, err := i.controllerImages(ctx, current)
	if err != nil || !reflect.DeepEqual(images, fresh) {
		return errors.Join(ErrExecutionHistoryAdmission, err)
	}
	need, closing, err := a.inspect(ctx, a.root)
	if err != nil || need != required || closing != seal {
		return errors.Join(ErrExecutionHistoryAdmission, err)
	}
	return ctx.Err()
}

// Uses the caller's existing exact metadata command producer; it cannot start
// a helper directly or turn another format's version into execution support.
func checkExecutionHistoryCapability(ctx context.Context, binary, root string, probe func(context.Context, string, string) (string, error), inspect ExecutionHistoryReader) error {
	if ctx == nil || probe == nil || inspect == nil {
		return ErrExecutionHistoryAdmission
	}
	required, seal, err := inspect(ctx, root)
	if err != nil || required < 1 || required > ExecutionHistoryReadVersion {
		return errors.Join(ErrExecutionHistoryAdmission, err)
	}
	if required > 1 {
		value, err := probe(ctx, binary, "-dataplane-execution-read-version")
		if err != nil {
			return errors.Join(ErrExecutionHistoryAdmission, err)
		}
		version, err := parseExecutionReadVersion(value)
		if err != nil || version < required {
			return ErrExecutionHistoryAdmission
		}
	}
	need, closing, err := inspect(ctx, root)
	if err != nil || need != required || closing != seal {
		return errors.Join(ErrExecutionHistoryAdmission, err)
	}
	return ctx.Err()
}
