package updatecheck

import (
	"context"
	"errors"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var ErrNodeHistoryAdmission = errors.New("retained node history or controller read capability requires review")

func knownNodeHistoryReadVersion(version int) bool {
	// This range belongs to the typed NodeStore reader, never to the
	// independently evolving self-update journal or envelope schema.
	return version >= 1 && version <= nodestore.ExactHistoryReadVersion
}

func parseNodeHistoryReadVersion(output string) (int, error) {
	version, err := strconv.Atoi(strings.TrimSuffix(output, "\n"))
	if err != nil || !knownNodeHistoryReadVersion(version) || output != strconv.Itoa(version)+"\n" {
		return 0, ErrNodeHistoryAdmission
	}
	return version, nil
}

// Paths and callback bindings come from trusted startup. This guard must run
// under CORE's existing operation admission, before probes and again before
// RecordCheck. It takes no live Store/config lock and performs no migration.
type NodeHistoryAdmission struct {
	configRoot, stateRoot, installation, executable string
	read                                            NodeHistoryReader
	currentReadVersion                              int
	identity                                        func(string) error
	probe                                           func(context.Context, selfupdatejournal.BinaryImage) (int, error)
}

func NewNodeHistoryAdmission(read NodeHistoryReader, currentReadVersion int) *NodeHistoryAdmission {
	return &NodeHistoryAdmission{configRoot: installpath.Config, stateRoot: installpath.State, installation: "/opt", executable: "/opt/bin/razvilka", read: read, currentReadVersion: currentReadVersion, identity: checkNodeHistoryControllerIdentity, probe: probeNodeHistoryBinary}
}

// CheckReadable is the target binary's downgrade CLI consumer. Its compiled
// typed reader capability must cover all retained private images, not merely
// return a version flag. CORE prints {"ok":true} only after this succeeds.
func (a *NodeHistoryAdmission) CheckReadable(ctx context.Context) error {
	if a == nil || a.read == nil || !knownNodeHistoryReadVersion(a.currentReadVersion) {
		return ErrNodeHistoryAdmission
	}
	required, err := RequiredRetainedNodeHistoryReadVersion(ctx, a.configRoot, a.stateRoot, a.read)
	if err != nil || required > a.currentReadVersion {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	return ctx.Err()
}

func (a *NodeHistoryAdmission) CheckWrite(ctx context.Context, wanted int) error {
	if a == nil || a.read == nil || a.identity == nil || a.probe == nil || !knownNodeHistoryReadVersion(wanted) || !knownNodeHistoryReadVersion(a.currentReadVersion) || a.currentReadVersion < wanted {
		return ErrNodeHistoryAdmission
	}
	if err := a.identity(a.executable); err != nil {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	required, err := RequiredRetainedNodeHistoryReadVersion(ctx, a.configRoot, a.stateRoot, a.read)
	if err != nil {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	retainedRequired := required
	if required < wanted {
		required = wanted
	}
	if a.currentReadVersion < required {
		return ErrNodeHistoryAdmission
	}
	currentSHA, err := hashRegularFile(a.executable, MaximumBinaryBytes)
	if err != nil {
		return err
	}
	images, err := a.controllerImages(ctx)
	if err != nil {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	for _, image := range images {
		before, err := hashRegularFile(image.Path, MaximumBinaryBytes)
		if err != nil || before != image.SHA256 {
			return ErrNodeHistoryAdmission
		}
		version := a.currentReadVersion
		if before != currentSHA {
			version, err = a.probe(ctx, image)
		}
		if err != nil || !knownNodeHistoryReadVersion(version) || version < required {
			return errors.Join(ErrNodeHistoryAdmission, err)
		}
		after, err := hashRegularFile(image.Path, MaximumBinaryBytes)
		if err != nil || after != before {
			return ErrNodeHistoryAdmission
		}
	}
	// Revalidate after capability observations. The existing exclusive app
	// admission prevents a cooperative installer from changing this inventory.
	if err := a.identity(a.executable); err != nil {
		return err
	}
	after, err := hashRegularFile(a.executable, MaximumBinaryBytes)
	if err != nil || after != currentSHA {
		return ErrNodeHistoryAdmission
	}
	fresh, err := a.controllerImages(ctx)
	if err != nil || !reflect.DeepEqual(images, fresh) {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	freshRequired, err := RequiredRetainedNodeHistoryReadVersion(ctx, a.configRoot, a.stateRoot, a.read)
	if err != nil || freshRequired != retainedRequired || !knownNodeHistoryReadVersion(a.currentReadVersion) || freshRequired > a.currentReadVersion {
		// An XHTTP image appearing during observations cannot borrow reader2
		// proofs that were collected for the prior RAW-only inventory.
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	return ctx.Err()
}

func (a *NodeHistoryAdmission) controllerImages(ctx context.Context) ([]selfupdatejournal.BinaryImage, error) {
	images, err := retainedControllerImages(ctx, a.installation, a.stateRoot)
	if err != nil {
		return nil, errors.Join(ErrNodeHistoryAdmission, err)
	}
	return images, nil
}

func checkNodeHistoryControllerIdentity(path string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || path != "/opt/bin/razvilka" {
		return ErrNodeHistoryAdmission
	}
	if err := checkRootOwnedPath(path); err != nil {
		return err
	}
	actual, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	installed, err := os.Stat(path)
	if err != nil || !os.SameFile(actual, installed) {
		return ErrNodeHistoryAdmission
	}
	return nil
}

func probeNodeHistoryBinary(ctx context.Context, image selfupdatejournal.BinaryImage) (int, error) {
	output, err := probeRetainedControllerFlag(ctx, image, "-node-history-read-version")
	if err != nil {
		return 0, errors.Join(ErrNodeHistoryAdmission, err)
	}
	return parseNodeHistoryReadVersion(output)
}
