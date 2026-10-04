package updatecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var ErrNodeHistoryAdmission = errors.New("retained node history or controller read capability requires review")

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
	return &NodeHistoryAdmission{configRoot: "/opt/etc/razvilka", stateRoot: "/opt/var/lib/razvilka", installation: "/opt", executable: "/opt/bin/razvilka", read: read, currentReadVersion: currentReadVersion, identity: checkNodeHistoryControllerIdentity, probe: probeNodeHistoryBinary}
}

// CheckReadable is the target binary's downgrade CLI consumer. Its compiled
// typed reader capability must cover all retained private images, not merely
// return a version flag. CORE prints {"ok":true} only after this succeeds.
func (a *NodeHistoryAdmission) CheckReadable(ctx context.Context) error {
	if a == nil || a.read == nil || a.currentReadVersion < 1 || a.currentReadVersion > 2 {
		return ErrNodeHistoryAdmission
	}
	required, err := RequiredRetainedNodeHistoryReadVersion(ctx, a.configRoot, a.stateRoot, a.read)
	if err != nil || required > a.currentReadVersion {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	return ctx.Err()
}

func (a *NodeHistoryAdmission) CheckWrite(ctx context.Context, wanted int) error {
	if a == nil || a.read == nil || a.identity == nil || a.probe == nil || wanted < 1 || wanted > 2 || a.currentReadVersion < wanted {
		return ErrNodeHistoryAdmission
	}
	if err := a.identity(a.executable); err != nil {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
	required, err := RequiredRetainedNodeHistoryReadVersion(ctx, a.configRoot, a.stateRoot, a.read)
	if err != nil {
		return errors.Join(ErrNodeHistoryAdmission, err)
	}
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
		if err != nil || version < required || version > 2 {
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
	return a.CheckReadable(ctx)
}

func (a *NodeHistoryAdmission) controllerImages(ctx context.Context) ([]selfupdatejournal.BinaryImage, error) {
	var images []selfupdatejournal.BinaryImage
	helperPresent := false
	helperID := ""
	filesPresent := false
	helper := filepath.Join(a.stateRoot, "self-update")
	if _, err := os.Lstat(helper); err == nil {
		root, err := ownedfs.Open(helper)
		if err != nil {
			return nil, err
		}
		data, readErr := root.ReadLimited("current.json", 64<<10)
		root.Close()
		if readErr != nil {
			return nil, ErrNodeHistoryAdmission
		}
		var record updateRecord
		if decodeFileProtocol(data, &record) != nil || record.Owner != updaterOwner || !jobIDPattern.MatchString(record.Job.ID) || !terminalHelperState(record.Job.State) {
			return nil, ErrNodeHistoryAdmission
		}
		helperPresent = true
		helperID = record.Job.ID
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	files := filepath.Join(a.stateRoot, "self-update-files")
	if _, err := os.Lstat(files); err == nil {
		store, err := selfupdatejournal.Open(a.installation, files)
		if err != nil {
			return nil, err
		}
		retained, err := store.RetainedBinaryImages(ctx)
		current, present, currentErr := store.Current()
		filesPresent = present
		store.Close()
		if err != nil || currentErr != nil {
			return nil, errors.Join(err, currentErr)
		}
		if helperPresent && (!present || helperID != current.ID) {
			return nil, ErrNodeHistoryAdmission
		}
		images = append(images, retained...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if helperPresent && !filesPresent {
		return nil, ErrNodeHistoryAdmission
	}
	legacy := filepath.Join(a.stateRoot, "update-backups")
	if _, err := os.Lstat(legacy); err == nil {
		root, err := ownedfs.Open(legacy)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		parent, err := os.OpenRoot(legacy)
		if err != nil {
			return nil, err
		}
		defer parent.Close()
		directory, err := parent.Open(".")
		if err != nil {
			return nil, err
		}
		defer directory.Close()
		entries, err := directory.ReadDir(258)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(entries) > 257 {
			return nil, ErrNodeHistoryAdmission
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil, ErrNodeHistoryAdmission
			}
			name := filepath.Join(entry.Name(), "razvilka.bin")
			if _, err := root.Stat(name); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return nil, err
			}
			sha, err := root.ReadLimited(filepath.Join(entry.Name(), "razvilka.sha256"), 64)
			// Historical manifests have no binary digest. They are preserved,
			// and cannot silently supply capability for a new Xray write.
			if err != nil || !validDigest("sha256:"+string(sha)) {
				return nil, ErrNodeHistoryAdmission
			}
			images = append(images, selfupdatejournal.BinaryImage{Path: filepath.Join(legacy, name), SHA256: string(sha)})
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Path < images[j].Path })
	return images, ctx.Err()
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
	// Execute only a bounded copy of the independently sealed image. Never
	// chmod an immutable old/new image or execute an unsealed backup in place.
	root, err := ownedfs.Open(filepath.Dir(image.Path))
	if err != nil {
		return 0, err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(image.Path), MaximumBinaryBytes)
	if err != nil || digestBytes(data) != image.SHA256 {
		return 0, ErrNodeHistoryAdmission
	}
	temporary, err := os.MkdirTemp("", "razvilka-history-reader-")
	if err != nil {
		return 0, err
	}
	defer os.Remove(temporary)
	path := filepath.Join(temporary, "controller")
	defer os.Remove(path)
	if err := os.WriteFile(path, data, 0700); err != nil {
		return 0, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, path, "-node-history-read-version")
	command.Env = commandEnvironment()
	out := &cappedOutput{maximum: 16}
	command.Stdout = out
	command.Stderr = io.Discard
	if err := runBoundedCommand(command); err != nil {
		return 0, ErrNodeHistoryAdmission
	}
	value := strings.TrimSpace(out.String())
	version, err := strconv.Atoi(value)
	if err != nil || (value != "1" && value != "2") {
		return 0, ErrNodeHistoryAdmission
	}
	return version, ctx.Err()
}
