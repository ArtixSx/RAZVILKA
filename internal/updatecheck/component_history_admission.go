package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var ErrComponentHistoryAdmission = errors.New("retained component formats or controller read capability require review")

func knownComponentReadVersion(version int) bool {
	return version >= 1 && version <= components.NFQWSInitialInstallSchema
}

func parseComponentReadVersion(output string) (int, error) {
	version, err := strconv.Atoi(strings.TrimSuffix(output, "\n"))
	if err != nil || !knownComponentReadVersion(version) || output != strconv.Itoa(version)+"\n" {
		return 0, ErrComponentHistoryAdmission
	}
	return version, nil
}

// ComponentHistoryAdmission observes a distinct typed format and the existing
// real current/candidate/rollback controller inventory. Paths and compiled
// currentReadVersion come from trusted startup, never a request. CheckWrite
// must run under CORE's original operation admission, outside any Store/control
// leaf lock; it takes no component writer lease or Manager mutex and grants no
// Stop, config revision, effect, inactivity or physical-generation authority.
type ComponentHistoryAdmission struct {
	stateRoot, installation, executable string
	currentReadVersion                  int
	inspect                             func(context.Context, string) (int, string, error)
	identity, owned                     func(string) error
	layout                              func(Deployment) error
	probe                               func(context.Context, selfupdatejournal.BinaryImage) (int, error)
}

func NewComponentHistoryAdmission(currentReadVersion int) *ComponentHistoryAdmission {
	return &ComponentHistoryAdmission{stateRoot: installpath.State, installation: "/opt", executable: "/opt/bin/razvilka", currentReadVersion: currentReadVersion, inspect: components.InspectRetainedManagedUpdateReadVersion, identity: checkNodeHistoryControllerIdentity, owned: checkRootOwnedPath, layout: checkDeploymentLayout, probe: probeComponentHistoryBinary}
}

func (a *ComponentHistoryAdmission) CheckReadable(ctx context.Context) error {
	if a == nil || ctx == nil || a.inspect == nil || !knownComponentReadVersion(a.currentReadVersion) {
		return ErrComponentHistoryAdmission
	}
	required, _, err := a.inspect(ctx, filepath.Join(a.stateRoot, "components"))
	if err != nil || !knownComponentReadVersion(required) || required > a.currentReadVersion {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	return ctx.Err()
}

func (a *ComponentHistoryAdmission) CheckWrite(ctx context.Context, wanted int) error {
	if a == nil || ctx == nil || a.inspect == nil || a.identity == nil || a.owned == nil || a.layout == nil || a.probe == nil || !knownComponentReadVersion(wanted) || !knownComponentReadVersion(a.currentReadVersion) || a.currentReadVersion < wanted {
		return ErrComponentHistoryAdmission
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	if err := a.identity(a.executable); err != nil {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	required, stateSeal, err := a.inspect(ctx, filepath.Join(a.stateRoot, "components"))
	if err != nil || !knownComponentReadVersion(required) {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	retainedRequired := required
	if required < wanted {
		required = wanted
	}
	if a.currentReadVersion < required {
		return ErrComponentHistoryAdmission
	}
	currentSHA, err := hashRegularFile(a.executable, MaximumBinaryBytes)
	if err != nil {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	images, err := a.controllerImages(ctx, currentSHA)
	if err != nil {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	for _, image := range images {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrComponentHistoryAdmission, err)
		}
		if a.owned(image.Path) != nil {
			return ErrComponentHistoryAdmission
		}
		before, err := hashRegularFile(image.Path, MaximumBinaryBytes)
		if err != nil || before != image.SHA256 {
			return ErrComponentHistoryAdmission
		}
		version := a.currentReadVersion
		if before != currentSHA {
			version, err = a.probe(ctx, image)
		}
		if err != nil || !knownComponentReadVersion(version) || version < required {
			return errors.Join(ErrComponentHistoryAdmission, err)
		}
		after, err := hashRegularFile(image.Path, MaximumBinaryBytes)
		if err != nil || after != before || a.owned(image.Path) != nil {
			return ErrComponentHistoryAdmission
		}
	}
	if err := a.identity(a.executable); err != nil {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	after, err := hashRegularFile(a.executable, MaximumBinaryBytes)
	if err != nil || after != currentSHA {
		return ErrComponentHistoryAdmission
	}
	fresh, err := a.controllerImages(ctx, currentSHA)
	if err != nil || !reflect.DeepEqual(images, fresh) {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	freshRequired, freshSeal, err := a.inspect(ctx, filepath.Join(a.stateRoot, "components"))
	if err != nil || freshRequired != retainedRequired || freshSeal != stateSeal {
		return errors.Join(ErrComponentHistoryAdmission, err)
	}
	return ctx.Err()
}

func (a *ComponentHistoryAdmission) controllerImages(ctx context.Context, currentSHA string) ([]selfupdatejournal.BinaryImage, error) {
	reader := NewSelfUpdateFileAdapter()
	reader.directory, reader.fileJournal, reader.installation = filepath.Join(a.stateRoot, "self-update"), filepath.Join(a.stateRoot, "self-update-files"), a.installation
	reader.owned, reader.layout = a.owned, a.layout
	images, err := retainedControllerImagesWithAdapter(ctx, a.installation, a.stateRoot, reader)
	if err != nil {
		return nil, err
	}
	images = append(images, selfupdatejournal.BinaryImage{Path: a.executable, SHA256: currentSHA})
	helper := filepath.Join(a.stateRoot, "self-update")
	if _, err := os.Lstat(helper); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return nil, err
		}
		root, err := ownedfs.Open(helper)
		if err != nil {
			return nil, err
		}
		data, readErr := root.ReadLimited("current.json", 64<<10)
		closeErr := root.Close()
		var record updateRecord
		if readErr != nil || closeErr != nil || decodeFileProtocol(data, &record) != nil || !terminalHelperState(record.Job.State) {
			return nil, ErrComponentHistoryAdmission
		}
		// Include sealed helper control.bin and every reviewed candidate,
		// including retained jobs, using the existing full concrete inventory.
		_, review, err := reader.loadBoundReview(ctx, record.Job.ID, true, false)
		if err != nil {
			return nil, err
		}
		retained, err := reader.journalReaderImagesWithCurrent(ctx, review, currentSHA)
		if err != nil {
			return nil, err
		}
		images = append(images, retained...)
	}
	if len(images) > 2048 {
		return nil, ErrComponentHistoryAdmission
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Path < images[j].Path })
	unique := images[:0]
	for _, image := range images {
		if len(unique) != 0 && unique[len(unique)-1].Path == image.Path {
			if unique[len(unique)-1].SHA256 != image.SHA256 {
				return nil, ErrComponentHistoryAdmission
			}
			continue
		}
		unique = append(unique, image)
	}
	return unique, ctx.Err()
}

func probeComponentHistoryBinary(ctx context.Context, image selfupdatejournal.BinaryImage) (int, error) {
	output, err := probeRetainedControllerFlag(ctx, image, "-component-update-schema")
	if err != nil {
		return 0, errors.Join(ErrComponentHistoryAdmission, err)
	}
	return parseComponentReadVersion(output)
}
