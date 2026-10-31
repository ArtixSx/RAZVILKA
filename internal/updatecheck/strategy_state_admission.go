package updatecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// StrategyLab contains compatibility ownership/finalizing fences and evidence
// generations. An upgrade/rollback over an existing state requires the sealed
// ordinary unchanged-state pair below. Legacy paths remain closed; parsing a
// schema alone never establishes rollback authority.
var ErrStrategyStateAdmission = errors.New("strategy-state-pair-required")

func requireNoStrategyState(ctx context.Context, stateRoot string) error {
	return requireNoStrategyStatePath(ctx, filepath.Join(stateRoot, "strategy-lab.json"))
}

func requireNoStrategyStatePath(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := os.Lstat(path)
	if !errors.Is(err, os.ErrNotExist) {
		return ErrStrategyStateAdmission
	}
	return ctx.Err()
}

func requireOrdinaryStrategyStatePath(ctx context.Context, path string) error {
	image, err := restorejournal.ReadFileImage(ctx, path)
	if err != nil {
		return ErrStrategyStateAdmission
	}
	_, err = ordinaryStrategyImage(image)
	return err
}

func (a *SelfUpdateFileAdapter) strategyStateAdmission(ctx context.Context, ids ...string) error {
	if a == nil || a.installation == "" {
		return ErrFileProtocol
	}
	image, schema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil {
		return err
	}
	if len(ids) != 1 {
		if image.Exists {
			return ErrStrategyStateAdmission
		}
		return nil
	}
	_, review, err := a.loadHeader(ctx, ids[0])
	if err != nil {
		return err
	}
	if review.StrategyPair == nil {
		if image.Exists {
			return ErrStrategyStateAdmission
		}
		return nil
	}
	return a.checkStrategyPair(ctx, review, image, schema)
}

type strategyControllerProof struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	StateReader    int    `json:"state_reader"`
	SnapshotReader int    `json:"snapshot_reader"`
}
type strategyPairProof struct {
	Schema      int                       `json:"schema"`
	StateSchema int                       `json:"state_schema"`
	StateSHA256 string                    `json:"state_sha256"`
	Controllers []strategyControllerProof `json:"controllers"`
}

func ordinaryStrategyImage(image restorejournal.Image) (int, error) {
	if !image.Exists {
		if len(image.Data) != 0 {
			return 0, ErrStrategyStateAdmission
		}
		return 0, nil
	}
	h := sha256.Sum256(image.Data)
	if strategylab.ValidatePrivateSnapshot(strategylab.PrivateSnapshot{Schema: 1, Content: image.Data, SHA256: hex.EncodeToString(h[:])}) != nil {
		return 0, ErrStrategyStateAdmission
	}
	var state strategylab.State
	if json.Unmarshal(image.Data, &state) != nil || (state.SchemaVersion != 1 && state.SchemaVersion != 4) || state.CompatibilitySession != nil || state.CompatibilityFinalizing {
		return 0, ErrStrategyStateAdmission
	}
	for _, c := range state.Candidates {
		if c.Validation.QuiescenceUnknown {
			return 0, ErrStrategyStateAdmission
		}
	}
	return state.SchemaVersion, nil
}

func (a *SelfUpdateFileAdapter) inspectOrdinaryStrategyState(ctx context.Context) (restorejournal.Image, int, error) {
	path := filepath.Join(a.installation, "razvilka/state/strategy-lab.json")
	if err := requireNoStrategyStatePath(ctx, path); err == nil {
		return restorejournal.Image{}, 0, nil
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return restorejournal.Image{}, 0, err
	}
	image, err := a.readPrivateFileImage(ctx, path)
	if err != nil {
		return image, 0, ErrStrategyStateAdmission
	}
	schema, err := ordinaryStrategyImage(image)
	return image, schema, err
}

func (a *SelfUpdateFileAdapter) sealStrategyPair(ctx context.Context, review fileReview) (*strategyPairProof, error) {
	image, schema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil || !image.Exists {
		return nil, err
	}
	// External old-generation bootstrap has separate archive ownership and is
	// deliberately outside this ordinary unchanged-state pair consumer.
	if review.Bootstrap != nil {
		return nil, ErrStrategyStateAdmission
	}
	images, err := a.strategyPairImages(ctx, review)
	if err != nil {
		return nil, err
	}
	proof := &strategyPairProof{Schema: 1, StateSchema: schema, StateSHA256: digestBytes(image.Data)}
	probe := a.strategyProbe
	if probe == nil {
		probe = func(c context.Context, image selfupdatejournal.BinaryImage, flag string) (string, error) {
			return a.probeStrategyReader(c, review, image, flag)
		}
	}
	for _, binary := range images {
		stateReader, err := probe(ctx, binary, "-strategy-lab-read-version")
		if err != nil || stateReader != "5\n" {
			return nil, ErrStrategyStateAdmission
		}
		snapshotReader, err := probe(ctx, binary, "-self-update-private-snapshot-read-version")
		if err != nil || snapshotReader != "3\n" {
			return nil, ErrStrategyStateAdmission
		}
		proof.Controllers = append(proof.Controllers, strategyControllerProof{binary.Path, binary.SHA256, 5, 3})
	}
	if len(proof.Controllers) < 2 {
		return nil, ErrStrategyStateAdmission
	}
	review.StrategyPair = proof
	if err := a.checkStrategyPair(ctx, review, image, schema); err != nil {
		return nil, err
	}
	return proof, nil
}

func (a *SelfUpdateFileAdapter) probeStrategyReader(ctx context.Context, review fileReview, image selfupdatejournal.BinaryImage, flag string) (string, error) {
	if a.admission == nil || (flag != "-strategy-lab-read-version" && flag != "-self-update-private-snapshot-read-version") {
		return "", ErrStrategyStateAdmission
	}
	root, err := ownedfs.Open(filepath.Dir(image.Path))
	if err != nil {
		return "", err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(image.Path), MaximumBinaryBytes)
	if err != nil || digestBytes(data) != image.SHA256 {
		return "", ErrStrategyStateAdmission
	}
	directory, err := os.MkdirTemp("", "razvilka-strategy-reader-")
	if err != nil {
		return "", err
	}
	defer os.Remove(directory)
	path := filepath.Join(directory, "controller")
	defer os.Remove(path)
	if err := os.WriteFile(path, data, 0700); err != nil {
		return "", err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, path, flag)
	command.Env = commandEnvironment()
	stdout, stderr := &cappedOutput{maximum: 16}, &cappedOutput{maximum: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	configureBoundedCommand(command)
	_, done, err := startInstallerHelperCommand(probeCtx, command, func(begin func() error) error {
		return a.admission(probeCtx, review.ID, review.AuthorityInstallationID, review.AuthoritySequence, "start/live", journalReaderProbeEffect, begin)
	})
	if done == nil {
		return "", errors.Join(ErrStrategyStateAdmission, err)
	}
	if err != nil {
		cancel()
		cleanupCommand(command)
	}
	waitErr := <-done
	if err != nil || waitErr != nil || stderr.Len() != 0 {
		return "", errors.Join(ErrStrategyStateAdmission, err, waitErr)
	}
	return stdout.String(), ctx.Err()
}

func (a *SelfUpdateFileAdapter) checkStrategyPair(ctx context.Context, review fileReview, image restorejournal.Image, schema int) error {
	proof := review.StrategyPair
	if proof == nil || proof.Schema != 1 || !image.Exists || proof.StateSchema != schema || proof.StateSHA256 != digestBytes(image.Data) || len(proof.Controllers) < 2 || len(proof.Controllers) > 1024 {
		return ErrStrategyStateAdmission
	}
	images, err := a.strategyPairImages(ctx, review)
	if err != nil || len(images) != len(proof.Controllers) {
		return ErrStrategyStateAdmission
	}
	for i, binary := range images {
		p := proof.Controllers[i]
		if p.Path != binary.Path || p.SHA256 != binary.SHA256 || p.StateReader != 5 || p.SnapshotReader != 3 {
			return ErrStrategyStateAdmission
		}
		hash, err := hashRegularFile(binary.Path, MaximumBinaryBytes)
		if err != nil || hash != binary.SHA256 {
			return ErrStrategyStateAdmission
		}
	}
	fresh, freshSchema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil || freshSchema != schema || fresh.Exists != image.Exists || !bytes.Equal(fresh.Data, image.Data) {
		return ErrStrategyStateAdmission
	}
	latest, err := a.strategyPairImages(ctx, review)
	if err != nil || !reflect.DeepEqual(images, latest) {
		return ErrStrategyStateAdmission
	}
	return ctx.Err()
}

// The installed pathname changes from old to candidate and back during the
// existing file transaction. Seal immutable control/candidate/retained images;
// observe the installed bytes independently as one of those exact two images.
// This proof is reader compatibility only, never permission to replace files.
func (a *SelfUpdateFileAdapter) strategyPairImages(ctx context.Context, review fileReview) ([]selfupdatejournal.BinaryImage, error) {
	live := filepath.Join(a.installation, "bin/razvilka")
	actual, err := hashRegularFile(live, MaximumBinaryBytes)
	if err != nil {
		return nil, ErrStrategyStateAdmission
	}
	allowed := actual == review.OldExecutableSHA256
	for _, file := range review.Files {
		if file.Target == "bin/razvilka" && actual == file.SHA256 {
			allowed = true
		}
	}
	if !allowed {
		return nil, ErrStrategyStateAdmission
	}
	images, err := a.journalReaderImagesWithCurrent(ctx, review, actual)
	if err != nil {
		return nil, err
	}
	result := make([]selfupdatejournal.BinaryImage, 0, len(images))
	for _, image := range images {
		if image.Path != live {
			result = append(result, image)
		}
	}
	return result, nil
}
