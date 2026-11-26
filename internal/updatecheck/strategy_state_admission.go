package updatecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// StrategyLab contains compatibility ownership/finalizing fences and evidence
// generations. An upgrade/rollback over an existing state requires the sealed
// settled unchanged-state pair below. Legacy paths remain closed; parsing a
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
	if len(ids) == 1 {
		return a.strategyAdmission(ctx, ids[0], false)
	}
	image, _, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil {
		return err
	}
	if image.Exists {
		return ErrStrategyStateAdmission
	}
	return nil
}

func (a *SelfUpdateFileAdapter) strategyAdmission(ctx context.Context, id string, preparing bool) error {
	image, schema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil {
		return err
	}
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	if hasBootstrapOfflineStrategy(review) {
		return a.checkBootstrapOfflineStrategy(ctx, review, image, schema)
	}
	if review.StrategyPair == nil {
		if image.Exists {
			return ErrStrategyStateAdmission
		}
		return nil
	}
	retained, present, err := a.strategyRetention(ctx, review)
	if err != nil {
		return err
	}
	if present {
		if preparing || schema != retained.StateSchema || image.Exists != retained.Current.Exists || !bytes.Equal(image.Data, retained.Current.Data) {
			return ErrStrategyStateAdmission
		}
		copyProof := *review.StrategyPair
		copyProof.StateSchema, copyProof.StateSHA256 = retained.StateSchema, digestBytes(retained.Current.Data)
		return a.checkStrategyPairMode(ctx, review, image, schema, preparing, &copyProof)
	}
	return a.checkStrategyPairMode(ctx, review, image, schema, preparing)
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

// Reader5 knows supervised state as standalone history, but its snapshot3
// pair contract accepted only ordinary1/4. Reader7 is the first controller
// that understands a settled supervised history in a paired snapshot.
func minimumStrategyPairReader(schema int) int {
	if schema == 1 || schema == 4 {
		return 5
	}
	return 7
}

func ordinaryStrategyImage(image restorejournal.Image) (int, error) {
	if !image.Exists {
		if len(image.Data) != 0 {
			return 0, ErrStrategyStateAdmission
		}
		return 0, nil
	}
	h := sha256.Sum256(image.Data)
	// Known terminal supervised history is preserved, never adopted as a
	// process owner. All actual Stop/journal/resource checks and exact binary
	// reader proofs remain mandatory at their existing effect boundaries.
	schema, err := strategylab.ReviewPrivatePairSnapshot(strategylab.PrivateSnapshot{Schema: 1, Content: image.Data, SHA256: hex.EncodeToString(h[:])})
	if err != nil {
		return 0, errors.Join(ErrStrategyStateAdmission, err)
	}
	return schema, nil
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
		version, versionErr := parseStrategyStateReader(stateReader)
		if err != nil || versionErr != nil || version < schema || version < minimumStrategyPairReader(schema) {
			return nil, ErrStrategyStateAdmission
		}
		snapshotReader, err := probe(ctx, binary, "-self-update-private-snapshot-read-version")
		versionSnapshot, versionErr := parsePrivateSnapshotReader(snapshotReader)
		if err != nil || versionErr != nil {
			return nil, ErrStrategyStateAdmission
		}
		proof.Controllers = append(proof.Controllers, strategyControllerProof{binary.Path, binary.SHA256, version, versionSnapshot})
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
	return a.checkStrategyPairMode(ctx, review, image, schema, false)
}

func (a *SelfUpdateFileAdapter) checkStrategyPairMode(ctx context.Context, review fileReview, image restorejournal.Image, schema int, preparing bool, retainedProof ...*strategyPairProof) error {
	proof := review.StrategyPair
	if len(retainedProof) > 1 {
		return ErrStrategyStateAdmission
	}
	if len(retainedProof) == 1 {
		proof = retainedProof[0]
	}
	if proof == nil || proof.Schema != 1 || !image.Exists || proof.StateSchema != schema || proof.StateSHA256 != digestBytes(image.Data) || len(proof.Controllers) < 2 || len(proof.Controllers) > 1024 {
		return ErrStrategyStateAdmission
	}
	images, err := a.strategyPairCheckImages(ctx, review, preparing)
	if err != nil || len(images) != len(proof.Controllers) {
		return ErrStrategyStateAdmission
	}
	for i, binary := range images {
		p := proof.Controllers[i]
		if p.Path != binary.Path || p.SHA256 != binary.SHA256 || (p.StateReader != 5 && p.StateReader != 7) || p.StateReader < schema || p.StateReader < minimumStrategyPairReader(schema) || (p.SnapshotReader != 3 && p.SnapshotReader != 4) {
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
	latest, err := a.strategyPairCheckImages(ctx, review, preparing)
	if err != nil || !reflect.DeepEqual(images, latest) {
		return ErrStrategyStateAdmission
	}
	return ctx.Err()
}

func parseStrategyStateReader(output string) (int, error) {
	version, err := strconv.Atoi(strings.TrimSuffix(output, "\n"))
	if err != nil || (version != 5 && version != StrategyLabReadVersion) || output != strconv.Itoa(version)+"\n" {
		return 0, ErrStrategyStateAdmission
	}
	return version, nil
}

func parsePrivateSnapshotReader(output string) (int, error) {
	if output == "3\n" {
		return 3, nil
	}
	if output == "4\n" {
		return 4, nil
	}
	return 0, ErrStrategyStateAdmission
}

type strategyPreparationKey struct{}
type strategyPreparation struct {
	self    *strategyPreparation
	adapter *SelfUpdateFileAdapter
	ctx     context.Context
	review  fileReview
	active  atomic.Bool
}

func (a *SelfUpdateFileAdapter) strategyPreparationFor(ctx context.Context, id string) *strategyPreparation {
	if ctx == nil || ctx.Err() != nil {
		return nil
	}
	token, _ := ctx.Value(strategyPreparationKey{}).(*strategyPreparation)
	if token == nil || token.self != token || token.adapter != a || token.ctx != ctx || token.review.ID != id || !token.active.Load() {
		return nil
	}
	return token
}

// Only the original synchronous six-file Prepare can borrow this scope. It
// permits immutable reader observations while Prepare constructs its own
// still-unreceipted snapshots; it grants no native or file replacement effect.
func (a *SelfUpdateFileAdapter) WithStrategyPairPreparation(ctx context.Context, id string, use func(context.Context) error) (result error) {
	if use == nil || ctx == nil || ctx.Err() != nil || a.strategyPreparationFor(ctx, id) != nil {
		return ErrStrategyStateAdmission
	}
	if err := a.strategyStateAdmission(ctx, id); err != nil {
		return err
	}
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	if review.StrategyPair == nil {
		return use(ctx)
	}
	token := &strategyPreparation{adapter: a, review: review}
	token.self = token
	scoped := context.WithValue(ctx, strategyPreparationKey{}, token)
	token.ctx = scoped
	token.active.Store(true)
	defer func() { token.active.Store(false) }()
	result = use(scoped)
	token.active.Store(false)
	// Even an unsuccessful Prepare never turns its incomplete files into a
	// readable inventory or a grant for another invocation.
	return errors.Join(result, a.strategyStateAdmission(ctx, id))
}

func (a *SelfUpdateFileAdapter) StrategyPairPreparationAuthority(ctx context.Context, id string, revision uint64) error {
	if a.strategyPreparationFor(ctx, id) == nil {
		return a.AuthorityAction(ctx, id, revision, "start/live")
	}
	return a.authorityAction(ctx, id, revision, "start/live", true)
}

func (a *SelfUpdateFileAdapter) strategyPairCheckImages(ctx context.Context, review fileReview, preparing bool) ([]selfupdatejournal.BinaryImage, error) {
	if !preparing {
		return a.strategyPairImages(ctx, review)
	}
	token := a.strategyPreparationFor(ctx, review.ID)
	if token == nil || !reflect.DeepEqual(token.review, review) {
		return nil, ErrStrategyStateAdmission
	}
	actual, err := hashRegularFile(filepath.Join(a.installation, "bin/razvilka"), MaximumBinaryBytes)
	if err != nil || actual != review.OldExecutableSHA256 {
		return nil, ErrStrategyStateAdmission
	}
	images := make([]selfupdatejournal.BinaryImage, 0, len(review.StrategyPair.Controllers))
	for _, controller := range review.StrategyPair.Controllers {
		images = append(images, selfupdatejournal.BinaryImage{Path: controller.Path, SHA256: controller.SHA256})
	}
	return images, ctx.Err()
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
