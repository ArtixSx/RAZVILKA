package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// This is an excluded, unchanged data image, not an ordinary rollback pair.
// The genuine modern candidate can read it; old193 acquires no reader ABI.
// Snapshot2 never replays this file. The complete paired archive retains the
// prior bytes, while public offline restore preserves current state/fences.
type bootstrapOfflineStrategyProof struct {
	Schema       int    `json:"schema"`
	StateSchema  int    `json:"state_schema"`
	StateSHA256  string `json:"state_sha256"`
	HelperSHA256 string `json:"helper_sha256"`
	StateReader  int    `json:"state_reader"`
}

func hasBootstrapOfflineStrategy(review fileReview) bool {
	return review.Bootstrap != nil && review.Bootstrap.OfflineStrategy != nil
}

func validBootstrapOfflineStrategy(review fileReview) bool {
	if !hasBootstrapOfflineStrategy(review) {
		return true
	}
	p := review.Bootstrap.OfflineStrategy
	return review.Bootstrap.Mode == "offline" && review.StrategyPair == nil && p.Schema == 1 && p.StateSchema == 1 &&
		validDigest("sha256:"+p.StateSHA256) && p.HelperSHA256 == review.Bootstrap.HelperSHA256 &&
		(p.StateReader == 5 || p.StateReader == StrategyLabReadVersion)
}

func (a *SelfUpdateFileAdapter) sealBootstrapOfflineStrategy(ctx context.Context, record updateRecord, review fileReview, original *externalBootstrapPreparation) (*bootstrapOfflineStrategyProof, error) {
	image, schema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil || !image.Exists {
		return nil, err
	}
	if original == nil || review.Bootstrap == nil || review.Bootstrap.Mode != "offline" || review.StrategyPair != nil || schema != 1 || hasBootstrapOfflineStrategy(review) {
		return nil, ErrStrategyStateAdmission
	}
	if err := original.matches(ctx, a, record, review.Bootstrap); err != nil {
		return nil, errors.Join(ErrStrategyStateAdmission, err)
	}
	binary := filepath.Join(a.directory, review.ID, "bundle", "dist", record.Job.Release.Binary.Name)
	// This is the same genuine candidate metadata probe used by the original
	// external preparation. It grants no generic start/live admission.
	output, err := probeFileCapability(ctx, binary, "-strategy-lab-read-version")
	reader, parseErr := parseStrategyStateReader(output)
	closingErr := original.current(ctx)
	if err != nil || parseErr != nil || closingErr != nil {
		return nil, errors.Join(ErrStrategyStateAdmission, err, parseErr, closingErr)
	}
	proof := &bootstrapOfflineStrategyProof{Schema: 1, StateSchema: schema, StateSHA256: digestBytes(image.Data), HelperSHA256: review.Bootstrap.HelperSHA256, StateReader: reader}
	binding := *review.Bootstrap
	binding.OfflineStrategy = proof
	review.Bootstrap = &binding
	if err := a.checkBootstrapOfflineStrategy(ctx, review, image, schema); err != nil {
		return nil, err
	}
	return proof, original.current(ctx)
}

func (a *SelfUpdateFileAdapter) checkBootstrapOfflineStrategy(ctx context.Context, review fileReview, image restorejournal.Image, schema int) error {
	if !hasBootstrapOfflineStrategy(review) || !validBootstrapOfflineStrategy(review) || !image.Exists || schema != 1 || digestBytes(image.Data) != review.Bootstrap.OfflineStrategy.StateSHA256 {
		return ErrStrategyStateAdmission
	}
	// An excluded-state proof cannot interpret/adopt an ordinary retention
	// record, including an unknown or partially published generation.
	if _, err := os.Lstat(filepath.Join(a.directory, review.ID, strategyRollbackRetentionName)); !errors.Is(err, os.ErrNotExist) {
		return ErrStrategyStateAdmission
	}
	if err := a.bootstrapStrategyImagesCurrent(ctx, review); err != nil {
		return err
	}
	fresh, freshSchema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil || freshSchema != schema || fresh.Exists != image.Exists || !bytes.Equal(fresh.Data, image.Data) {
		return errors.Join(ErrStrategyStateAdmission, err)
	}
	return a.bootstrapStrategyImagesCurrent(ctx, review)
}

func (a *SelfUpdateFileAdapter) bootstrapStrategyImagesCurrent(ctx context.Context, review fileReview) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate := ""
	for _, file := range review.Files {
		if file.Target == "bin/razvilka" && file.SHA256 == review.Bootstrap.HelperSHA256 {
			candidate = file.Candidate
		}
	}
	if candidate == "" {
		return ErrStrategyStateAdmission
	}
	for _, path := range []string{filepath.Join(a.directory, review.ID, "control.bin"), candidate} {
		actual, err := hashRegularFile(path, MaximumBinaryBytes)
		if err != nil || actual != review.Bootstrap.HelperSHA256 {
			return errors.Join(ErrStrategyStateAdmission, err)
		}
	}
	installed, err := hashRegularFile(filepath.Join(a.installation, "bin/razvilka"), MaximumBinaryBytes)
	if err != nil || installed != review.OldExecutableSHA256 && installed != review.Bootstrap.HelperSHA256 {
		return errors.Join(ErrStrategyStateAdmission, err)
	}
	return ctx.Err()
}
