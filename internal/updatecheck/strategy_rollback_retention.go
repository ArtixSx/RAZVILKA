package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

const strategyRollbackRetentionName = "strategy-rollback-retention.json"
const strategyRollbackSealEffect = "strategy-rollback-retention-seal"

// Snapshot3 remains the original immutable preimage. This separate record is
// minted only by the joined native candidate-stop producer and binds the exact
// more recent settled history which rollback must preserve. It grants no live
// validation, process ownership, health or permission to replay a command.
type strategyRollbackRetention struct {
	Schema              int                       `json:"schema"`
	ID                  string                    `json:"id"`
	ReviewSHA256        string                    `json:"review_sha256"`
	SnapshotSHA256      string                    `json:"snapshot_sha256"`
	OriginalStateSHA256 string                    `json:"original_state_sha256"`
	StateSchema         int                       `json:"state_schema"`
	Current             restorejournal.Image      `json:"current"`
	Controllers         []strategyControllerProof `json:"controllers"`
	StopIntent          selfupdatejournal.Receipt `json:"stop_intent"`
	CandidateFinal      fileCommandReceipt        `json:"candidate_final"`
	Digest              string                    `json:"digest"`
}

func strategyRetentionBytes(proof strategyRollbackRetention) ([]byte, error) {
	proof.Digest = ""
	unsigned, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	proof.Digest = digestBytes(unsigned)
	return json.Marshal(proof)
}
func decodeStrategyRetention(raw []byte) (strategyRollbackRetention, error) {
	var proof strategyRollbackRetention
	if len(raw) > restorejournal.MaxImageBytes || decodeFileProtocol(raw, &proof) != nil {
		return proof, ErrStrategyStateAdmission
	}
	canonical, err := strategyRetentionBytes(proof)
	if err != nil || !bytes.Equal(canonical, raw) {
		return proof, ErrStrategyStateAdmission
	}
	return proof, nil
}
func retentionReaders(proof *strategyPairProof, schema int) bool {
	if proof == nil || len(proof.Controllers) < 2 || len(proof.Controllers) > 1024 {
		return false
	}
	for _, controller := range proof.Controllers {
		if controller.StateReader != 7 || controller.StateReader < schema || controller.SnapshotReader != 4 {
			return false
		}
	}
	return true
}

func (a *SelfUpdateFileAdapter) strategyRetention(ctx context.Context, review fileReview) (proof strategyRollbackRetention, present bool, err error) {
	full := filepath.Join(a.directory, review.ID, strategyRollbackRetentionName)
	if _, err := os.Lstat(full); errors.Is(err, os.ErrNotExist) {
		return proof, false, ctx.Err()
	}
	image, err := a.readPrivateFileImage(ctx, full)
	if err != nil || !image.Exists {
		return proof, false, errors.Join(ErrStrategyStateAdmission, err)
	}
	proof, err = decodeStrategyRetention(image.Data)
	if err != nil {
		return proof, false, err
	}
	record, actualReview, err := a.loadHeader(ctx, review.ID)
	if err != nil || !reflect.DeepEqual(actualReview, review) || review.StrategyPair == nil {
		return proof, false, ErrStrategyStateAdmission
	}
	if proof.Schema != 1 || proof.ID != review.ID || proof.ReviewSHA256 != record.FileReviewSHA256 || proof.OriginalStateSHA256 != review.StrategyPair.StateSHA256 || !validDigest("sha256:"+proof.SnapshotSHA256) || !proof.Current.Exists || !retentionReaders(review.StrategyPair, proof.StateSchema) || !reflect.DeepEqual(proof.Controllers, review.StrategyPair.Controllers) {
		return proof, false, ErrStrategyStateAdmission
	}
	schema, err := ordinaryStrategyImage(proof.Current)
	if err != nil || schema != proof.StateSchema || digestBytes(proof.Current.Data) == proof.OriginalStateSHA256 {
		return proof, false, ErrStrategyStateAdmission
	}
	root, err := a.commandRoot(review.ID)
	if err != nil {
		return proof, false, err
	}
	defer root.Close()
	snapshot, err := root.ReadLimited("private-snapshot.json", 6<<20)
	if err != nil || digestBytes(snapshot) != proof.SnapshotSHA256 {
		return proof, false, ErrStrategyStateAdmission
	}
	original, err := a.privateSnapshot(ctx, review.ID)
	if err != nil || original.Schema != 3 || digestBytes(original.Images["strategy"].Data) != proof.OriginalStateSHA256 {
		return proof, false, ErrStrategyStateAdmission
	}
	if !candidateStopIntent(proof.StopIntent, review.ID) || len(proof.StopIntent.Files) != 6 || !validFileCommandReceipt(proof.CandidateFinal) || proof.CandidateFinal.ID != review.ID || proof.CandidateFinal.Command != "start-candidate-panel" || proof.CandidateFinal.State != "reaped" || !proof.CandidateFinal.WaitECHILD || proof.CandidateFinal.Cancelled || proof.CandidateFinal.ExitCode != 0 {
		return proof, false, ErrStrategyStateAdmission
	}
	final, err := readFileCommand(root, review.ID, "start-candidate-panel")
	if err != nil || final != proof.CandidateFinal {
		return proof, false, ErrStrategyStateAdmission
	}
	if err := a.strategyRetentionLedger(ctx, review, proof); err != nil {
		return proof, false, err
	}
	return proof, true, ctx.Err()
}

func (a *SelfUpdateFileAdapter) strategyRetentionLedger(ctx context.Context, review fileReview, proof strategyRollbackRetention) error {
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.VerifyReviewedImages(ctx, review.ID, review.Files, review.OldExecutableSHA256, review.OldInitSHA256, review.OldConfigSHA256); err != nil {
		return err
	}
	current, present, err := store.Current()
	if err != nil || !present || current.ID != review.ID || !reflect.DeepEqual(current.Files, proof.StopIntent.Files) || current.Paired != nil || current.Retired != nil || current.BeforeFiles {
		return ErrStrategyStateAdmission
	}
	prefix := proof.StopIntent.Commands
	if len(current.Commands) < len(prefix) || len(current.Commands) > len(prefix)+2 || !slices.Equal(current.Commands[:len(prefix)], prefix) {
		return ErrStrategyStateAdmission
	}
	if len(current.Commands) > len(prefix) && current.Commands[len(prefix)] != "restore-private-state" {
		return ErrStrategyStateAdmission
	}
	if len(current.Commands) > len(prefix)+1 && current.Commands[len(prefix)+1] != "start-rollback-panel" {
		return ErrStrategyStateAdmission
	}
	if !current.Rollback {
		expected := proof.StopIntent
		expected.Phase = "command-finished"
		if !reflect.DeepEqual(current, expected) {
			return ErrStrategyStateAdmission
		}
		return ctx.Err()
	}
	if current.Phase == "command-started" && current.Command != "restore-private-state" {
		return selfupdatejournal.ErrUnknown
	}
	switch current.Phase {
	case "restoring", "restored", "command-started", "command-finished", "rolled-back", "rolled-back-stopped":
	default:
		return ErrStrategyStateAdmission
	}
	return ctx.Err()
}

func (a *SelfUpdateFileAdapter) strategyRollbackImages(ctx context.Context, id string, snapshot privateFileSnapshot) (map[string]restorejournal.Image, error) {
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return nil, err
	}
	retained, present, err := a.strategyRetention(ctx, review)
	if err != nil {
		return nil, err
	}
	if !present {
		return snapshot.Images, nil
	}
	if snapshot.Schema != 3 {
		return nil, ErrStrategyStateAdmission
	}
	actual, schema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil || schema != retained.StateSchema || actual.Exists != retained.Current.Exists || !bytes.Equal(actual.Data, retained.Current.Data) {
		return nil, ErrStrategyStateAdmission
	}
	result := make(map[string]restorejournal.Image, len(snapshot.Images))
	for name, image := range snapshot.Images {
		result[name] = image
	}
	result["strategy"] = retained.Current
	total := 0
	for _, image := range result {
		total += len(image.Data)
	}
	if total > restorejournal.MaxPlanBytes/2 {
		return nil, ErrFileProtocol
	}
	return result, nil
}
