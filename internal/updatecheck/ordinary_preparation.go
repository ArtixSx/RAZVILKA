package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var errOrdinaryPreparation = errors.New("ordinary-preparation-owner-refused")

type ordinaryPreparationFailure struct {
	stage string
	cause error
}

func (e *ordinaryPreparationFailure) Error() string {
	return "ordinary-preparation-" + e.stage + "-refused"
}
func (e *ordinaryPreparationFailure) Unwrap() error { return e.cause }
func ordinaryPreparationFailed(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	switch stage {
	case "owner", "version", "histories", "capabilities", "journals", "candidate-check", "script-syntax", "migration", "ready":
	default:
		stage = "owner"
	}
	return &ordinaryPreparationFailure{stage, cause}
}

// Only the actual Updater.prepare generation issues this ephemeral capability.
// It grants neither raw replacement nor runtime/Stop acceptance. A subsequent
// Ready observation uses the sealed review and actual parent independently.
type ordinaryPreparation struct {
	self                *ordinaryPreparation
	updater             *Updater
	adapter             *SelfUpdateFileAdapter
	original            context.Context
	done                chan struct{}
	active              atomic.Bool
	header              []byte
	record              updateRecord
	files               map[string]string
	producer            fileProcess
	authority           SelfUpdateAuthority
	helperInfo, jobInfo os.FileInfo
	reviewSHA           string
}

func ordinaryFutureVersions(old, next string) bool {
	_, _, oldOK := parseComparableVersion(old)
	_, _, nextOK := parseComparableVersion(next)
	return oldOK && nextOK && compareVersions(old, "0.20.0") >= 0 && compareVersions(next, old) > 0
}

func (p *ordinaryPreparation) lifetime(ctx context.Context) error {
	if p == nil || p.self != p || !p.active.Load() || p.updater == nil || p.adapter == nil || ctx == nil || ctx != p.original || ctx.Err() != nil || p.done == nil {
		return errOrdinaryPreparation
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) {
		return errOrdinaryPreparation
	}
	select {
	case <-p.done:
		return errOrdinaryPreparation
	default:
	}
	u := p.updater
	u.mu.Lock()
	current := u.record
	valid := u.done == p.done && u.cancel != nil && !u.handoffActive && reflect.DeepEqual(current, p.record)
	u.mu.Unlock()
	if !valid {
		return errOrdinaryPreparation
	}
	return nil
}

func (p *ordinaryPreparation) matches(ctx context.Context, a *SelfUpdateFileAdapter, r updateRecord) error {
	if p == nil || p.adapter != a || r.ExecutableHash != p.producer.ExecutableSHA256 || !reflect.DeepEqual(r.Files, p.files) {
		return errOrdinaryPreparation
	}
	r.Files, r.ExecutableHash = nil, ""
	if !reflect.DeepEqual(r, p.record) {
		return errOrdinaryPreparation
	}
	return p.current(ctx)
}

// This profile is narrower than the existing capability2 API. Its only callers
// are the original preparation issuer and Ready's fresh verified parent.
func checkOrdinaryPreparationCapabilities(ctx context.Context, binary string, nodes, component int, probe func(context.Context, string, string) (string, error)) error {
	if ctx == nil || !knownNodeHistoryReadVersion(nodes) || !knownComponentReadVersion(component) || probe == nil {
		return ErrFileProtocol
	}
	for _, c := range []struct{ flag, wanted string }{
		{"-self-update-schema", "0\n"}, {"-self-update-read-version", "4\n"},
		{"-component-update-schema", ""}, {"-node-history-read-version", ""},
		{"-native-enrollment-schema", "1\n"}, {"-subscription-schema", "1\n"},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := probe(ctx, binary, c.flag)
		if err != nil {
			return errOrdinaryPreparation
		}
		switch c.flag {
		case "-component-update-schema":
			v, err := parseComponentReadVersion(value)
			if err != nil || v < max(components.ComponentUpdateSchema, component) {
				return ErrComponentHistoryAdmission
			}
		case "-node-history-read-version":
			v, err := parseNodeHistoryReadVersion(value)
			if err != nil || v < max(2, nodes) {
				return ErrNodeHistoryAdmission
			}
		default:
			if value != c.wanted {
				return errOrdinaryPreparation
			}
		}
	}
	return ctx.Err()
}

func ordinaryFutureReview(r updateRecord, review fileReview) bool {
	ordinary, err := ordinaryInstallerReviewKind(review, r)
	return err == nil && ordinary && review.PreparationParent != nil && validJournalReaderProof(review.JournalReaders) && review.JournalReaders.Schema == selfupdatejournal.PairedSchema && review.JournalReaders.RequiredReader == selfupdatejournal.PairedSchema
}

func ordinaryReadyParentMatches(record updateRecord, review fileReview, actual fileProcess) bool {
	return ordinaryFutureReview(record, review) && validFileProcess(actual) && actual == *review.PreparationParent && record.ParentPID == actual.PID &&
		record.Job.State == "ready" && record.Job.Stage == "ready" && record.Job.CanApply && !record.Job.CanCancel && record.Job.HelperPID == 0 && record.Job.ReviewToken != "" &&
		!record.Job.UpdatedAt.After(time.Now()) && time.Since(record.Job.UpdatedAt) <= 15*time.Minute
}

func ordinaryPreparationReport(output, version string, migration bool) bool {
	var report struct {
		OK       bool   `json:"ok"`
		Version  string `json:"version"`
		Migrated bool   `json:"migrated"`
	}
	// Main reports Migrated only when a schema actually changed. A no-op
	// migration is legitimate; the subsequent real staged-config inspection
	// independently checks preservation of all reviewed settings.
	return len(output) < 64<<10 && json.Unmarshal([]byte(output), &report) == nil && report.OK && report.Version == version && (migration || !report.Migrated)
}

// Every mutable candidate input is confined to this job, including the
// recovery journals derived by Main from the directory of -config.
func ordinaryPreparationArguments(job, mode, configPath string) []string {
	args := []string{mode, "-config", configPath}
	for _, item := range []struct{ flag, name string }{
		{"-custom-services", "custom.json"}, {"-devices", "devices.json"},
		{"-node-state", "nodes"}, {"-stage", "engines"},
		{"-warp-state", "warp"}, {"-cloudflare-state", "cloudflare"},
	} {
		args = append(args, item.flag, filepath.Join(job, "staged", item.name))
	}
	for _, item := range []struct{ flag, name string }{
		{"-catalog", "service-catalog.json"}, {"-sources", "sources.json"},
		{"-community-catalog", "community-catalog.json"},
	} {
		args = append(args, item.flag, filepath.Join(job, "bundle", "configs", item.name))
	}
	return args
}

func (p *ordinaryPreparation) commandMatches(path string, args []string, effect string) bool {
	if p == nil || p.adapter == nil || p.record.Job.Release == nil {
		return false
	}
	job := filepath.Join(p.adapter.directory, p.record.Job.ID)
	candidate := filepath.Join(job, "bundle/dist", p.record.Job.Release.Binary.Name)
	if path != candidate && path != p.record.Deployment.Executable {
		return false
	}
	switch effect {
	case "ordinary-prepare-metadata":
		if len(args) != 1 {
			return false
		}
		switch args[0] {
		case "-version", "-self-update-schema", "-self-update-read-version", "-component-update-schema", "-node-history-read-version", "-native-enrollment-schema", "-subscription-schema":
			return true
		}
	case "ordinary-prepare-check":
		return path == candidate && reflect.DeepEqual(args, ordinaryPreparationArguments(job, "-check", p.record.Deployment.Paths["config"]))
	case "ordinary-prepare-migration":
		return path == candidate && reflect.DeepEqual(args, ordinaryPreparationArguments(job, "-migrate-config", filepath.Join(job, "staged/config.json")))
	}
	return false
}
