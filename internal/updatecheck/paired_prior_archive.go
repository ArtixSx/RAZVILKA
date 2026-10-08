package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// This is a new offline evidence format, not an extension of private snapshot
// 1/2 or an active self-update receipt. It conveys no restore/retirement grant.
const pairedPriorArchiveSchema = 3
const pairedPriorArchiveKind = "razvilka-paired-prior-state"
const pairedPriorManifestEffect = "paired-offline-manifest"
const pairedPriorArchiveDirectory = "var/lib/razvilka-offline-recovery"
const maximumPairedArchiveBytes int64 = 2 << 30
const maximumPairedArchiveFileBytes int64 = MaximumBinaryBytes

var ErrPairedPriorArchive = errors.New("paired prior-state archive requires complete matching private evidence")

type priorRootSpec struct {
	path      string
	directory bool
	required  bool
}

// Whole application trees cover new/unknown descendants as bytes, never as
// retirement or replay authority. Independent control/native journals are
// included as evidence; there is deliberately no restore operation here.
var pairedPriorRoots = []priorRootSpec{
	{"bin/razvilka", false, true},
	{"etc/init.d/S99razvilka", false, true},
	{"etc/init.d/S99artem-flow", false, false},
	{"etc/init.d/S99artem-flow.razvilka-disabled", false, false},
	{"etc/razvilka", true, true},
	{"var/lib/razvilka", true, true},
	{"var/cache/razvilka", true, false},
	{"var/log/razvilka", true, false},
	{"var/run/razvilka.pid", false, false},
}

type pairedPriorBinding struct {
	ID             string `json:"id"`
	ReviewSHA256   string `json:"review_sha256"`
	ReceiptSHA256  string `json:"receipt_sha256"`
	InstallationID string `json:"installation_id"`
	Sequence       uint64 `json:"sequence"`
	Revision       uint64 `json:"revision"`
}

type pairedPriorRoot struct {
	Path      string           `json:"path"`
	Directory bool             `json:"directory"`
	Exists    bool             `json:"exists"`
	Mode      uint32           `json:"mode"`
	Entries   []directoryEntry `json:"entries,omitempty"`
}

type pairedPriorPayload struct {
	Root   int    `json:"root"`
	Name   string `json:"name"`
	Blob   string `json:"blob"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type pairedPriorArchive struct {
	Kind     string               `json:"kind"`
	Schema   int                  `json:"schema"`
	Platform string               `json:"platform"`
	Binding  pairedPriorBinding   `json:"binding"`
	Roots    []pairedPriorRoot    `json:"roots"`
	Payloads []pairedPriorPayload `json:"payloads"`
}

func pairedPriorRootFor(path string) (int, string, bool) {
	path = filepath.ToSlash(path)
	for i, root := range pairedPriorRoots {
		if path == root.path {
			return i, "", true
		}
		if root.directory && strings.HasPrefix(path, root.path+"/") {
			return i, filepath.FromSlash(strings.TrimPrefix(path, root.path+"/")), true
		}
	}
	return 0, "", false
}

func validatePairedPriorCoverage() error {
	covered := func(path string) error {
		path = filepath.ToSlash(path)
		if !strings.HasPrefix(path, "/opt/") {
			return ErrPairedPriorArchive
		}
		if _, _, covered := pairedPriorRootFor(strings.TrimPrefix(path, "/opt/")); !covered {
			return ErrPairedPriorArchive
		}
		return nil
	}
	for _, path := range ProductionPaths() {
		if err := covered(path); err != nil {
			return err
		}
	}
	return checkInstallerWritePaths("/opt", covered)
}

func validPairedPriorBinding(binding pairedPriorBinding) bool {
	return jobIDPattern.MatchString(binding.ID) && jobIDPattern.MatchString(binding.InstallationID) && binding.Sequence > 0 && validDigest("sha256:"+binding.ReviewSHA256) && validDigest("sha256:"+binding.ReceiptSHA256)
}

func validatePairedPriorArchive(doc pairedPriorArchive) error {
	if doc.Kind != pairedPriorArchiveKind || doc.Schema != pairedPriorArchiveSchema || doc.Platform != runtime.GOOS || !validPairedPriorBinding(doc.Binding) || len(doc.Roots) != len(pairedPriorRoots) || len(doc.Payloads) > 20000 || validatePairedPriorCoverage() != nil {
		return ErrPairedPriorArchive
	}
	next := 0
	var total int64
	for i, root := range doc.Roots {
		spec := pairedPriorRoots[i]
		if root.Path != spec.path || root.Directory != spec.directory || root.Mode > 0777 || spec.required && !root.Exists || !root.Exists && (root.Mode != 0 || len(root.Entries) != 0) || !root.Directory && len(root.Entries) != 0 {
			return ErrPairedPriorArchive
		}
		var names []string
		if root.Exists && root.Directory {
			data, _ := json.Marshal(directoryImage{Mode: root.Mode, Entries: root.Entries})
			if _, err := validateDirectoryImage(restorejournal.Image{Exists: true, Data: data}); err != nil {
				return ErrPairedPriorArchive
			}
			for _, entry := range root.Entries {
				if len(entry.Data) != 0 {
					return ErrPairedPriorArchive
				}
				if !entry.Directory {
					names = append(names, entry.Name)
				}
			}
		} else if root.Exists {
			names = []string{""}
		}
		for _, name := range names {
			if next >= len(doc.Payloads) {
				return ErrPairedPriorArchive
			}
			payload := doc.Payloads[next]
			if payload.Root != i || payload.Name != name || payload.Blob != fmt.Sprintf("payload-%08d", next) || payload.Size < 0 || payload.Size > maximumPairedArchiveFileBytes || !validDigest("sha256:"+payload.SHA256) {
				return ErrPairedPriorArchive
			}
			total += payload.Size
			if total > maximumPairedArchiveBytes {
				return ErrPairedPriorArchive
			}
			next++
		}
	}
	if next != len(doc.Payloads) {
		return ErrPairedPriorArchive
	}
	return nil
}

// CapturePairedPriorState captures and verifies the actually installed old
// application under the existing prepared transaction's writer lease. No
// current caller invokes it yet. Its returned digest is only copy evidence;
// a later guarded terminal lifecycle must bind it before any fleet exclusion.
func (a *SelfUpdateFileAdapter) CapturePairedPriorState(ctx context.Context, id string) (string, error) {
	if runtime.GOOS != "linux" || a == nil || ctx == nil || a.admission == nil || a.runtimeInactive == nil {
		return "", ErrPairedPriorArchive
	}
	if _, finite := ctx.Deadline(); !finite {
		return "", ErrPairedPriorArchive
	}
	record, review, err := a.load(ctx, id)
	if err != nil {
		return "", err
	}
	check := func(c context.Context) error {
		if err := a.Authority(c, id, review.Revision); err != nil {
			return err
		}
		if err := a.fileQuiescence(c, id); err != nil {
			return err
		}
		if err := a.filePanelAbsent(c); err != nil {
			return err
		}
		return a.runtimeInactive(c, id)
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return "", ErrPairedPriorArchive
	}
	defer store.Close()
	var digest string
	err = store.WithPreparedPriorState(ctx, id, check, check, func(c context.Context, receipt selfupdatejournal.Receipt) error {
		if err := store.VerifyReviewedImages(c, id, review.Files, review.OldExecutableSHA256, review.OldInitSHA256, review.OldConfigSHA256); err != nil {
			return err
		}
		data, _ := json.Marshal(receipt)
		binding := pairedPriorBinding{ID: id, ReviewSHA256: record.FileReviewSHA256, ReceiptSHA256: digestBytes(data), InstallationID: review.AuthorityInstallationID, Sequence: review.AuthoritySequence, Revision: review.Revision}
		digest, err = capturePairedPriorState(c, a.installation, binding, receipt, a.owned, check, func(begin func() error) error {
			return a.EffectAdmission(c, id, "start/live", pairedPriorManifestEffect, begin)
		}, nil)
		return err
	})
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return digest, nil
}

func priorArchiveMatchesReceipt(doc pairedPriorArchive, receipt selfupdatejournal.Receipt) error {
	for _, file := range receipt.Files {
		root, name, covered := pairedPriorRootFor(file.Target)
		if !covered {
			return ErrPairedPriorArchive
		}
		var payload *pairedPriorPayload
		for i := range doc.Payloads {
			if doc.Payloads[i].Root == root && doc.Payloads[i].Name == name {
				payload = &doc.Payloads[i]
				break
			}
		}
		if (payload != nil) != file.OldPresent || payload != nil && payload.SHA256 != file.OldHash {
			return ErrPairedPriorArchive
		}
		if payload != nil {
			mode := doc.Roots[root].Mode
			for _, entry := range doc.Roots[root].Entries {
				if entry.Name == name {
					mode = entry.Mode
				}
			}
			if mode != file.OldMode {
				return ErrPairedPriorArchive
			}
		}
	}
	return nil
}
