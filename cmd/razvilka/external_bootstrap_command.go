package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// CORE dispatches this before ordinary startup. It accepts only a reviewed
// external package reference and fresh transaction ID, never installation,
// journal or control overrides. The actual original process is the helper.
func runExternalBootstrapCommand(args []string, roots selfUpdateJournalRoots) (bool, int) {
	if len(args) == 0 || args[0] != "self-update-bootstrap-old193" {
		return false, 0
	}
	if len(args) != 4 {
		return true, 2
	}
	id, idErr := hex.DecodeString(args[1])
	sha, shaErr := hex.DecodeString(args[3])
	if idErr != nil || len(id) != 16 || hex.EncodeToString(id) != args[1] || shaErr != nil || len(sha) != 32 || hex.EncodeToString(sha) != args[3] ||
		!filepath.IsAbs(args[2]) || filepath.Clean(args[2]) != args[2] {
		return true, 2
	}
	if runtime.GOOS != "linux" || roots != productionSelfUpdateJournalRoots() {
		return true, 3
	}
	parent, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	var gate operationgate.Gate
	ctx, release, err := gate.ExclusiveContext(parent)
	if err != nil {
		return true, 3
	}
	defer release() // The synchronous provider joins commands before release.
	control := selfUpdateDefaultPath("/opt/var/lib/razvilka/self-update-stop")
	var epoch *operationgate.ControlEpochReview
	defer func() {
		if epoch != nil {
			epoch.Close()
		}
	}()
	owner := func(c context.Context, transaction string) error {
		if transaction != args[1] {
			return updatecheck.ErrExternalBootstrap
		}
		if err := gate.WithExclusiveContext(c, func() error {
			if epoch != nil {
				return epoch.Current(c)
			}
			// Before the source has passed its physical read-only review, this
			// callback cannot initialize or adopt any protected control state.
			stop, present, err := operationgate.ReadSelfUpdateStop(c, control)
			if err != nil {
				return err
			}
			if present && stop.Stopped {
				return operationgate.ErrSelfUpdateStopped
			}
			return c.Err()
		}); err != nil {
			return err
		}
		return independentSelfUpdateFences(c, "/opt/etc/razvilka/config.json", "/opt/var/lib/razvilka/dataplane")
	}
	authority := func(c context.Context, transaction string) (updatecheck.SelfUpdateAuthority, error) {
		if c != ctx || transaction != args[1] {
			return updatecheck.SelfUpdateAuthority{}, updatecheck.ErrExternalBootstrap
		}
		if epoch == nil {
			err := gate.WithExclusiveContext(c, func() error {
				if _, err := operationgate.InitializeSelfUpdateControl(c, control); err != nil {
					return err
				}
				var err error
				epoch, err = gate.ReviewControlEpoch(c, control)
				return err
			})
			if err != nil {
				return updatecheck.SelfUpdateAuthority{}, err
			}
		}
		if err := owner(c, transaction); err != nil {
			return updatecheck.SelfUpdateAuthority{}, err
		}
		r := epoch.Reference()
		return updatecheck.SelfUpdateAuthority{InstallationID: r.InstallationID, Sequence: r.Sequence}, nil
	}
	admit := func(c context.Context, transaction, installation string, sequence uint64, action, effect string, begin func() error) error {
		if epoch == nil || begin == nil || owner(c, transaction) != nil {
			return updatecheck.ErrExternalBootstrap
		}
		r := epoch.Reference()
		if r.InstallationID != installation || r.Sequence != sequence {
			return operationgate.ErrSelfUpdateStopChanged
		}
		return gate.WithExclusiveContext(c, func() error {
			if action == "bootstrap-offline" {
				// Exact fixed-plan effects were checked by the bound adapter.
				// Existing durable Stop still revokes every forward effect.
				return operationgate.WithSelfUpdateEffectAdmission(c, control, transaction, installation, sequence, effect, begin)
			}
			return selfUpdateEffectAdmission(c, transaction, installation, sequence, action, effect, begin)
		})
	}
	adapter := updatecheck.NewSelfUpdateFileAdapterWithAuthority(selfUpdateStopCheck, admit, selfUpdateRuntimeInactive)
	result, err := adapter.BootstrapExternalOld193(ctx, args[1], args[2], args[3], owner, authority)
	if err != nil {
		fmt.Fprintln(os.Stderr, externalBootstrapFailureOutput(updatecheck.ExternalBootstrapFailureCategory(err)))
		if errors.Is(err, updatecheck.ErrFileCommandUnsettled) {
			// Do not claim that a failed join has relinquished process effects.
			gate.Fence()
		}
		return true, 3
	}
	return true, writeCommandJSON(result)
}

func externalBootstrapFailureOutput(category string) string {
	return "external old0.19.3 bootstrap requires review; category=" + category + "; retain package, journals and paired archive"
}

// The native gate may print only a recognized complete fixed CLI diagnostic.
// Arbitrary stderr, paths, result bytes and execution errors stay private.
func externalBootstrapDiagnosticCategory(diagnostic []byte) string {
	for _, category := range updatecheck.ExternalBootstrapFailureCategories() {
		if bytes.Equal(diagnostic, []byte(externalBootstrapFailureOutput(category)+"\n")) {
			return category
		}
	}
	return "unrecognized-or-absent-diagnostic"
}
