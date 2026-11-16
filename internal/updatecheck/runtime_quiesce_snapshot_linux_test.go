package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Exercise the actual quiesce entry, stopping at its next authority check.
// Model identities and receipts live only in the isolated adapter fixture;
// they never claim successful runtime quiescence or authorize a command.
func TestRuntimeQuiesceSnapshotAdmission(t *testing.T) {
	for _, kind := range []string{"mutable2", "paired3", "legacy1", "future4", "forged-state", "unbound-pair", "missing-hash", "unjoined-stop", "unjoined-private", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			paired := kind != "mutable2" && kind != "legacy1"
			var a *SelfUpdateFileAdapter
			var u *Updater
			var review fileReview
			if paired {
				a, u, review, _ = strategyPairFixture(t)
			} else {
				a, u, review = fileAdapterFixture(t)
				for _, rel := range []string{"etc/razvilka", "razvilka/state"} {
					if err := os.MkdirAll(filepath.Join(a.installation, rel), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx := context.Background()
			if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
				t.Fatal(err)
			}
			snapshot, err := a.privateSnapshot(ctx, review.ID)
			if err != nil || paired && snapshot.Schema != 3 || !paired && snapshot.Schema != 2 {
				t.Fatal("actual snapshot producer", err)
			}

			// A different birth for the same PID is inactive, independently of
			// any missing PID file. No running process is killed by this test.
			self, err := fileProcessOf(os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			self.ExecutableSHA256 = reviewedHelperSHA(review)
			old := self
			birth, err := strconv.ParseUint(old.Start, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			old.Start = strconv.FormatUint(birth+1, 10)
			old.ExecutableSHA256 = review.OldExecutableSHA256
			u.record.Job.HelperPID, u.record.ParentPID = self.PID, old.PID
			publishStrategyReview(t, a, u, review)
			job := filepath.Join(a.directory, review.ID)
			identity, err := json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, review.ID, self, old})
			if err != nil {
				t.Fatal(err)
			}
			retainedFile(t, job, "helper.identity.json", identity)
			if err := a.oldPanelInactive(ctx, review.ID); err != nil {
				t.Fatal("model prior birth not inactive", err)
			}
			root, err := a.commandRoot(review.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			for _, command := range []string{"stop-old-panel", "prepare-private-state"} {
				r := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: review.ID, Command: command, State: "reaped", Parent: self, Supervisor: self, WaitECHILD: true}
				if command == "stop-old-panel" {
					r.DirectPID, r.Reaped = self.PID, 1
				}
				if kind == "unjoined-stop" && command == "stop-old-panel" || kind == "unjoined-private" && command == "prepare-private-state" {
					r.State, r.WaitECHILD, r.Reaped, r.DirectPID = "armed", false, 0, 0
				}
				if err := writeFileCommand(root, r); err != nil {
					t.Fatal(err)
				}
			}

			switch kind {
			case "legacy1":
				snapshot.Schema = 1
				for name := range filePrivateDirectories {
					if _, present := snapshot.Images[name]; !present {
						snapshot.Images[name] = restorejournal.Image{}
					}
				}
			case "future4":
				snapshot.Schema = 4
			case "forged-state":
				image := snapshot.Images["strategy"]
				image.Data = append(image.Data, '\n')
				snapshot.Images["strategy"] = image
			case "unbound-pair":
				review.StrategyPair = nil
				publishStrategyReview(t, a, u, review)
			}
			data, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			retainedFile(t, job, "private-snapshot.json", data)
			retainedFile(t, job, "private-snapshot.sha256", []byte(digestBytes(data)))
			if kind == "missing-hash" {
				if err := os.Remove(filepath.Join(job, "private-snapshot.sha256")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "legacy1" {
				if _, err := a.privateSnapshot(ctx, review.ID); err != nil {
					t.Fatal("legacy must remain readable evidence", err)
				}
			}
			if kind == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			nextAuthority := errors.New("test reached the next quiesce authority check")
			calls := 0
			a.stopCheck = func(context.Context, string) (bool, error) { calls++; return false, nextAuthority }
			err = a.RuntimeQuiesceAuthority(ctx, review.ID, review.Revision, self.PID)
			wantNext := kind == "mutable2" || kind == "paired3"
			if err == nil || errors.Is(err, nextAuthority) != wantNext || (calls == 1) != wantNext || calls > 1 {
				t.Fatalf("snapshot boundary: next=%t calls=%d err=%v", wantNext, calls, err)
			}
		})
	}
}
