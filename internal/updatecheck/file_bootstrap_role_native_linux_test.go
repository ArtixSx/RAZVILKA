//go:build linux

package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This is an actual cold-observer refusal, not a bootstrap fixture grant.
// Review/old-panel facts are modeled; the observer's hash, argv and birth are
// read from the running test ELF. A copied candidate alone cannot gain a role.
func TestNativeBootstrapControllerRoleRefusesColdObserver(t *testing.T) {
	a, u, review := bootstrapOwnerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	self, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile("/proc/self/exe")
	if err != nil || digestBytes(program) != self.Process.ExecutableSHA256 {
		t.Fatal("actual observer image was not stable", err)
	}
	u.record.Job.Release.Binary.Digest = "sha256:" + self.Process.ExecutableSHA256
	u.record.Job.Release.Binary.Size = int64(len(program))
	u.record.Files["dist/"+u.record.Job.Release.Binary.Name] = self.Process.ExecutableSHA256
	review.Bootstrap.HelperSHA256 = self.Process.ExecutableSHA256
	u.record.Job.State, u.record.Job.CanApply, u.record.Job.CanCancel, u.record.Job.ReviewToken = "restarting", false, false, ""
	u.record.Job.HelperPID, u.record.ParentPID = self.Process.PID, 2147483646
	job := filepath.Join(a.directory, review.ID)
	for _, path := range []string{filepath.Join(job, "bundle/dist", u.record.Job.Release.Binary.Name), filepath.Join(job, "control.bin")} {
		if err := os.WriteFile(path, program, 0700); err != nil {
			t.Fatal(err)
		}
	}
	review.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	saveStoppedReview(t, a, u, review)
	panel := self.Process
	panel.PID, panel.ExecutableSHA256 = u.record.ParentPID, review.OldExecutableSHA256
	identity := fileHelperIdentity{selfUpdateProtocolSchema, review.ID, self.Process, panel}
	data, _ := json.Marshal(identity)
	if err := os.WriteFile(filepath.Join(job, "helper.identity.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.load(ctx, review.ID); err != nil {
		t.Fatal("negative fixture failed before role inspection", err)
	}
	if bootstrapControllerRole(review, u.record, identity, fileCommandReceipt{}, self) != "" {
		t.Fatal("actual cold test process acquired an installer role")
	}
	if err := a.VerifyInstallerControllerRole(ctx, review.ID, self.Process.PID); !errors.Is(err, ErrInstallerControllerRole) {
		t.Fatal("cold observer API borrowed modeled owner evidence", err)
	}
}
