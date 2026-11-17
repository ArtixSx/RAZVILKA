package updatecheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func publishStrategyReview(t *testing.T, a *SelfUpdateFileAdapter, u *Updater, review fileReview) {
	t.Helper()
	data, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "file-review.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.record.FileReviewSHA256 = digestBytes(data)
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
}
