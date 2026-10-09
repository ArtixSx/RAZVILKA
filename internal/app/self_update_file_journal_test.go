package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

type boundFileUpdateProof struct {
	*fileUpdateProof
	installation, journal string
	opens, reads          int
	openErr, readErr      error
	readHook              func()
}

func (p *boundFileUpdateProof) OpenFileJournal() (*selfupdatejournal.Store, error) {
	p.opens++
	if p.openErr != nil {
		return nil, p.openErr
	}
	return selfupdatejournal.OpenWithPairedEvidence(p.installation, p.journal, func(ctx context.Context, r selfupdatejournal.Receipt, _ string, _ bool) error {
		p.reads++
		if r.ID != fileUpdateID || r.Schema != selfupdatejournal.PairedSchema || r.Paired == nil {
			return selfupdatejournal.ErrMismatch
		}
		if p.readHook != nil {
			p.readHook()
		}
		return errors.Join(p.readErr, ctx.Err())
	})
}

func TestSelfUpdateAppPairedCurrentRequiresClosingReceipt(t *testing.T) {
	a, p := boundPairedFileUpdateFixture(t)
	p.readHook = func() {
		path := filepath.Join(p.journal, "current.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := a.SelfUpdateFiles.Current(); !errors.Is(err, selfupdatejournal.ErrMismatch) {
		t.Fatal("paired reader callback hid changed current pointer", err)
	}
	assertFileUpdateImages(t, a, p.fileUpdateProof, true)
}

// Actual App actions and owned journal/paired publication/file replacement.
// Archive/process evidence is an explicit provider model, never native proof.
func boundPairedFileUpdateFixture(t *testing.T) (*App, *boundFileUpdateProof) {
	t.Helper()
	a, original := fileUpdateHTTPFixture(t)
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	p := &boundFileUpdateProof{fileUpdateProof: original, installation: a.SelfUpdateFiles.Installation, journal: a.SelfUpdateFiles.Directory}
	s, err := p.OpenFileJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	okay := func(ctx context.Context) error { return ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err = s.SealPairedPriorState(ctx, fileUpdateID, okay, okay, func(ctx context.Context, prepared selfupdatejournal.Receipt) (selfupdatejournal.PairedBinding, error) {
		data, err := json.Marshal(prepared)
		if err != nil {
			return selfupdatejournal.PairedBinding{}, err
		}
		sum := sha256.Sum256(data)
		return selfupdatejournal.PairedBinding{ManifestSHA256: strings.Repeat("a", 64), PreparedSHA256: hex.EncodeToString(sum[:]), ReviewSHA256: strings.Repeat("b", 64), InstallationID: strings.Repeat("c", 32), Sequence: 1, Revision: original.revision}, ctx.Err()
	}, func(ctx context.Context, _ string, begin func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return begin()
	})
	if err != nil {
		t.Fatal(err)
	}
	a.SelfUpdateFiles.Adapter = p
	return a, p
}

func TestSelfUpdateAppUsesBoundPairedReaderAndPreparedInstall(t *testing.T) {
	a, p := boundPairedFileUpdateFixture(t)
	before := p.reads
	r, present, err := a.SelfUpdateFiles.Current()
	if err != nil || !present || r.Phase != "paired-prepared" || !r.Pending() || p.reads <= before {
		t.Fatal("actual App Current missed original paired evidence reader", r, present, err)
	}
	bare, err := selfupdatejournal.Open(p.installation, p.journal)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bare.RetainedReceipt(context.Background(), fileUpdateID)
	bare.Close()
	if err == nil {
		t.Fatal("bare reader unexpectedly admitted paired evidence")
	}
	assertFileUpdateImages(t, a, p.fileUpdateProof, true)
	if err := fileUpdateAction(t, a, "install"); err != nil {
		t.Fatal("original paired-prepared checkpoint could not install", err)
	}
	r, present, err = a.SelfUpdateFiles.Current()
	if err != nil || !present || r.Phase != "installed" || r.Schema != selfupdatejournal.PairedSchema || !r.Pending() || len(p.effects) != 6 {
		t.Fatal("paired install lost format/pending fence or exact effect admission", r, present, err, p.effects)
	}
	assertFileUpdateImages(t, a, p.fileUpdateProof, false)
}

func TestSelfUpdateAppNeverFallsBackAfterBoundReaderRefusal(t *testing.T) {
	for _, stage := range []string{"open", "evidence"} {
		t.Run(stage, func(t *testing.T) {
			a, p := boundPairedFileUpdateFixture(t)
			refused := errors.New("modeled original paired reader refused")
			if stage == "open" {
				p.openErr = refused
			} else {
				p.readErr = refused
			}
			if _, _, err := a.SelfUpdateFiles.Current(); !errors.Is(err, refused) {
				t.Fatal("Current replaced original provider refusal", err)
			}
			if err := a.SelfUpdateFiles.Action(context.Background(), fileUpdateID, "install", p.revision, func(context.Context) error { return nil }); !errors.Is(err, refused) {
				t.Fatal("Action fell back or hid original provider refusal", err)
			}
			assertFileUpdateImages(t, a, p.fileUpdateProof, true)
			if len(p.effects) != 0 {
				t.Fatal("refused evidence reached replacement", p.effects)
			}
		})
	}
}
