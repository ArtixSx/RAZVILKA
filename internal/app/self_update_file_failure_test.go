package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Real file journal and candidate/installed images; process observations are
// simulated. These tests do not assert native installer success or authority.
type failingFileUpdateBoundary struct {
	*fileUpdateProof
	t                       *testing.T
	ctx                     context.Context
	mode                    string
	cause                   error
	quiesced, installReview bool
}

func (p *failingFileUpdateBoundary) sameContext(ctx context.Context) {
	p.t.Helper()
	if ctx != p.ctx {
		p.t.Fatal("diagnostic changed original callback context")
	}
}

func (p *failingFileUpdateBoundary) Review(ctx context.Context, id string) (uint64, string, []selfupdatejournal.File, error) {
	p.sameContext(ctx)
	if p.quiesced {
		p.installReview = true
		if p.mode == "install-review" {
			return 0, "", nil, p.cause
		}
	}
	return p.fileUpdateProof.Review(ctx, id)
}

func (p *failingFileUpdateBoundary) AuthorityAction(ctx context.Context, _ string, _ uint64, _ string) error {
	p.sameContext(ctx)
	if p.quiesced && (p.mode == "post-provider" || p.mode == "install-provider" && p.installReview) {
		return p.cause
	}
	return nil
}

func (p *failingFileUpdateBoundary) Quiescence(ctx context.Context, id string) error {
	p.sameContext(ctx)
	if p.quiesced && p.mode == "install-quiescence" {
		return p.cause
	}
	return p.fileUpdateProof.Quiescence(ctx, id)
}

func (p *failingFileUpdateBoundary) Run(ctx context.Context, id, command string) error {
	p.sameContext(ctx)
	err := p.fileUpdateProof.Run(ctx, id, command)
	if err == nil && command == "quiesce-old-runtime" {
		p.quiesced = true
	}
	return err
}

func TestSelfUpdateFileFailurePreparedBoundariesPreserveFiles(t *testing.T) {
	for _, test := range []struct{ mode, want string }{
		{"post-provider", "file-protocol-quiesce-post-authority-provider"},
		{"post-guard", "file-protocol-quiesce-post-authority-guard"},
		{"post-recovery", "file-protocol-quiesce-post-authority-recovery"},
		{"install-review", "file-protocol-install-review"},
		{"install-provider", "file-protocol-install-authority-provider"},
		{"install-quiescence", "file-protocol-install-quiescence"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			a, original := fileUpdateHTTPFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cause := errors.New("private /opt/path and stderr must remain local")
			p := &failingFileUpdateBoundary{fileUpdateProof: original, t: t, ctx: ctx, mode: test.mode, cause: cause}
			a.SelfUpdateFiles.Adapter = p
			a.SelfUpdateFiles.RecoveryGuard = func(c context.Context) error {
				p.sameContext(c)
				if p.quiesced && p.mode == "post-recovery" {
					return cause
				}
				return nil
			}
			guard := func(c context.Context) error {
				p.sameContext(c)
				if p.quiesced && p.mode == "post-guard" {
					return cause
				}
				return nil
			}
			err := a.SelfUpdateFiles.RunHelper(ctx, fileUpdateID, guard)
			if !errors.Is(err, cause) || updatecheck.SelfUpdateFileFailureCode(err) != test.want {
				t.Fatal("original failure boundary was lost", updatecheck.SelfUpdateFileFailureCode(err), test.want)
			}
			if ctx.Err() != nil {
				t.Fatal("diagnostic cancelled the caller context", ctx.Err())
			}
			r, present, readErr := a.SelfUpdateFiles.Current()
			wantCommands := []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"}
			if readErr != nil || !present || r.Phase != "prepared" || r.Index != 0 || r.BeforeFiles || r.Command != "" || !reflect.DeepEqual(r.Commands, wantCommands) {
				t.Fatal("prepared receipt advanced after failed boundary", r, readErr)
			}
			assertFileUpdateImages(t, a, original, true)
			if !reflect.DeepEqual(p.runs, wantCommands) || len(p.effects) != 0 || len(p.lives) != 0 || len(p.finishes) != 0 {
				t.Fatal("failure reached file admission or later commands", p.runs, p.effects, p.lives, p.finishes)
			}
		})
	}
}
