package dataplane

import (
	"context"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestUSQUECommitReviewsOwnPublishedDraftBeforeManagerCommit(t *testing.T) {
	f := newUSQUELifecycleFixture(t)
	f.activate()
	configs := f.a.Configs
	draft, err := configs.ReadExpert("usque", "main")
	if err != nil || draft.Source != "staged" || draft.SHA256 == "" {
		t.Fatal("owned transaction did not have a staged source", err)
	}
	var closingContext context.Context
	ctx := WithReviewGuard(f.ctx, func(c context.Context) error {
		current, err := configs.ReadExpert("usque", "main")
		if err != nil || current.SHA256 != draft.SHA256 {
			return ErrReviewChanged
		}
		switch current.Source {
		case "staged":
			if ReviewingPublishedUSQUEDraft(c, configs, draft.SHA256) {
				t.Fatal("draft acquired publication evidence before its write")
			}
		case "live":
			if !ReviewingPublishedUSQUEDraft(c, configs, draft.SHA256) {
				return ErrReviewChanged
			}
			if ReviewCommittedAdapter(c) != "" || ReviewingPublishedUSQUEDraft(c, &engineconfig.Manager{}, draft.SHA256) ||
				ReviewingPublishedUSQUEDraft(c, configs, "foreign-digest") {
				t.Fatal("local publication borrowed wider commit authority")
			}
			closingContext = c
		default:
			return ErrReviewChanged
		}
		return nil
	})
	if err := f.a.Commit(ctx, f.plan, f.root); err != nil {
		t.Fatal("original Commit could not complete its own live health review", err)
	}
	if closingContext == nil || ReviewingPublishedUSQUEDraft(closingContext, configs, draft.SHA256) {
		t.Fatal("the original proof did not execute and revoke inside Commit")
	}
}
