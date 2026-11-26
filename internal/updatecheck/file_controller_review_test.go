package updatecheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestControllerReviewRoutingRequiresBoundFormatAndFutureReaders(t *testing.T) {
	review, record, _, _, _ := ordinaryRoleFixture(t)
	if ordinary, err := ordinaryInstallerReviewKind(review, record); !ordinary || err != nil {
		t.Fatal("valid ordinary review refused", err)
	}
	bootstrap, bootstrapRecord, _, _, _ := bootstrapRoleFixture(t)
	if ordinary, err := ordinaryInstallerReviewKind(bootstrap, bootstrapRecord); ordinary || err != nil {
		t.Fatal("explicit bootstrap review was not identified", err)
	}
	for _, kind := range []string{"unknown-schema", "old-version", "downgrade", "no-readers", "reader3", "injected-bootstrap", "different-release", "different-owner", "different-job", "different-revision", "different-image", "nil-release"} {
		t.Run(kind, func(t *testing.T) {
			review, record, _, _, _ := ordinaryRoleFixture(t)
			switch kind {
			case "unknown-schema":
				review.Schema = 99
			case "old-version":
				review.OldVersion, record.CurrentVersion = "0.19.3", "0.19.3"
			case "downgrade":
				review.NewVersion, record.Job.Release.Version = "0.19.9", "0.19.9"
			case "no-readers":
				review.JournalReaders = nil
			case "reader3":
				review.JournalReaders.RequiredReader = 3
			case "injected-bootstrap":
				review.Bootstrap = bootstrap.Bootstrap
			case "different-release":
				review.ReleaseID++
			case "different-owner":
				record.Owner = "foreign"
			case "different-job":
				record.Job.ID = "ffffffffffffffffffffffffffffffff"
			case "different-revision":
				review.Revision++
			case "different-image":
				review.OldExecutableSHA256 = "changed"
			case "nil-release":
				record.Job.Release = nil
			}
			if ordinary, err := ordinaryInstallerReviewKind(review, record); ordinary || !errors.Is(err, ErrOrdinaryInstallerControllerRole) {
				t.Fatal("invalid ordinary review enabled a fallback", err)
			}
		})
	}
	bootstrap.Bootstrap.HelperSHA256 = bootstrap.OldExecutableSHA256
	if ordinary, err := ordinaryInstallerReviewKind(bootstrap, bootstrapRecord); ordinary || err == nil {
		t.Fatal("invalid bootstrap binding enabled a fallback")
	}
}

func TestControllerReviewRoutingRefusesColdContextAndModelAdapter(t *testing.T) {
	a := &SelfUpdateFileAdapter{}
	id := "0123456789abcdef0123456789abcdef"
	for _, ctx := range []context.Context{nil, context.Background()} {
		if ordinary, err := a.OrdinaryInstallerControllerReview(ctx, id); ordinary || !errors.Is(err, ErrOrdinaryInstallerControllerRole) {
			t.Fatal("unbounded routing context accepted", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if ordinary, err := a.OrdinaryInstallerControllerReview(ctx, id); ordinary || err == nil {
		t.Fatal("model adapter selected a production verifier")
	}
	cancel()
	if ordinary, err := a.OrdinaryInstallerControllerReview(ctx, id); ordinary || err == nil {
		t.Fatal("cancelled routing context accepted")
	}
}
