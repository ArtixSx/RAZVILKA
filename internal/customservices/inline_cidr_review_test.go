package customservices

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

// Real ordinary Manager publication and protected files; no App/physical/
// network/native permission is created by these registry readback tests.
func inlineCIDRReviewFixture(t *testing.T) (context.Context, *Manager, catalog.Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	m, err := Load(filepath.Join(t.TempDir(), "custom-services.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := m.Create(catalog.Service{Name: "Inline TCP", CIDRs: []string{"203.0.113.7/32"}, ProbeURL: "https://telegram.org/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, m, clone([]catalog.Service{service})[0]
}

func TestInlineCIDRReviewRequiresOriginalPublishedManagerAndDetachedMetadata(t *testing.T) {
	ctx, m, service := inlineCIDRReviewFixture(t)
	r, err := m.ReviewAppliedInlineCIDRs(ctx, service)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Current(ctx, m); err != nil || !reflect.DeepEqual(service, r.Service()) {
		t.Fatal("actual published definition missing", err)
	}
	metadata := r.Service()
	metadata.CIDRs[0] = "198.51.100.8/32"
	if !reflect.DeepEqual(service, r.Service()) || r.Current(ctx, m) != nil {
		t.Fatal("detached metadata mutated original review")
	}
	other, err := Load(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.Current(ctx, other), ErrInlineCIDRReview) || r.Current(ctx, m) != nil {
		t.Fatal("another Manager adopted original review")
	}
	// Model a caller copy without copying the mutex itself.
	copy := &InlineCIDRReview{self: r, manager: m}
	if !errors.Is(copy.Current(ctx, m), ErrInlineCIDRReview) || !errors.Is(copy.Close(), ErrInlineCIDRReview) || copy.Service().ID != "" {
		t.Fatal("copied token supplied original ownership")
	}
	if r.Close() != nil || r.Close() != nil || !errors.Is(r.Current(ctx, m), ErrInlineCIDRReview) {
		t.Fatal("closed review revived")
	}
}

func TestInlineCIDRReviewRejectsUnpublishedOrMixedDefinitions(t *testing.T) {
	ctx, m, service := inlineCIDRReviewFixture(t)
	for _, cut := range []string{"metadata", "domain", "source", "unbounded", "cancelled", "uncertain"} {
		t.Run(cut, func(t *testing.T) {
			expected := clone([]catalog.Service{service})[0]
			operation := ctx
			switch cut {
			case "metadata":
				expected.CIDRs[0] = "198.51.100.8/32"
			case "domain":
				expected.Domains = []string{"example.org"}
			case "source":
				expected.SourceRefs = []string{"external"}
			case "unbounded":
				operation = context.Background()
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				operation = cancelled
			case "uncertain":
				m.writeUncertain = true
				defer func() { m.writeUncertain = false }()
			}
			if r, err := m.ReviewAppliedInlineCIDRs(operation, expected); r != nil || !errors.Is(err, ErrInlineCIDRReview) {
				t.Fatal("unpublished/mixed definition issued a review", cut)
			}
		})
	}
}

func TestInlineCIDRReviewDetectsWholeRegistryChangeAndSameBytesReplacement(t *testing.T) {
	for _, cut := range []string{"ordinary writer", "same bytes replacement", "in-place content"} {
		t.Run(cut, func(t *testing.T) {
			ctx, m, service := inlineCIDRReviewFixture(t)
			r, err := m.ReviewAppliedInlineCIDRs(ctx, service)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			original := append([]byte(nil), m.diskImage.Data...)
			switch cut {
			case "ordinary writer":
				// Keep reviewed service unchanged, but change the full registry.
				if _, err := m.Create(catalog.Service{Name: "Another", CIDRs: []string{"198.51.100.8/32"}}, nil); err != nil {
					t.Fatal("read owner blocked ordinary writer", err)
				}
			case "same bytes replacement":
				if err := r.root.WriteAtomic(r.name, original, 0600); err != nil {
					t.Fatal(err)
				}
			case "in-place content":
				if err := os.WriteFile(m.path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(r.Current(ctx, m), ErrInlineCIDRReview) {
				t.Fatal("changed original registry accepted")
			}
			if err := r.root.WriteAtomic(r.name, original, 0600); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(r.Current(ctx, m), ErrInlineCIDRReview) {
				t.Fatal("restored bytes renewed revoked original review")
			}
		})
	}
}
