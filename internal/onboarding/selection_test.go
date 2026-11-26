package onboarding

import (
	"errors"
	"slices"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
)

func TestSelectedStarterCanBeNoneOneOrAllButNeverBroader(t *testing.T) {
	c, cfg, old, next := fixture()
	m := map[string]autonomy.Service{}
	r := map[string]autonomy.Runtime{}
	review := Starter(c, cfg, old, m)
	for _, ids := range [][]string{{}, {"youtube"}, {"youtube", "discord"}, {"unknown"}, {"youtube", "youtube"}} {
		services, _, e := EnrollSelected(c, cfg, old, next, m, r, review.SHA256, nil, &ids)
		bad := len(ids) > 0 && ids[0] == "unknown" || len(ids) == 2 && ids[0] == ids[1]
		if bad {
			if e == nil {
				t.Fatal(ids)
			}
		} else if e != nil || len(services) != len(ids) {
			t.Fatal(ids, e, len(services))
		}
	}
}

func TestOptionalOnlyReviewPreservesExistingServicesAndExactSelection(t *testing.T) {
	c, cfg, old, next := fixture()
	for _, service := range c.Services {
		if catalog.IsNFQWS2Starter(service) {
			cfg.AppliedServices[service.ID] = State{Enabled: true, Route: "direct"}
		}
	}
	c.Services = append(c.Services,
		catalog.Service{ID: "another-option"},
		catalog.Service{ID: "already-configured"},
		catalog.Service{ID: "already-managed"},
	)
	cfg.Services["already-configured"] = State{Route: "direct"}
	managed := map[string]autonomy.Service{"already-managed": {ID: "already-managed", Enabled: true}}
	observations := map[string]autonomy.Runtime{"already-managed": {State: "healthy"}}
	review := Starter(c, cfg, old, managed)
	if !review.Eligible || review.SHA256 == "" || len(review.Items) != 0 || review.Skipped == 0 ||
		!slices.Equal(review.OptionalIDs, []string{"another-option", "extra-example"}) {
		t.Fatalf("wrong optional-only review: %+v", review)
	}
	for _, opts := range [][]string{nil, {"extra-example"}} {
		emptyStarter := []string{}
		services, states, err := EnrollSelected(c, cfg, old, next, managed, observations, review.SHA256, opts, &emptyStarter)
		if err != nil || len(services) != len(managed)+len(opts) || len(states) != len(services) || !services["already-managed"].Enabled || states["already-managed"].State != "healthy" {
			t.Fatalf("unexpected selection %v: %v, %v", opts, services, err)
		}
		if len(opts) != 0 && (services[opts[0]].ExpectedRoute != "auto" || !services[opts[0]].AllLAN || len(services[opts[0]].Sources) != 0 || states[opts[0]].State != "pending") {
			t.Fatal("explicit service was enrolled outside Standard or made active")
		}
	}
	for _, id := range []string{"already-configured", "already-managed", "youtube", "unknown"} {
		if _, _, err := Enroll(c, cfg, old, next, managed, observations, review.SHA256, []string{id}); !errors.Is(err, ErrStarterChanged) {
			t.Fatalf("unreviewed option accepted: %s", id)
		}
	}
	next.AllLAN = false
	if _, _, err := Enroll(c, cfg, old, next, managed, observations, review.SHA256, []string{"extra-example"}); !errors.Is(err, ErrStarterChanged) {
		t.Fatal("empty explicit device scope authorized enrollment")
	}
}

func TestBuiltinWebChoicesRequireExplicitEnrollment(t *testing.T) {
	_, cfg, old, next := fixture()
	c := catalog.WithWebDefaults(catalog.NFQWS2Starter())
	review := Starter(c, cfg, old, nil)
	if !slices.Equal(review.OptionalIDs, []string{"instagram-web", "telegram-web", "whatsapp-web"}) {
		t.Fatalf("quick setup choices %v", review.OptionalIDs)
	}
	noStock := []string{}
	services, runtime, err := EnrollSelected(c, cfg, old, next, nil, nil, review.SHA256, nil, &noStock)
	if err != nil || len(services) != 0 || len(runtime) != 0 {
		t.Fatalf("catalogue entries activated without selection: %v", err)
	}
	services, runtime, err = EnrollSelected(c, cfg, old, next, nil, nil, review.SHA256, []string{"telegram-web"}, &noStock)
	selected := services["telegram-web"]
	if err != nil || len(services) != 1 || len(runtime) != 1 || !selected.AllLAN || selected.ExpectedRoute != "auto" ||
		runtime["telegram-web"].State != "pending" {
		t.Fatalf("explicit web selection did not preserve Standard intent: %+v, %v", services, err)
	}
}

func TestOptionalReviewRejectsDuplicateCatalogIDAndPreservesLegacyHash(t *testing.T) {
	c, cfg, old, next := fixture()
	managed := map[string]autonomy.Service{}
	review := Starter(c, cfg, old, managed)
	type oldReview struct {
		Eligible       bool          `json:"eligible"`
		Route          string        `json:"route"`
		SHA256         string        `json:"sha256"`
		Items          []StarterItem `json:"items"`
		Skipped        int           `json:"skipped"`
		ConfigRevision uint64        `json:"config_revision"`
	}
	legacy := digest(struct {
		Catalog catalog.Catalog
		Config  ConfigView
		Policy  autonomy.Policy
		Managed map[string]autonomy.Service
		Review  oldReview
	}{c, cfg, old, managed, oldReview{true, review.Route, "", review.Items, review.Skipped, review.ConfigRevision}})
	if review.SHA256 != legacy {
		t.Fatal("legacy review digest changed")
	}
	duplicate := c.Services[len(c.Services)-1]
	c.Services = append(c.Services, duplicate)
	if bad := Starter(c, cfg, old, managed); bad.Eligible || bad.SHA256 != "" || len(bad.Items) != 0 || len(bad.OptionalIDs) != 0 {
		t.Fatalf("ambiguous catalog returned a usable review: %+v", bad)
	}
	if _, _, err := Enroll(c, cfg, old, next, managed, nil, legacy, []string{duplicate.ID}); !errors.Is(err, ErrStarterChanged) {
		t.Fatal("ambiguous description admitted after review")
	}
}
