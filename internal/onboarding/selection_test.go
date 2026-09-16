package onboarding

import (
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"testing"
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
