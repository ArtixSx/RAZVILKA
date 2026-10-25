package updatecheck

import "testing"

func TestOrdinaryFutureVersionsIncludesPrereleaseGenerationWithoutChangingChannelPolicy(t *testing.T) {
	for _, tc := range []struct {
		old, next, channel   string
		ordinary, discovered bool
	}{
		{"0.20.0-rc.63", "0.20.0-rc.64", "preview", true, true},
		{"0.20.0-rc.63", "0.20.0-rc.64", "stable", true, false},
		{"0.20.0-rc.63", "0.20.0-rc.64", "", true, false},
		{"0.20.0-rc.63", "0.20.0", "stable", true, true},
		{"0.20.0-rc.63", "0.20.1", "stable", true, true},
		{"v0.20.0-rc.63", "v0.20.0-rc.64", "preview", true, true},
		{"0.20.0", "0.20.1", "stable", true, true},
		{"0.20.0", "0.20.0-rc.64", "preview", false, false},
		{"0.20.0-rc.64", "0.20.0-rc.63", "preview", false, false},
		{"0.20.0-rc.63", "0.20.0-rc.63", "preview", false, false},
		{"0.20.0-rc.9", "0.20.0-rc.10", "preview", true, true},
		{"0.19.3", "0.20.0", "stable", false, true},
		{"0.19.99-rc.63", "0.20.0", "stable", false, true},
		{"0.19.99", "0.20.0-rc.64", "preview", false, true},
		{"1.0.0-rc.1", "1.0.0", "stable", true, true},
		{"garbage", "0.20.1", "preview", false, false},
		{"0.20.0-rc.63", "0.20.0-rc.064", "preview", false, false},
		{"0.20.0-rc.063", "0.20.0", "stable", false, false},
		{"0.20.0-rc.63", "0.20.0-rc.64+build", "preview", true, false},
		{"0.20.0-rc.63", "0.20.0+build", "stable", true, false},
		{"0.20.0-rc.63", "0.20.0", "evil", true, false},
	} {
		t.Run(tc.old+"/"+tc.next+"/"+tc.channel, func(t *testing.T) {
			if got := ordinaryFutureVersions(tc.old, tc.next); got != tc.ordinary {
				t.Fatalf("ordinary generation admission=%v want=%v", got, tc.ordinary)
			}
			// Discovery narrows candidate selection independently. Neither an
			// RC installation nor ordinary admission opts the user into preview.
			if got := CanUpgradeChannel(tc.old, tc.next, tc.channel); got != tc.discovered {
				t.Fatalf("channel discovery=%v want=%v", got, tc.discovered)
			}
		})
	}
}
