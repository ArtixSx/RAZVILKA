package updatecheck

import "testing"

// Every ordinary controller gate must admit the same generation as its
// original preparation, while still comparing the bound old and new versions.
func TestOrdinaryControllerGatesSharePreparationVersionAdmission(t *testing.T) {
	for _, tc := range []struct {
		old, next string
		accepted  bool
	}{
		{"0.20.0-rc.81", "0.20.0-rc.82", true},
		{"0.20.0-rc.81", "0.20.0", true},
		{"0.20.0-rc.81", "0.20.1", true},
		{"0.20.0", "0.20.1", true},
		{"0.19.3", "0.20.1", false},
		{"0.19.99-rc.1", "0.20.0", false},
		{"invalid", "0.20.1", false},
		{"0.20.0-rc.81", "invalid", false},
		{"0.20.0-rc.81", "0.20.0-rc.80", false},
		{"0.20.0", "0.20.0-rc.82", false},
		{"0.20.0-rc.81", "0.20.0-rc.81", false},
	} {
		t.Run(tc.old+"/"+tc.next, func(t *testing.T) {
			review, record, identity, command, facts := ordinaryRoleFixture(t)
			review.OldVersion, record.CurrentVersion = tc.old, tc.old
			review.NewVersion, record.Job.Release.Version = tc.next, tc.next
			ordinary, err := ordinaryInstallerReviewKind(review, record)
			if ordinary != tc.accepted || (err == nil) != tc.accepted {
				t.Fatalf("review routing accepted=%v err=%v want=%v", ordinary, err, tc.accepted)
			}
			for i, want := range []string{"ordinary-installer", "quiesce-supervisor", "quiesce-child"} {
				if !tc.accepted {
					want = ""
				}
				if got := ordinaryControllerRole(review, record, identity, command, facts[i]); got != want {
					t.Fatalf("controller %d role=%q want=%q", i, got, want)
				}
			}
			command.State, command.Reaped, command.WaitECHILD = "reaped", 1, true
			want := ""
			if tc.accepted {
				want = "ordinary-installer"
			}
			if got := ordinaryJoinedInstallerRole(review, record, identity, command, facts[0]); got != want {
				t.Fatalf("joined installer role=%q want=%q", got, want)
			}
		})
	}
}
