package engineconfig

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestNFQWSModeIsDraftOnlyAndRequiresExactReviewAndDiscoveryConsent(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
	body := "# retained\nMODE_LIST='--hostlist=/opt/etc/nfqws2/lists/user.list'\nMODE_AUTO=\"$MODE_LIST --hostlist-auto=auto.list\"\nNFQWS_EXTRA_ARGS=\"$MODE_LIST\"\nNFQWS_ARGS=\"--lua-desync=circular:fails=2\"\nUDP_PORTS=443\n"
	if _, e := m.Stage("nfqws2", "main", body); e != nil {
		t.Fatal(e)
	}
	v, e := m.NFQWSMode()
	if e != nil || v.Mode != "user-list" || !v.CanAuto || !v.NativeAdaptive {
		t.Fatal(v, e)
	}
	if _, e := m.StageNFQWSMode(context.Background(), "auto", v.Review, false); !errors.Is(e, ErrNFQWSModeUnsupported) {
		t.Fatal(e)
	}
	if _, e := m.StageNFQWSMode(context.Background(), "auto", "wrong", true); !errors.Is(e, ErrNFQWSModeChanged) {
		t.Fatal(e)
	}
	after, e := m.StageNFQWSMode(context.Background(), "auto", v.Review, true)
	if e != nil || after.Mode != "auto" || !after.DraftOnly {
		t.Fatal(after, e)
	}
	raw, source, e := m.rawLocked("nfqws2", "main")
	if e != nil || source != "staged" || !strings.Contains(string(raw), "UDP_PORTS=443") || !strings.Contains(string(raw), "# retained") {
		t.Fatal(source, e)
	}
	if _, e := m.StageNFQWSMode(context.Background(), "user-list", v.Review, false); !errors.Is(e, ErrNFQWSModeChanged) {
		t.Fatal("stale accepted", e)
	}
}

func TestParseNFQWSListArgumentsFollowsTheShell(t *testing.T) {
	base := "MODE_LIST=\"--hostlist=/l/user.list\"\nMODE_ALL=\"--hostlist-exclude=/l/exclude.list\"\nMODE_AUTO=\"$MODE_LIST --hostlist-auto=/l/auto.list $MODE_ALL\"\nNFQWS_ARGS_IPSET=\"--ipset=/l/ipset.list --ipset-exclude=/l/ipset_exclude.list\"\n"
	for _, c := range []struct {
		extra, mode string
		want        []string
		ok          bool
	}{
		{`NFQWS_EXTRA_ARGS="$MODE_AUTO"`, "auto", []string{"--hostlist=/l/user.list", "--hostlist-auto=/l/auto.list", "--hostlist-exclude=/l/exclude.list"}, true},
		{`export NFQWS_EXTRA_ARGS="$MODE_LIST" # only mine`, "user-list", []string{"--hostlist=/l/user.list"}, true},
		// A repeated assignment is ambiguous to the reader: refused.
		{"NFQWS_EXTRA_ARGS=\"$MODE_AUTO\"\nNFQWS_EXTRA_ARGS=\"$MODE_LIST\"", "", nil, false},
		{`NFQWS_EXTRA_ARGS="$UNKNOWN"`, "", nil, false},
		{"NFQWS_EXTRA_ARGS=\"`cat /tmp/x`\"", "", nil, false},
	} {
		got, err := ParseNFQWSListArguments([]byte(base + c.extra + "\n"))
		if (err == nil) != c.ok || c.ok && (got.Mode != c.mode || strings.Join(got.Extra, " ") != strings.Join(c.want, " ") || strings.Join(got.IPSet, " ") != "--ipset=/l/ipset.list --ipset-exclude=/l/ipset_exclude.list") {
			t.Fatalf("%s: %+v %v", c.extra, got, err)
		}
	}
}
