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

func TestNFQWSCustomProfilesAreLiteralAndIgnoreTheManagedBlock(t *testing.T) {
	raw := "NFQWS_ARGS_CUSTOM=\"--filter-udp=50000 --filter-l7=discord --lua-desync=fake --new --filter-tcp=5222 --lua-desync=multisplit\"\nNFQWS_EXTRA_ARGS=\"$MODE_AUTO\"\n" +
		ManagedListBegin + "\nNFQWS_EXTRA_ARGS=\"$NFQWS_EXTRA_ARGS --hostlist-exclude=/x\"\n" + ManagedListEnd + "\n"
	got, err := NFQWSCustomProfiles([]byte(raw))
	if err != nil || len(got) != 2 || strings.Join(got[0], " ") != "--filter-udp=50000 --filter-l7=discord --lua-desync=fake" || strings.Join(got[1], " ") != "--filter-tcp=5222 --lua-desync=multisplit" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := NFQWSCustomProfiles([]byte("NFQWS_ARGS_CUSTOM=\"\"\n")); err != nil || len(got) != 0 {
		t.Fatalf("empty custom: %q %v", got, err)
	}
	for _, unresolved := range []string{"NFQWS_ARGS_CUSTOM=\"$OTHER\"\n", "NFQWS_ARGS_CUSTOM=\"`cat /tmp/x`\"\n", "NFQWS_ARGS_CUSTOM='$LITERAL'\n"} {
		if _, err := NFQWSCustomProfiles([]byte(unresolved)); err == nil {
			t.Fatalf("%q was read without running the shell", unresolved)
		}
	}
}

// While apply's managed block is in the live file, the owner's assignments
// still read and edit as before.
func TestGuidedReaderIgnoresManagedBlock(t *testing.T) {
	raw := "NFQWS_EXTRA_ARGS=\"$MODE_AUTO\"\n" + ManagedListBegin + "\nNFQWS_EXTRA_ARGS=\"$NFQWS_EXTRA_ARGS --hostlist-exclude=/x\"\nif [ -n \"$A\" ]; then A=\"$A b\"; fi\n" + ManagedListEnd + "\n"
	fields, err := parseShellAssignments(string(withoutManagedBlock([]byte(raw))))
	if err != nil || fields["NFQWS_EXTRA_ARGS"] != "$MODE_AUTO" {
		t.Fatalf("%v %v", fields, err)
	}
}
