package engineconfig

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// The stock nfqws2-keenetic 1.3.1 configuration already covers Discord voice.
const stockNFQWS2UDP = "MODE_LIST=\"--hostlist=/opt/etc/nfqws2/lists/user.list\"\nNFQWS_EXTRA_ARGS=\"$MODE_LIST\"\nNFQWS_ARGS=\"--filter-tcp=443 --filter-l7=tls\"\n" +
	"NFQWS_ARGS_UDP=\"--filter-udp=590-600,1400,3478-3481,5349,19294-19344,49152-65535\n                --filter-l7=wireguard,stun,discord,mtproto,unknown\n                --out-range=<n2\n                --lua-desync=fake:repeats=6:strategy=1\"\n" +
	"NFQWS_ARGS_CUSTOM=\"\"\nUDP_PORTS=443,590:600,1400,3478:3481,5349,19294:19344,49152:65535\n"

func discordFixture(t *testing.T, body string) *Manager {
	t.Helper()
	m := New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
	if _, err := m.Stage("nfqws2", "main", body); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDiscordRepairLeavesCoveredStockConfigUnchanged(t *testing.T) {
	m := discordFixture(t, stockNFQWS2UDP)
	view, err := m.NFQWSMode()
	if err != nil || !view.DiscordVoice {
		t.Fatalf("stock profile not recognized: %+v %v", view, err)
	}
	after, err := m.StageNFQWSDiscordRepair(context.Background(), view.Review)
	raw, _, _ := m.rawLocked("nfqws2", "main")
	if err != nil || after.Review != view.Review || string(raw) != stockNFQWS2UDP {
		t.Fatalf("covered configuration was rewritten: %v", err)
	}
}

// Discord repair: an older configuration without a Discord UDP profile gets
// the repair in its additional strategies; existing strategies and ports stay.
func TestDiscordRepairAddsAdditionalStrategyAndPorts(t *testing.T) {
	body := "# kept comment\nMODE_LIST=\"--hostlist=/opt/etc/nfqws2/lists/user.list\"\nNFQWS_EXTRA_ARGS=\"$MODE_LIST\"\nNFQWS_ARGS=\"--filter-tcp=443 --filter-l7=tls --lua-desync=fake\"\nNFQWS_ARGS_CUSTOM=\"--filter-udp=27015 --lua-desync=fake\"\nUDP_PORTS=443,27015\n"
	m := discordFixture(t, body)
	view, err := m.NFQWSMode()
	if err != nil || view.DiscordVoice {
		t.Fatalf("missing profile reported as covered: %+v %v", view, err)
	}
	if _, err := m.StageNFQWSDiscordRepair(context.Background(), "stale"); !errors.Is(err, ErrNFQWSModeChanged) {
		t.Fatalf("stale review accepted: %v", err)
	}
	after, err := m.StageNFQWSDiscordRepair(context.Background(), view.Review)
	if err != nil || !after.DiscordVoice || !after.DraftOnly {
		t.Fatalf("repair not staged: %+v %v", after, err)
	}
	raw, source, _ := m.rawLocked("nfqws2", "main")
	text := string(raw)
	if source != "staged" || !strings.Contains(text, "# kept comment") || !strings.Contains(text, "--filter-tcp=443 --filter-l7=tls --lua-desync=fake") {
		t.Fatalf("existing configuration not preserved:\n%s", text)
	}
	if !strings.Contains(text, "--filter-udp=27015 --lua-desync=fake --new "+DiscordRepairProfile) {
		t.Fatalf("repair not appended to additional strategies:\n%s", text)
	}
	if !strings.Contains(text, `UDP_PORTS="443,27015,1400,3478:3481,5349,19294:19344,50000:50099"`) {
		t.Fatalf("voice ports not queued:\n%s", text)
	}
	if validation := ValidateContent("nfqws2", "main", text); !validation.OK {
		t.Fatalf("repaired configuration invalid: %s", validation.Output)
	}
	// A second request is a no-op once covered.
	again, err := m.StageNFQWSDiscordRepair(context.Background(), after.Review)
	raw2, _, _ := m.rawLocked("nfqws2", "main")
	if err != nil || string(raw2) != text || again.Review != after.Review {
		t.Fatalf("repeated repair changed the draft: %v", err)
	}
}

func TestDiscordRepairRefusesPortListOverflow(t *testing.T) {
	body := "NFQWS_ARGS=\"--filter-tcp=443\"\nUDP_PORTS=1:2,4:5,7:8,10:11,13:14,16:17,19\n"
	m := discordFixture(t, body)
	view, err := m.NFQWSMode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.StageNFQWSDiscordRepair(context.Background(), view.Review); !errors.Is(err, ErrDiscordRepairPorts) {
		t.Fatalf("multiport overflow accepted: %v", err)
	}
	raw, _, _ := m.rawLocked("nfqws2", "main")
	if string(raw) != body {
		t.Fatal("refused repair changed the draft")
	}
}
