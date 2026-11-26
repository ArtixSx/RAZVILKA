package z2kimport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyPreviewNormalizesCompatibleData(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".z2k-installed-tag", "v2.0.1\n")
	writeFixture(t, root, "lists/custom-strategies/yt_tcp.txt", "# custom\n--filter-tcp=443 --payload=tls_client_hello\n")
	writeFixture(t, root, "lists/custom-strategies/gv_tcp.txt", "--qnum=200 --filter-tcp=443\n")
	writeFixture(t, root, "lists/extra-domains.txt", "Example.COM\n*.video.example\nhttps://invalid.example/path\n")
	writeFixture(t, root, "lists/autohostlist-domains.txt", "auto.example\n")
	writeFixture(t, root, "ipset/zapret-hosts-user-exclude.txt", "203.0.113.9\n2001:db8::/32\nbad\n")
	writeFixture(t, root, "state.tsv", "youtube.com\t3\n# comment\n")
	preview, err := (Scanner{Root: root}).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Found || preview.Version != "v2.0.1" || !preview.ReadOnly {
		t.Fatalf("unexpected discovery: %+v", preview)
	}
	if len(preview.Strategies) != 2 || !preview.Strategies[1].Compatible && !preview.Strategies[0].Compatible {
		t.Fatalf("strategy compatibility missing: %+v", preview.Strategies)
	}
	compatible := 0
	for _, strategy := range preview.Strategies {
		if strategy.Compatible {
			compatible++
		}
	}
	if compatible != 1 {
		t.Fatalf("compatible strategies=%d: %+v", compatible, preview.Strategies)
	}
	if len(preview.ExtraDomains) != 2 || len(preview.AutoDomains) != 1 || len(preview.ExcludeCIDRs) != 2 || preview.StateRows != 1 {
		t.Fatalf("unexpected normalized data: %+v", preview)
	}
	if len(preview.Warnings) < 3 {
		t.Fatalf("ambiguous data was not reported: %+v", preview.Warnings)
	}
}

func TestMissingRootIsNotAnError(t *testing.T) {
	preview, err := (Scanner{Root: filepath.Join(t.TempDir(), "missing")}).Scan()
	if err != nil || preview.Found || !preview.ReadOnly {
		t.Fatalf("unexpected missing preview: %v %+v", err, preview)
	}
}

func writeFixture(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
