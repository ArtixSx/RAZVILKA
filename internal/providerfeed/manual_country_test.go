package providerfeed

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestManualCountryUsesOnlySafeLabelsAndPreservesAcceptedClaim(t *testing.T) {
	m, nodes, path := persistentManager(t)
	base := "vless://123e4567-e89b-12d3-a456-426614174000@nl.private.example:443?security=tls&sni=nl.private.example"
	imported := func(raw string) string {
		t.Helper()
		s, err := nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, raw, testTime, time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.RecordManualImportCountries(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
		return s.Nodes[0].ID
	}
	id := imported(base)
	if len(m.CountryMetadata()) != 0 {
		t.Fatal("endpoint/SNI inferred geography")
	}
	nl := base + "#" + url.PathEscape("🇳🇱 Нидерланды private-label-marker")
	imported(nl)
	if m.CountryMetadata()[id].Code != "NL" || m.CountryMetadata()[id].Source != "publisher" {
		t.Fatal("label not preserved as publisher metadata")
	}
	before, _ := os.ReadFile(filepath.Join(path, FileName))
	imported(nl)
	imported(base + "#" + url.PathEscape("🇩🇪 Германия"))
	after, _ := os.ReadFile(filepath.Join(path, FileName))
	if string(before) != string(after) || m.CountryMetadata()[id].Code != "NL" {
		t.Fatal("duplicate/conflicting label rewrote accepted metadata")
	}
	for _, data := range [][]byte{after, mustManualCountryJSON(t, m.CountryMetadata())} {
		for _, secret := range []string{"private-label-marker", "nl.private.example", "123e4567", "vless://"} {
			if strings.Contains(string(data), secret) {
				t.Fatal("private label/material persisted in metadata")
			}
		}
	}
}

func mustManualCountryJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestManualCountryAmbiguousAndDuplicateLabelsCannotSupplyClaim(t *testing.T) {
	for _, label := range []string{"🇳🇱 Германия", ""} {
		t.Run(label, func(t *testing.T) {
			m, nodes, _ := persistentManager(t)
			base := "vless://123e4567-e89b-12d3-a456-426614174000@private.example:443?security=tls#"
			raw := base + url.PathEscape(label)
			if label == "" {
				raw = base + url.PathEscape("🇳🇱 Нидерланды") + "\n" + base + url.PathEscape("🇩🇪 Германия")
			}
			if _, err := nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, raw, testTime, time.Hour, false); err != nil {
				t.Fatal(err)
			}
			if err := m.RecordManualImportCountries(context.Background(), raw); err != nil {
				t.Fatal(err)
			}
			if len(m.CountryMetadata()) != 0 {
				t.Fatal("ambiguous or discarded duplicate label acquired country")
			}
		})
	}
}
