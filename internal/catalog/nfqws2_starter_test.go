package catalog

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// upstreamList reads a copy of an nfqws2-keenetic list kept with the snapshot.
func upstreamList(t *testing.T, name string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile("data/nfqws2-keenetic/upstream/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if name == "user.list" {
		sum := sha256.Sum256(data)
		for _, s := range NFQWS2Starter().Services {
			if s.Provenance == nil || s.Provenance.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatal("recorded upstream digest differs from the kept copy", s.ID)
			}
		}
	}
	domains := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
			domains[strings.ToLower(line)] = true
		}
	}
	return domains
}

func TestRepair2StarterExactlySixStockGroups(t *testing.T) {
	c := NFQWS2Starter()
	if len(c.Services) != 6 || Validate(c) != nil {
		t.Fatal("invalid default catalogue")
	}
	// RAZVILKA's documented supplements (data README); everything else must
	// be exactly the upstream host list of the snapshot.
	supplement := map[string]string{"discordstatus.com": "discord", "discordapp.io": "discord", "discord-attachments-uploads-prd.storage.googleapis.com": "discord",
		"airhornbot.com": "discord", "airhorn.solutions": "discord", "bigbeans.solutions": "discord", "watchanimeattheoffice.com": "discord", "hammerandchisel.ssl.zendesk.com": "discord",
		"auth.riotgames.com": "riotgames", "authenticate.riotgames.com": "riotgames"}
	seen := map[string]bool{}
	total, upstream := 0, 0
	for _, s := range c.Services {
		if !IsNFQWS2Starter(s) || len(s.Strategy) != 1 || s.Strategy[0] != "nfqws2" {
			t.Fatal("non-NFQ default")
		}
		for _, d := range s.Domains {
			if seen[d] {
				t.Fatal("duplicate domain", d)
			}
			seen[d] = true
			total++
			if owner, ok := supplement[d]; ok {
				if s.ID != owner {
					t.Fatal("supplement outside its service", d)
				}
				continue
			}
			upstream++
		}
	}
	hostList := upstreamList(t, "user.list")
	if upstream != len(hostList) || total != len(hostList)+len(supplement) {
		t.Fatal("stock membership changed", upstream, total, len(hostList))
	}
	for d := range hostList {
		if !seen[d] {
			t.Fatal("upstream domain missing from the catalogue", d)
		}
	}
	// A domain the package excludes is never processed by NFQWS2, so listing
	// it under an NFQWS2 service would be misleading (1.3.1 moved Roblox's
	// main domains to the exclude list).
	excluded := upstreamList(t, "exclude.list")
	for d := range seen {
		for suffix := d; ; {
			if excluded[suffix] {
				t.Fatal("catalogue domain is excluded by the package", d)
			}
			dot := strings.IndexByte(suffix, '.')
			if dot < 0 {
				break
			}
			suffix = suffix[dot+1:]
		}
	}
	b, e := os.ReadFile("../../configs/service-catalog.json")
	if e != nil || !bytes.Equal(b, nfqws2StarterJSON) {
		t.Fatal("installed data differs from reviewed data", e)
	}
	c.Services[0].Domains[0] = "injected.example"
	if IsNFQWS2Starter(c.Services[0]) {
		t.Fatal("modified definition accepted")
	}
	if !IsNFQWS2Starter(NFQWS2Starter().Services[0]) {
		t.Fatal("mutable shared data")
	}
}
