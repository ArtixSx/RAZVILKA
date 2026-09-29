package catalog

import (
	"bytes"
	"os"
	"testing"
)

func TestRepair2StarterExactlySixStockGroups(t *testing.T) {
	c := NFQWS2Starter()
	if len(c.Services) != 6 || Validate(c) != nil {
		t.Fatal("invalid default catalogue")
	}
	// RAZVILKA's documented Discord supplement (data README); everything else
	// must remain the 278 upstream domains.
	supplement := map[string]bool{"discordstatus.com": true, "discordapp.io": true, "discord-attachments-uploads-prd.storage.googleapis.com": true,
		"airhornbot.com": true, "airhorn.solutions": true, "bigbeans.solutions": true, "watchanimeattheoffice.com": true, "hammerandchisel.ssl.zendesk.com": true}
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
			if supplement[d] {
				if s.ID != "discord" {
					t.Fatal("supplement outside Discord", d)
				}
				continue
			}
			upstream++
		}
	}
	if upstream != 278 || total != 278+len(supplement) {
		t.Fatal("stock membership changed", upstream, total)
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
