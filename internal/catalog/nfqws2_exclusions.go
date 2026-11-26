package catalog

import (
	_ "embed"
	"strings"
)

// The exclude list shipped by nfqws2-keenetic (the same snapshot as the
// catalogue). The panel uses it only to tell the package's defaults from the
// owner's own exclusions; the router's live list is never replaced by it.
//
//go:embed data/nfqws2-keenetic/upstream/exclude.list
var nfqws2StockExcludeList string

// NFQWS2StockExclusions returns the package's default excluded domains.
func NFQWS2StockExclusions() []string {
	var domains []string
	for _, line := range strings.Split(nfqws2StockExcludeList, "\n") {
		if line = strings.ToLower(strings.TrimSpace(line)); line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains
}
