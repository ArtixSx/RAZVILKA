package catalog

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"slices"
	"sort"
)

// These are data, never imported shell commands or a network-installed manager.
// Keep configs/service-catalog.json byte-identical (enforced by tests).
//
//go:embed data/nfqws2-keenetic/catalog.json
var nfqws2StarterJSON []byte

// NFQWS2Starter returns an independent copy; callers must not mutate a shared
// catalogue image and thereby manufacture matching first-setup permissions.
func NFQWS2Starter() Catalog {
	var c Catalog
	if err := json.Unmarshal(nfqws2StarterJSON, &c); err != nil {
		panic(err)
	}
	return c
}

var nfqws2StarterReference = NFQWS2Starter()

// IsNFQWS2Starter deliberately requires the whole reviewed definition. An
// imported service, a familiar name, or a changed domain set cannot opt in.
func IsNFQWS2Starter(s Service) bool {
	for _, original := range nfqws2StarterReference.Services {
		if s.ID == original.ID {
			return reflect.DeepEqual(starterDefinition(s), starterDefinition(original))
		}
	}
	return false
}

// catalogSnapshot sorts merged destination sets and materializes empty slices.
// Accept only those representation differences; never extra destinations.
func starterDefinition(s Service) Service {
	s.Domains = slices.Clone(s.Domains)
	sort.Strings(s.Domains)
	s.CIDRs = slices.Clone(s.CIDRs)
	sort.Strings(s.CIDRs)
	if len(s.Domains) == 0 {
		s.Domains = nil
	}
	if len(s.CIDRs) == 0 {
		s.CIDRs = nil
	}
	return s
}
