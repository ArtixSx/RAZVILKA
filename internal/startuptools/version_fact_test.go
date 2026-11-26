package startuptools

import (
	"reflect"
	"testing"
)

// These are comparison-predicate negatives, not a tool owner or native grant.
func TestStaticVersionFactWhitelistRefusesUnknownProfiles(t *testing.T) {
	for _, base := range []profile{ubuntuProfile(), stockProfile()} {
		for name, change := range map[string]func(*profile){
			"hash":      func(p *profile) { p.mainSHA = "0000000000000000000000000000000000000000000000000000000000000000" },
			"version":   func(p *profile) { p.version += "-unknown" },
			"alias":     func(p *profile) { p.aliases[0] += "-unknown" },
			"loader":    func(p *profile) { p.loader += "-unknown" },
			"extension": func(p *profile) { p.extension += "-unknown" },
			"libraries": func(p *profile) { p.libraries = append(p.libraries, "/unknown") },
		} {
			t.Run(base.arch+"-"+name, func(t *testing.T) {
				p := cloneVersionProfile(base)
				change(&p)
				if staticVersionProfile(p) {
					t.Fatal("unknown comparison profile retained static versions")
				}
			})
		}
	}
	p := ubuntuProfile()
	p.mainSHA = "38ac0252c751be1c89ebc2e2eb6a05bf1720b05eea552a1dee8380af94d72a52"
	p.version = "1.8.10 (legacy)"
	p.id = "unissued-fixture-profile"
	if staticVersionProfile(p) {
		t.Fatal("unissued CI comparison shape accepted")
	}
}

func TestStaticVersionFactClonesWholeProfile(t *testing.T) {
	p := stockProfile()
	copy := cloneVersionProfile(p)
	if !reflect.DeepEqual(p, copy) {
		t.Fatal("comparison profile clone changed data")
	}
	copy.libraries[0] = "/changed"
	for key := range copy.pins {
		copy.pins[key][0] = "changed"
		break
	}
	if p.libraries[0] == "/changed" {
		t.Fatal("library mutation reached original profile")
	}
	for _, hashes := range p.pins {
		if hashes[0] == "changed" {
			t.Fatal("nested pin mutation reached original profile")
		}
	}
}
