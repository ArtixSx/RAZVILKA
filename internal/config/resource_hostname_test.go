package config

import "testing"

func TestResourceHostnameAcceptsObservedHostingIdentityWithoutPermittingRule(t *testing.T) {
	for _, name := range []string{"discordsays.com", "discordsez.com", "github.io", "appspot.com", "co.uk"} {
		if actual, err := ResourceHostname(name); err != nil || actual != name {
			t.Fatal("actual hostname rejected", name, actual, err)
		}
		if _, err := PolicyDomain(name); err == nil {
			t.Fatal("observed identity became curated match rule", name)
		}
		for _, kind := range []string{"exact", "suffix"} {
			if _, err := NormalizeResourceMatches([]ResourceMatch{{Kind: kind, Value: name}}); err == nil {
				t.Fatal("hosting suffix exclusion rule admitted", kind, name)
			}
		}
	}
	for input, want := range map[string]string{"EXAMPLE.RU.": "example.ru", "пример.рф": "xn--e1afmkfd.xn--p1ai"} {
		if actual, err := ResourceHostname(input); err != nil || actual != want {
			t.Fatal("hostname canonical identity changed", input, actual, err)
		}
	}
	for _, name := range []string{"", "localhost", "https://example.ru/path", "example.ru/a", "example.ru:443", "*.example.ru", "1.1.1.1", "[::1]", "example..ru", "evil_1.ru", " example.ru", "example.ru..", "example.ru\x00", "example.ru\xff"} {
		if _, err := ResourceHostname(name); err == nil {
			t.Fatal("invalid observed hostname admitted", name)
		}
	}
}

func TestObservedHostingHostnameKeepsExclusionPrecedenceAndLabelBoundaries(t *testing.T) {
	cfg := Default()
	cfg.InactiveResourceExclusions = &ResourceExclusions{Schema: 1, Revision: 1, Manual: []ResourceMatch{{Kind: "service", Value: "discord"}, {Kind: "exact", Value: "exact.example"}, {Kind: "suffix", Value: "blocked.example"}}}
	set, err := EffectiveConfigResourceExclusions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []ResourceTarget{{Domain: "discordsays.com"}, {Domain: "discordsez.com"}, {Domain: "sub.exact.example"}, {Domain: "notblocked.example"}, {Domain: "blocked.example.attacker.test"}} {
		if denied, err := set.Matches(target); err != nil || denied {
			t.Fatal("observation changed rule semantics", target, denied, err)
		}
	}
	for _, target := range []ResourceTarget{{ServiceID: "discord", Domain: "discordsays.com"}, {Domain: "exact.example"}, {Domain: "blocked.example"}, {Domain: "sub.blocked.example"}} {
		if denied, err := set.Matches(target); err != nil || !denied {
			t.Fatal("current exclusion lost precedence", target, denied, err)
		}
	}
}
