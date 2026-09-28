package community

import "testing"

func FuzzCommunityParsersFailWithoutPanic(f *testing.F) {
	for _, seed := range []string{"example.com\nfull:www.example.org\ndomain:example.net\n", "regexp:^a$\nkeyword:b\n", "10.0.0.0/8\n2001:db8::/32\n", "payload:\n  - '+.example.com'\n", ""} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = parseDomains(body)
		_, _, _ = parseDomainDocument(body)
		_, _ = parseCIDRs(body)
		if domain, err := normalizeDomain(string(body)); err == nil {
			if again, err := normalizeDomain(domain); err != nil || again != domain {
				t.Fatalf("normalizeDomain(%q)=%q is not stable: %q, %v", body, domain, again, err)
			}
		}
	})
}
