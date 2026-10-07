package startuptools

import (
	"strings"
	"testing"
)

func TestPathDiagnosticsUseOnlyFixedCategories(t *testing.T) {
	for path, want := range map[string]string{
		"/opt/etc": "OPT_ETC", "/etc": "ETC", "/opt": "OPT",
		"/opt/lib/iptables": "EXTENSION_ROOT", "/usr/sbin/iptables-legacy": "XTABLES_ENTRY",
		"/opt/lib/private-name.so": "LIBRARY_PATH", "/private/secret": "OTHER_PROTECTED_PATH",
	} {
		got := pathCategory(path)
		if got != want || strings.Contains(got, "/") || strings.Contains(got, "secret") || strings.Contains(got, "private") {
			t.Fatal("diagnostic leaked dynamic path or lost category", got)
		}
	}
}
