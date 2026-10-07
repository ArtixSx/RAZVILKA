package updatecheck

import (
	"reflect"
	"testing"
)

func TestFileLiveEndpointRequiresActualCanonicalListen(t *testing.T) {
	for _, test := range []struct {
		args []string
		good bool
	}{
		{[]string{"runtime", "-listen", "192.168.1.1:8787"}, true},
		{[]string{"runtime", "-listen", "127.0.0.1:8787"}, true},
		{[]string{"runtime"}, false},
		{[]string{"runtime", "-listen"}, false},
		{[]string{"runtime", "-listen", "", "-listen", "127.0.0.1:8787"}, false},
		{[]string{"runtime", "-listen", "127.0.0.1:8787", "-listen", "127.0.0.1:8787"}, false},
		{[]string{"runtime", "-listen=127.0.0.1:8787"}, false},
		{[]string{"runtime", "--listen", "127.0.0.1:8787"}, false},
		{[]string{"runtime", "-listen", "0.0.0.0:8787"}, false},
		{[]string{"runtime", "-listen", "224.0.0.1:8787"}, false},
		{[]string{"runtime", "-listen", "[::1]:8787"}, false},
		{[]string{"runtime", "-listen", "127.0.0.1:80"}, false},
		{[]string{"runtime", "-listen", "127.0.0.1:08787"}, false},
		{[]string{"runtime", "-listen", "localhost:8787"}, false},
		{[]string{"runtime", "-listen", "127.0.0.1:8787/redirect"}, false},
	} {
		url, err := fileLiveEndpoint(test.args)
		if (err == nil) != test.good || !test.good && url != "" {
			t.Fatal("ambiguous/wide bind became health authority", test.args, url, err)
		}
	}
}

func TestFileLiveProbeExactRecipesAndAuthority(t *testing.T) {
	endpoint := "http://127.0.0.1:8787/api/v1/status"
	args, err := fileLiveProbeArgs(fileLiveHealthEffect, endpoint, 321)
	if err != nil || !reflect.DeepEqual(args, []string{"-healthcheck", endpoint, "-healthcheck-pid", "321", "-healthcheck-require-dataplane"}) {
		t.Fatal(args, err)
	}
	for _, test := range []struct {
		effect, endpoint string
		pid              int
	}{
		{"health-probe", endpoint, 321}, {journalReaderProbeEffect, endpoint, 321},
		{fileLiveVersionEffect, endpoint, 321}, {fileLiveVersionEffect, "", 321},
		{fileLiveHealthEffect, endpoint, 1},
		{fileLiveHealthEffect, "http://user@127.0.0.1:8787/api/v1/status", 321},
		{fileLiveHealthEffect, endpoint + "?query=secret", 321},
		{fileLiveHealthEffect, "https://127.0.0.1:8787/api/v1/status", 321},
		{fileLiveHealthEffect, "http://127.0.0.1:8787/other", 321},
	} {
		if args, err := fileLiveProbeArgs(test.effect, test.endpoint, test.pid); err == nil || args != nil {
			t.Fatal("arbitrary health payload accepted", test, args, err)
		}
	}
	for _, effect := range []string{fileLiveVersionEffect, fileLiveHealthEffect} {
		if !validFileEffect(effect) || !validFileEffectAction(effect, "start/live") {
			t.Fatal("exact selfupdate probe recipe unavailable", effect)
		}
		for _, action := range []string{"read/observe", "stop-owned", "replace-to-rollback"} {
			if validFileEffectAction(effect, action) {
				t.Fatal("cleanup/read authority granted probe Start", effect, action)
			}
		}
	}
}
