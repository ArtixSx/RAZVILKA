package engineconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func firstStartStock(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata", "nfqws2-first-start-1.3.1.conf"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestNFQWSFirstStartClosedArguments(t *testing.T) {
	stock := firstStartStock(t)
	const owner = "0123456789abcdef01234567"
	if e := NFQWSFirstStartStockConfig(stock); e != nil {
		t.Fatal(e)
	}
	raw, e := NFQWSFirstStartConfig(stock, owner, []string{"z.example", "a.example", "z.example"}, []string{"bank.example"}, []string{"192.0.2.0/24"})
	if e != nil {
		t.Fatal(e)
	}
	original, e := NFQWSFirstStartOriginalConfig(raw, owner)
	if e != nil || !bytes.Equal(original, stock) {
		t.Fatal("original changed", e)
	}
	effective, e := NFQWSFirstStartEffectiveConfig(raw, owner)
	if e != nil {
		t.Fatal(e)
	}
	args, e := NFQWSStartupArguments(effective, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"--filter-tcp=443", "--hostlist-domains=a.example,z.example", "--hostlist-exclude-domains=bank.example", "--ipset-exclude-ip=192.0.2.0/24"} {
		if !slices.Contains(args, want) {
			t.Fatal("missing", want, args)
		}
	}
	for _, arg := range args {
		if arg == "--new" || strings.HasPrefix(arg, "--filter-udp") || strings.Contains(arg, "/lists/") || strings.HasPrefix(arg, "--ipset=") {
			t.Fatal("open profile", args)
		}
	}
	fields, e := parseShellAssignments(effective)
	if e != nil || fields["TCP_PORTS"] != "443" || fields["UDP_PORTS"] != "" {
		t.Fatal("firewall ports", e)
	}
	for _, bad := range [][]byte{bytes.Replace(stock, []byte("CONFIG_VERSION=1"), []byte("CONFIG_VERSION=2"), 1), append(slices.Clone(stock), []byte("\ntouch /tmp/executed\n")...), append(slices.Clone(stock), []byte("\nEVIL=1\n")...)} {
		if NFQWSFirstStartStockConfig(bad) == nil {
			t.Fatal("accepted foreign config")
		}
	}
	for _, domains := range [][]string{nil, {"a.example'"}, {"a.example --new"}, {"$(whoami).example"}} {
		if _, e := NFQWSFirstStartConfig(stock, owner, domains, nil, nil); e == nil {
			t.Fatal("accepted invalid plan", domains)
		}
	}
}

func TestNFQWSFirstStartInitExactRoundTrip(t *testing.T) {
	stock, e := os.ReadFile(filepath.Join("..", "components", "testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if e != nil {
		t.Fatal(e)
	}
	const owner = "0123456789abcdef01234567"
	guarded, e := NFQWSFirstStartInit(stock, owner)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Count(guarded, []byte(`if [ -n "$UDP_PORTS" ]; then`)) != 3 {
		t.Fatal("not all UDP rules guarded")
	}
	restored, e := NFQWSFirstStartOriginalInit(guarded, owner)
	if e != nil || !bytes.Equal(restored, stock) {
		t.Fatal("not exact roundtrip", e)
	}
	if got, e := NFQWSFirstStartInitOwner(guarded); e != nil || got != owner {
		t.Fatal(got, e)
	}
	for _, bad := range [][]byte{append(slices.Clone(guarded), []byte("echo unknown\n")...), bytes.Replace(guarded, []byte("if [ -n"), []byte("if [ -z"), 1), bytes.Replace(guarded, []byte(owner), []byte("1123456789abcdef01234567"), 1)} {
		if _, e := NFQWSFirstStartOriginalInit(bad, owner); e == nil {
			t.Fatal("accepted foreign init")
		}
	}
	for _, bad := range [][]byte{
		append(slices.Clone(guarded), []byte(nfqwsFirstStartDispatch(owner))...),
		bytes.Replace(guarded, []byte("  owned_start) set -- start ;;"), []byte("  start) set -- start ;;"), 1),
		bytes.Replace(guarded, []byte(nfqwsFirstStartDispatchEnd), []byte("touch /tmp/foreign\n"+nfqwsFirstStartDispatchEnd), 1),
		bytes.Replace(guarded, []byte(nfqwsFirstStartDispatch(owner)), nil, 1),
	} {
		if _, err := NFQWSFirstStartOriginalInit(bad, owner); err == nil {
			t.Fatal("accepted missing, injected or duplicate dispatcher")
		}
	}
}
