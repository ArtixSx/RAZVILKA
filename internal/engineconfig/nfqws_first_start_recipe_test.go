package engineconfig

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestNFQWSFirstStartRecipeRoundTripAndClosedTCP443(t *testing.T) {
	const owner = "0123456789abcdef01234567"
	stock := firstStartStock(t)
	legacy, err := NFQWSFirstStartConfig(stock, owner, []string{"selected.example"}, []string{"bank.example"}, []string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	const legacyBlock = "# RAZVILKA INSTANCE 0123456789abcdef01234567\n# RAZVILKA NFQWS2 TCP443 STARTER v1\n" +
		"NFQWS_BASE_ARGS='--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua --lua-init=@/opt/etc/nfqws2/lua/zapret-antidpi.lua --fastpath-workaround=0 --ipcache-hostname=0'\n" +
		"NFQWS_ARGS='--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld'\n" +
		"NFQWS_ARGS_QUIC=''\nNFQWS_ARGS_UDP=''\nNFQWS_ARGS_IPSET=''\nNFQWS_ARGS_CUSTOM=''\n" +
		"NFQWS_EXTRA_ARGS='--hostlist-domains=selected.example --hostlist-exclude-domains=bank.example --ipset-exclude-ip=192.0.2.0/24'\nTCP_PORTS=443\nUDP_PORTS=''\nLOG_LEVEL=0\n"
	if !bytes.Equal(legacy, append(slices.Clone(stock), []byte(ManagedListBegin+"\n"+legacyBlock+ManagedListEnd+"\n")...)) {
		t.Fatal("default no longer matches the original v1 bytes")
	}
	for _, recipe := range []NFQWSFirstStartRecipe{"", NFQWSFirstStartStockTLSCircular, NFQWSFirstStartStockTLSCircularAuto, NFQWSFirstStartStockTLSCircularObserveAuto} {
		raw, err := NFQWSFirstStartConfigForRecipe(stock, owner, []string{"selected.example"}, []string{"bank.example"}, []string{"192.0.2.0/24"}, recipe)
		if err != nil {
			t.Fatal(err)
		}
		if recipe == "" && !bytes.Equal(raw, legacy) {
			t.Fatal("default changed v1 bytes")
		}
		original, err := NFQWSFirstStartOriginalConfig(raw, owner)
		if err != nil || !bytes.Equal(original, stock) {
			t.Fatal("stock evidence changed", err)
		}
		got, err := NFQWSFirstStartConfigRecipe(raw, owner)
		if err != nil || got != recipe {
			t.Fatal("recipe roundtrip", got, err)
		}
		main, err := NFQWSFirstStartEffectiveConfig(raw, owner)
		if err != nil {
			t.Fatal(err)
		}
		args, err := NFQWSStartupArguments(main, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"--filter-tcp=443", "--filter-l7=tls", "--payload=tls_client_hello", "--hostlist-domains=selected.example", "--hostlist-exclude-domains=bank.example", "--ipset-exclude-ip=192.0.2.0/24", "--ipcache-hostname=0"} {
			if !slices.Contains(args, want) {
				t.Fatal("missing closed constraint", want)
			}
		}
		mode := "--fastpath-workaround=0"
		if recipe == NFQWSFirstStartStockTLSCircularAuto || recipe == NFQWSFirstStartStockTLSCircularObserveAuto {
			mode = "--fastpath-workaround=auto"
		}
		if !slices.Contains(args, mode) {
			t.Fatal("wrong fastpath mode", args)
		}
		for _, arg := range args {
			if strings.HasPrefix(arg, "--filter-udp") || arg == "--new" || strings.Contains(arg, "http_req") || strings.Contains(arg, "mtproto") {
				t.Fatal("widened recipe", arg)
			}
		}
		if recipe != "" && (!slices.Contains(args, "--lua-init=@/opt/etc/nfqws2/lua/zapret-auto.lua") || !slices.Contains(args, "--blob=tls_clienthello:@/opt/etc/nfqws2/blobs/tls_clienthello.bin")) {
			t.Fatal("missing circular assets")
		}
		start := bytes.Index(raw, []byte(ManagedListBegin))
		change := func(before, after string) []byte {
			return append(slices.Clone(raw[:start]), bytes.Replace(raw[start:], []byte(before), []byte(after), 1)...)
		}
		for _, bad := range [][]byte{
			change("--filter-tcp=443", "--filter-tcp=443,80"),
			change("--payload=tls_client_hello", "--payload=tls_client_hello,mtproto_initial"),
			append(slices.Clone(raw), []byte("# foreign tail\n")...),
		} {
			// Replace in the managed overlay, not its preserved stock prefix.
			if bytes.Equal(bad, raw) {
				t.Fatal("bad mutation did not apply")
			}
			if _, err := NFQWSFirstStartEffectiveConfig(bad, owner); err == nil {
				t.Fatal("accepted drift")
			}
		}
	}
	if _, err := NFQWSFirstStartConfigForRecipe(stock, owner, []string{"selected.example"}, nil, nil, "foreign"); err == nil {
		t.Fatal("accepted unknown recipe")
	}
}

func TestNFQWSFirstStartV2RejectsUnknownOrForgedRecipeMarker(t *testing.T) {
	const owner = "0123456789abcdef01234567"
	raw, err := NFQWSFirstStartConfigForRecipe(firstStartStock(t), owner, []string{"selected.example"}, nil, nil, NFQWSFirstStartStockTLSCircular)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte("# RAZVILKA RECIPE stock-tls-circular-v1"), []byte("# RAZVILKA RECIPE unknown"), 1),
		bytes.Replace(raw, []byte(NFQWSFirstStartFormatV2), []byte(NFQWSFirstStartFormat), 1),
		bytes.Replace(raw, []byte("# RAZVILKA RECIPE stock-tls-circular-v1\n"), nil, 1),
	} {
		if _, err := NFQWSFirstStartEffectiveConfig(bad, owner); err == nil {
			t.Fatal("accepted forged version/recipe")
		}
	}
}

func TestNFQWSFirstStartStockAutoChangesOnlyModeAndRecipeIdentity(t *testing.T) {
	const owner = "0123456789abcdef01234567"
	stock := firstStartStock(t)
	compile := func(recipe NFQWSFirstStartRecipe) []byte {
		t.Helper()
		raw, err := NFQWSFirstStartConfigForRecipe(stock, owner, []string{"selected.example"}, []string{"bank.example"}, []string{"192.0.2.0/24"}, recipe)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	old := compile(NFQWSFirstStartStockTLSCircular)
	// Freeze the existing circular overlay separately from its stock prefix.
	block := old[bytes.Index(old, []byte(ManagedListBegin)):]
	if got := fmt.Sprintf("%x", sha256.Sum256(block)); got != "40956d57d7a1f739d00668ff154f47b51639718fe512ed340166c596d921d7d9" {
		t.Fatal("existing circular bytes changed", got)
	}
	auto := compile(NFQWSFirstStartStockTLSCircularAuto)
	start := bytes.Index(auto, []byte(ManagedListBegin))
	expected := append(slices.Clone(old[:start]), bytes.Replace(old[start:], []byte("# RAZVILKA RECIPE stock-tls-circular-v1\n"), []byte("# RAZVILKA RECIPE stock-tls-circular-auto-v1\n"), 1)...)
	expected = append(slices.Clone(expected[:start]), bytes.Replace(expected[start:], []byte("--fastpath-workaround=0"), []byte("--fastpath-workaround=auto"), 1)...)
	if !bytes.Equal(auto, expected) {
		t.Fatal("auto changed scope, strategies, assets or other flags")
	}
	for _, forged := range [][]byte{
		append(slices.Clone(old[:start]), bytes.Replace(old[start:], []byte("--fastpath-workaround=0"), []byte("--fastpath-workaround=auto"), 1)...),
		append(slices.Clone(auto[:start]), bytes.Replace(auto[start:], []byte("--fastpath-workaround=auto"), []byte("--fastpath-workaround=0"), 1)...),
		append(slices.Clone(auto[:start]), bytes.Replace(auto[start:], []byte("--fastpath-workaround=auto"), []byte("--fastpath-workaround=1"), 1)...),
		bytes.Replace(auto, []byte("# RAZVILKA RECIPE stock-tls-circular-auto-v1"), []byte("# RAZVILKA RECIPE stock-tls-circular-auto-v2"), 1),
	} {
		if _, err := NFQWSFirstStartEffectiveConfig(forged, owner); err == nil {
			t.Fatal("accepted forged mode/identity")
		}
	}
}

func TestNFQWSFirstStartCircularObserverEnvelopeKeepsMutatorsClosed(t *testing.T) {
	const owner = "0123456789abcdef01234567"
	stock := firstStartStock(t)
	raw, err := NFQWSFirstStartConfigForRecipe(stock, owner, []string{"selected.example"}, []string{"bank.example"}, []string{"192.0.2.0/24"}, NFQWSFirstStartStockTLSCircularObserveAuto)
	if err != nil {
		t.Fatal(err)
	}
	main, err := NFQWSFirstStartEffectiveConfig(raw, owner)
	if err != nil {
		t.Fatal(err)
	}
	args, err := NFQWSStartupArguments(main, nil)
	if err != nil {
		t.Fatal(err)
	}
	// nfqws2 setters affect following Lua instances. Only the observer may see
	// bounded replies/other payloads; every stock mutator inherits the closed
	// outgoing ClientHello envelope, under the same selected/excluded hostlists.
	incoming, payload := "x", "all"
	count := 0
	for _, arg := range args {
		if strings.HasPrefix(arg, "--in-range=") {
			incoming = strings.TrimPrefix(arg, "--in-range=")
		}
		if strings.HasPrefix(arg, "--payload=") {
			payload = strings.TrimPrefix(arg, "--payload=")
		}
		if strings.HasPrefix(arg, "--lua-desync=") {
			count++
			if strings.HasPrefix(arg, "--lua-desync=circular:") {
				if incoming != "-s5556" || payload != "all" || count != 1 {
					t.Fatal("observer is blind or unbounded", incoming, payload)
				}
			} else if incoming != "x" || payload != "tls_client_hello" {
				t.Fatal("mutator widened to replies or other payloads", arg)
			}
		}
	}
	if count != 7 {
		t.Fatal("stock three-strategy chain changed", count)
	}
	old, err := NFQWSFirstStartConfigForRecipe(stock, owner, []string{"selected.example"}, []string{"bank.example"}, []string{"192.0.2.0/24"}, NFQWSFirstStartStockTLSCircularAuto)
	if err != nil {
		t.Fatal(err)
	}
	expected := bytes.Replace(old, []byte("# RAZVILKA RECIPE "+string(NFQWSFirstStartStockTLSCircularAuto)), []byte("# RAZVILKA RECIPE "+string(NFQWSFirstStartStockTLSCircularObserveAuto)), 1)
	expected = bytes.Replace(expected, []byte(nfqwsFirstStartStockTLSCircularArgs), []byte(nfqwsFirstStartStockTLSCircularObserveArgs), 1)
	if !bytes.Equal(raw, expected) {
		t.Fatal("new recipe changed anything beyond identity and observation envelope")
	}
	for _, change := range [][2]string{{"--in-range=-s5556", "--in-range=a"}, {"--in-range=x --payload=tls_client_hello", "--in-range=a --payload=tls_client_hello"}, {"--payload=all --lua-desync=circular", "--payload=tls_client_hello --lua-desync=circular"}, {"--filter-tcp=443", "--filter-tcp=443,8443"}, {"--filter-l7=tls", "--filter-l7=tls,http"}} {
		start := bytes.Index(raw, []byte(ManagedListBegin))
		forged := append(slices.Clone(raw[:start]), bytes.Replace(raw[start:], []byte(change[0]), []byte(change[1]), 1)...)
		if _, err := NFQWSFirstStartEffectiveConfig(forged, owner); err == nil {
			t.Fatal("forged observer/scope accepted", change)
		}
	}
}
