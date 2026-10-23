package engineconfig

import (
	"bytes"
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
	for _, recipe := range []NFQWSFirstStartRecipe{"", NFQWSFirstStartStockTLSCircular} {
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
		for _, want := range []string{"--filter-tcp=443", "--filter-l7=tls", "--payload=tls_client_hello", "--hostlist-domains=selected.example", "--hostlist-exclude-domains=bank.example", "--ipset-exclude-ip=192.0.2.0/24", "--fastpath-workaround=0", "--ipcache-hostname=0"} {
			if !slices.Contains(args, want) {
				t.Fatal("missing closed constraint", want)
			}
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
