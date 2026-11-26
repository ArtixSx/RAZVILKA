package engineconfig

import (
	"slices"
	"strings"
	"testing"
)

const nativeNFQWSConfig = `USER=nobody
NFQUEUE_NUM=300
ISP_INTERFACE="eth3"
NFQWS_BASE_ARGS="--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua --fastpath-workaround=0"
NFQWS_ARGS="--filter-tcp=443 --filter-l7=tls --lua-desync=multisplit:pos=1,midsld"
NFQWS_ARGS_UDP="--filter-udp=50000-65535 --lua-desync=fake"
NFQWS_ARGS_QUIC="--filter-udp=443 --lua-desync=fake"
MODE_LIST="--hostlist=/opt/etc/nfqws2/lists/user.list"
NFQWS_EXTRA_ARGS="$MODE_LIST --hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list"
NFQWS_ARGS_IPSET="--ipset=/opt/etc/nfqws2/lists/ipset.list"
NFQWS_ARGS_CUSTOM="--hostlist-domains=owner.example"
`

func TestNFQWSStartupArgumentsMirrorDistinctStockBranches(t *testing.T) {
	got, err := NFQWSStartupArguments(nativeNFQWSConfig, []string{"--hostlist-domains=excluded.example"})
	if err != nil {
		t.Fatal(err)
	}
	profiles := strings.Split(strings.Join(got, " "), " --new ")
	if len(profiles) != 7 {
		t.Fatalf("profiles=%v", profiles)
	}
	if !strings.Contains(profiles[0], "--hostlist-domains=excluded.example") || profiles[1] != "--hostlist-domains=owner.example" {
		t.Fatal(profiles)
	}
	if strings.Contains(profiles[2], "--hostlist") || !strings.Contains(profiles[2], "--filter-udp=50000-65535") {
		t.Fatal("stock UDP must not be misrepresented as hostlist-restricted", profiles)
	}
	if !strings.Contains(profiles[3], "--ipset-ip=0.0.0.0") || !strings.Contains(profiles[4], "--hostlist=") || !strings.Contains(profiles[5], "--ipset-ip=0.0.0.0") || !strings.Contains(profiles[6], "--hostlist=") {
		t.Fatal(profiles)
	}
}

func TestNFQWSStartupArgumentsClosedSingleProfileAndRefusals(t *testing.T) {
	closed := strings.ReplaceAll(nativeNFQWSConfig, `NFQWS_ARGS_UDP="--filter-udp=50000-65535 --lua-desync=fake"`, `NFQWS_ARGS_UDP=""`)
	closed = strings.ReplaceAll(closed, `NFQWS_ARGS_QUIC="--filter-udp=443 --lua-desync=fake"`, `NFQWS_ARGS_QUIC=""`)
	closed = strings.ReplaceAll(closed, `NFQWS_ARGS_IPSET="--ipset=/opt/etc/nfqws2/lists/ipset.list"`, `NFQWS_ARGS_IPSET=""`)
	closed = strings.ReplaceAll(closed, `NFQWS_ARGS_CUSTOM="--hostlist-domains=owner.example"`, `NFQWS_ARGS_CUSTOM=""`)
	args, err := NFQWSStartupArguments(closed, nil)
	if err != nil || slices.Contains(args, "--new") || strings.Contains(strings.Join(args, " "), "--filter-udp") || !slices.Contains(args, "--hostlist=/opt/etc/nfqws2/lists/user.list") {
		t.Fatal(args, err)
	}
	for _, change := range []string{"\ntouch /tmp/foreign\n", "\nUSER=root\n", "\nOTHER=\"$(touch /tmp/foreign)\"\n", "\nOTHER=\"$UNDEFINED\"\n", "\nNFQWS_ARGS_CUSTOM=\"--daemon\"\n", "\nNFQWS_BIN=/tmp/foreign\n", "\nPATH=/tmp\n"} {
		if _, err := NFQWSStartupArguments(closed+change, nil); err == nil {
			t.Fatalf("accepted %q", change)
		}
	}
	if _, err := NFQWSStartupArguments(strings.Replace(closed, "--filter-tcp=443", "--filter-tcp=443 --new", 1), nil); err == nil {
		t.Fatal("init-refused embedded profile delimiter accepted")
	}
	if _, err := NFQWSStartupArguments(strings.Replace(closed, "--filter-tcp=443", "--hostlist=/tmp/list*", 1), nil); err == nil {
		t.Fatal("shell pathname expansion accepted")
	}
}

func TestNFQWSRunningConfigMatchesOnlyGeneratedCurrentArguments(t *testing.T) {
	running := "ISP_INTERFACE=eth3\nNFQUEUE_NUM=300\nPOLICY_MARK=0x100/0xff\nTCP_PORTS=443\nUDP_PORTS=443\n"
	if err := NFQWSRunningConfigMatches(nativeNFQWSConfig, running); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"NFQUEUE_NUM=301\n", "ISP_INTERFACE=eth4\n", "NFQWS_ARGS=\"--filter-tcp=80\"\n", "FOREIGN=1\n", "POLICY_NAME=\"$(touch /tmp/x)\"\n"} {
		if err := NFQWSRunningConfigMatches(nativeNFQWSConfig, value); err == nil {
			t.Fatalf("accepted unreviewed runtime overlay %q", value)
		}
	}
}
