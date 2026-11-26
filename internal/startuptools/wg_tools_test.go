package startuptools

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestWGCommandToolsRejectUnissuedOrClosedSource(t *testing.T) {
	for _, l := range []*Lease{nil, {}, unitLease(t)} {
		for _, engine := range []string{"wireguard", "amneziawg", "warp-wg", ""} {
			if _, err := l.WGCommandTools(engine); !errors.Is(err, ErrUnknown) {
				t.Fatal("unissued source produced descriptor", engine, err)
			}
		}
	}
	for _, runner := range []*wgRunner{nil, {}} {
		if _, err := runner.RunWG(context.Background(), nil, "/usr/bin/wg", "show", "all", "public-key"); !errors.Is(err, ErrUnknown) {
			t.Fatal("unissued runner", err)
		}
	}
}

func TestWGNativeABIRejectsBroadToolsAndPrivateReadback(t *testing.T) {
	public := strings.Repeat("A", 43) + "="
	positive := []struct {
		index  int
		engine string
		args   []string
	}{
		{3, "wireguard", []string{"show", "all", "public-key"}},
		{4, "wireguard", []string{"show", "all", "public-key"}},
		{3, "wireguard", []string{"show", "rz-wg", "latest-handshakes"}},
		{3, "wireguard", []string{"setconf", "rz-wg", "/private/rz-wg.setconf"}},
		{4, "amneziawg", []string{"set", "rz-awg", "fwmark", "0x180000"}},
		{3, "wireguard", []string{"set", "rz-wg", "peer", public, "endpoint", "198.51.100.1:51820"}},
		{2, "wireguard", []string{"link", "add", "dev", "rz-wg", "type", "wireguard"}},
		{2, "amneziawg", []string{"link", "add", "dev", "rz-awg", "type", "amneziawg"}},
		{2, "wireguard", []string{"link", "delete", "dev", "rz-wg"}},
		{2, "wireguard", []string{"link", "set", "dev", "rz-wg", "up"}},
		{2, "wireguard", []string{"link", "set", "dev", "rz-wg", "mtu", "1280"}},
		{2, "wireguard", []string{"address", "add", "2001:db8::2/128", "dev", "rz-wg", "noprefixroute", "nodad"}},
		{2, "wireguard", []string{"-4", "-j", "route", "get", "198.51.100.1", "mark", "0"}},
		{2, "wireguard", []string{"-6", "rule", "add", "priority", "21900", "fwmark", "0x180000", "lookup", "219"}},
		{0, "wireguard", []string{"-t", "mangle", "-N", "RZG_test"}},
		{1, "wireguard", []string{"-t", "filter", "-C", "FORWARD", "-j", "RZG_test"}},
	}
	for _, c := range positive {
		if !wgArguments(c.index, c.engine, c.args) {
			t.Fatal("native compiler ABI refused", c)
		}
	}
	negative := []struct {
		index int
		args  []string
	}{
		{3, []string{"showconf", "rz-wg"}}, {3, []string{"show", "rz-wg", "dump"}}, {3, []string{"show", "rz-wg", "private-key"}},
		{3, []string{"setconf", "rz-wg", "relative.conf"}}, {3, []string{"set", "rz-wg", "private-key", "/private/key"}},
		{4, []string{"setconf", "rz-awg", "/private/profile"}}, {3, []string{"set", "all", "fwmark", "0"}},
		{2, []string{"-batch", "/private/commands"}}, {2, []string{"route", "flush", "table", "main"}},
		{2, []string{"link", "add", "dev", "rz-wg", "type", "veth"}}, {2, []string{"link", "set", "dev", "rz-wg", "netns", "other"}},
		{2, []string{"link", "set", "dev", "rz-wg", "mtu", "99999999"}}, {2, []string{"address", "add", "10.0.0.1/32", "dev", "rz-wg", "nodad"}},
		{0, []string{"-t", "filter", "-F"}}, {1, []string{"-t", "filter", "--restore", "/private/rules"}},
	}
	for _, c := range negative {
		if wgArguments(c.index, "wireguard", c.args) {
			t.Fatal("broad ABI admitted", c)
		}
	}
}

func TestWGVersionAndProfileAreHeldSourceComparisons(t *testing.T) {
	for i, good := range []string{"wireguard-tools v1.0.20210914 - https://git.zx2c4.com/wireguard-tools/\n", "amneziawg-tools v3.1.20260812 - https://amnezia.org\n"} {
		if !validWGVersion(i, []byte(good)) || validWGVersion(1-i, []byte(good)) {
			t.Fatal("backend identity", i)
		}
		for _, bad := range []string{strings.TrimSuffix(good, "\n"), good + "\n", good + "fake\n", strings.Repeat("x", 257), "wg 3.1\n"} {
			if validWGVersion(i, []byte(bad)) {
				t.Fatal("ambiguous version", i, bad)
			}
		}
	}
	for _, stock := range []bool{false, true} {
		for _, engine := range []string{"wireguard", "amneziawg"} {
			p := wgProfile(stock, engine)
			if p.ipSHA == "" || p.mainSHA == "" || p.wgEngine != engine || p.loader == "" || len(p.libraries) == 0 {
				t.Fatal("detached tool profile", p.id)
			}
		}
	}
}
