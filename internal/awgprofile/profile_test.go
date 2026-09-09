package awgprofile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func profileText(extra string) string {
	return "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))) + "\nAddress = 10.8.0.2/32\n" + extra + "\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))) + "\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
}
func advanced() string {
	return "S1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nHeaderProtectionKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32))) + "\nRandomTrailers = on\nDisableCookies = off\nRekeyAfterTime = 100-130\nI1 = <b 0x01020304><r 20>\n"
}
func TestProfiles(t *testing.T) {
	for _, tc := range []struct{ name, extra, want string }{{"plain", "", "wg"}, {"v1", "H1 = 10\nH2 = 20\nH3 = 30\nH4 = 40", "awg1.0"}, {"cps", "I1 = <b 0xabcd><t><rc 2><rd 3>", "awg1.5"}, {"v2", "H1 = 10-20\nS3 = 0\nS4 = 0", "awg2.0"}, {"v31", advanced(), "awg3.1"}} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := Parse(profileText(tc.extra))
			if e != nil || p.Public().Version != tc.want {
				t.Fatalf("version=%s err=%v", p.Public().Version, e)
			}
			again, e := Parse(p.Config())
			if e != nil || again.Config() != p.Config() || again.Public().SHA256 != p.Public().SHA256 {
				t.Fatal("round trip", e)
			}
			if !strings.Contains(p.Config(), "Table = off") {
				t.Fatal("routing authority not stripped")
			}
		})
	}
}
func TestRejectBeforeAnyExecution(t *testing.T) {
	cases := []string{"PostUp = curl attacker.invalid", "SaveConfig = true", "Jmin = 100\nJmax = 10", "Jc = 3\nJmin = 0\nJmax = 2", "H1 = 5-9\nH2 = 8-10", "H1 = 4294967296", "S1 = 65536", "I1 = <r -1>", "I1 = <rc -1>", "I1 = <rd -5>", "I1 = <b 0x1>", "I1 = <r 1001>", "I1 = <t><t>", "I1 = <x 23>", "I1 = <r 1000><r 1000><r 1000><r 1000><r 1000>", "i1 = <r 2>", "RandomTrailers = maybe", "RekeyTimeout = 10-3", "RekeyTimeout = 65536", "HeaderProtectionKey = not-a-key", strings.Replace(advanced(), "S4 = 12", "S4 = 11", 1), strings.Replace(advanced(), "S4 = 12\n", "", 1), "MTU = 1", "S1 = 1\nS1 = 2", "Extra = hello"}
	for _, extra := range cases {
		t.Run(extra[:min(22, len(extra))], func(t *testing.T) {
			if _, e := Parse(profileText(extra)); e == nil {
				t.Fatalf("accepted invalid profile")
			}
		})
	}
}
func TestSecretRedactionAndDetachedView(t *testing.T) {
	p, e := Parse(profileText(advanced()))
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(p)
	printed := fmt.Sprintf("%v %+v %#v %s %q", p, p, p, p, p)
	for _, secret := range []string{strings.Repeat("YWFh", 5), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))} {
		if strings.Contains(string(data)+printed, secret) {
			t.Fatal("secret in normal serialization")
		}
	}
	view := p.Public()
	view.RequiredFeatures[0] = "mutated"
	if p.Public().RequiredFeatures[0] == "mutated" {
		t.Fatal("not detached")
	}
}
func TestFlagsCanonicalAndServerNotGenerated(t *testing.T) {
	s := strings.Replace(advanced(), "RandomTrailers = on", "RandomTrailers = true", 1)
	p, e := Parse(profileText(s))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(p.Config(), "RandomTrailers = on") || !p.Public().RandomTrailers {
		t.Fatal("flag not canonical")
	}
	if p.Public().Verification != "syntax-only" {
		t.Fatal("fake network proof")
	}
}
func TestEndpointAndLimits(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:5", "10.0.0.1:50", "[fe80::1%eth3]:40", "[::1]:50", "vpn.example.com:0", "user@vpn.example.com:5", "router.local:6"} {
		if _, e := Parse(strings.Replace(profileText(""), "vpn.example.com:51820", endpoint, 1)); e == nil {
			t.Errorf("accepted endpoint %s", endpoint)
		}
	}
	if _, e := Parse(profileText("") + "\n[Peer]\n"); e == nil {
		t.Fatal("multiple peers accepted")
	}
	if _, e := Parse(strings.Repeat(" ", MaxBytes+1)); e == nil {
		t.Fatal("size")
	}
}
func TestCapabilityGate(t *testing.T) {
	p, e := Parse(profileText(advanced()))
	if e != nil {
		t.Fatal(e)
	}
	good := Capabilities{Backend: "kernel", ModuleLoaded: true, LoadedModuleVersion: "3.1.20260906", ToolPath: "/opt/sbin/awg", ToolVersion: "amneziawg-tools v3.1.20260812"}
	if got := Check(p.Public(), good); len(got) != 0 {
		t.Fatal(got)
	}
	for _, mut := range []func(*Capabilities){func(c *Capabilities) { c.LoadedModuleVersion = "3.0.20260805" }, func(c *Capabilities) { c.ToolVersion = "wireguard-tools v1.0.0" }, func(c *Capabilities) { c.ModuleLoaded = false }, func(c *Capabilities) { c.Backend = "nativewg" }, func(c *Capabilities) { c.ToolPath = "" }} {
		c := good
		mut(&c)
		if len(Check(p.Public(), c)) == 0 {
			t.Fatal("unsupported accepted")
		}
	}
}
func FuzzParse(f *testing.F) {
	f.Add(profileText(advanced()))
	f.Add("[Interface]\nI1 = <r -1>")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > MaxBytes+1 {
			return
		}
		p, e := Parse(s)
		if e == nil {
			again, e := Parse(p.Config())
			if e != nil || again.Config() != p.Config() {
				t.Fatal("noncanonical")
			}
			b, _ := json.Marshal(p)
			if strings.Contains(string(b), "PrivateKey") {
				t.Fatal("secret field exposed")
			}
		}
	})
}
