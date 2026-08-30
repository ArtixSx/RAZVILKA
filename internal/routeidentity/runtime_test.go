package routeidentity

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

type runtimeFixture struct {
	files                          map[string][]byte
	links                          map[string]string
	proc                           procReader
	root, config, binary, endpoint string
	args                           []string
}

func newRuntimeFixture(t *testing.T) *runtimeFixture {
	t.Helper()
	f := &runtimeFixture{files: map[string][]byte{}, links: map[string]string{}, root: filepath.Join(t.TempDir(), "runtime"), binary: "/opt/bin/sing-box", endpoint: "127.0.0.1:18081"}
	f.config = filepath.Join(f.root, "engine.json")
	f.args = []string{"run", "-c", f.config}
	f.files[f.config] = []byte(`{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":18081}],"outbounds":[{"type":"vless","server":"node.example","server_port":443,"uuid":"PRIVATE-SECRET"}]}`)
	f.files["/proc/sys/kernel/random/boot_id"] = []byte("boot-a\n")
	f.files["/proc/42/stat"] = []byte("42 (a name ) with spaces) S " + strings.Repeat("0 ", 18) + "12345 0 0\n")
	f.files["/proc/42/cmdline"] = []byte(strings.Join(append([]string{f.binary}, f.args...), "\x00") + "\x00")
	f.links["/proc/42/exe"] = f.binary
	f.links["/proc/42/ns/net"] = "net:[77]"
	f.links["/proc/self/ns/net"] = "net:[77]"
	f.links["/proc/42/fd/5"] = "socket:[900]"
	f.files["/proc/42/net/tcp"] = []byte(fmt.Sprintf("sl local_address rem_address st\n0: %08X:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 900\n", binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}), 18081))
	f.files[filepath.Join(f.root, "engine.pid")] = []byte("42\n")
	f.proc = procReader{
		readFile: func(p string) ([]byte, error) {
			if b, ok := f.files[p]; ok {
				return b, nil
			}
			return nil, os.ErrNotExist
		},
		readLink: func(p string) (string, error) {
			if b, ok := f.links[p]; ok {
				return b, nil
			}
			return "", os.ErrNotExist
		},
		readDir: func(p string) ([]os.DirEntry, error) {
			if p != "/proc/42/fd" {
				return nil, os.ErrNotExist
			}
			return fs.ReadDir(fstest.MapFS{"5": &fstest.MapFile{Mode: 0o600}}, ".")
		},
	}
	f.receipt(t)
	return f
}

func (f *runtimeFixture) receipt(t *testing.T) {
	t.Helper()
	data, err := recordStart(f.proc, 42, f.binary, f.args, f.config, Hash(f.files[f.config]))
	if err != nil {
		t.Fatal(err)
	}
	f.files[filepath.Join(f.root, "engine.pid")+ReceiptSuffix] = data
}

func TestRuntimePassport(t *testing.T) {
	f := newRuntimeFixture(t)
	p, err := verify(f.proc, f.root, "sing-box", f.endpoint)
	if err != nil || p.PID != 42 || p.Outbound != "vless" || p.ID == "" {
		t.Fatalf("passport=%+v err=%v", p, err)
	}
	encoded, _ := json.Marshal(p)
	receipt := f.files[filepath.Join(f.root, "engine.pid")+ReceiptSuffix]
	for _, bytes := range [][]byte{encoded, receipt} {
		if strings.Contains(string(bytes), "PRIVATE-SECRET") || strings.Contains(string(bytes), "node.example") {
			t.Fatal("secret leaked")
		}
	}
	// Restarting the same engine with the same configuration changes identity.
	f.files["/proc/42/stat"] = []byte(strings.ReplaceAll(string(f.files["/proc/42/stat"]), "12345", "54321"))
	f.receipt(t)
	next, err := verify(f.proc, f.root, "sing-box", f.endpoint)
	if err != nil || p.ID == next.ID {
		t.Fatalf("restart identity unchanged: %+v %v", next, err)
	}
}

func TestRuntimePassportRejectsStaleOrUnownedEvidence(t *testing.T) {
	for _, tt := range []struct {
		name, want string
		change     func(*runtimeFixture)
	}{
		{"missing-receipt", "route-receipt-missing", func(f *runtimeFixture) { delete(f.files, filepath.Join(f.root, "engine.pid")+ReceiptSuffix) }},
		{"corrupt-receipt", "route-receipt-missing", func(f *runtimeFixture) { f.files[filepath.Join(f.root, "engine.pid")+ReceiptSuffix] = []byte("bad") }},
		{"invalid-pid", "route-pid-invalid", func(f *runtimeFixture) { f.files[filepath.Join(f.root, "engine.pid")] = []byte("1") }},
		{"config-drift", "route-runtime-changed", func(f *runtimeFixture) { f.files[f.config] = []byte(`{"outbounds":[{"type":"direct"}]}`) }},
		{"boot-changed", "route-runtime-changed", func(f *runtimeFixture) { f.files["/proc/sys/kernel/random/boot_id"] = []byte("boot-b") }},
		{"pid-reused", "route-runtime-changed", func(f *runtimeFixture) {
			f.files["/proc/42/stat"] = []byte(strings.ReplaceAll(string(f.files["/proc/42/stat"]), "12345", "54321"))
		}},
		{"command-drift", "route-runtime-changed", func(f *runtimeFixture) {
			f.files["/proc/42/cmdline"] = []byte("sing-box\x00run\x00-c\x00another.json\x00")
		}},
		{"deleted-executable", "route-runtime-changed", func(f *runtimeFixture) { f.links["/proc/42/exe"] += " (deleted)" }},
		{"other-socket-owner", "route-listener-owner-mismatch", func(f *runtimeFixture) { f.links["/proc/42/fd/5"] = "socket:[901]" }},
		{"other-namespace", "route-network-namespace-mismatch", func(f *runtimeFixture) { f.links["/proc/42/ns/net"] = "net:[88]" }},
		{"not-listening", "route-listener-unavailable", func(f *runtimeFixture) {
			f.files["/proc/42/net/tcp"] = []byte(strings.ReplaceAll(string(f.files["/proc/42/net/tcp"]), " 0A ", " 01 "))
		}},
		{"reused-listen-port", "route-listener-ambiguous", func(f *runtimeFixture) {
			f.files["/proc/42/net/tcp"] = append(f.files["/proc/42/net/tcp"], f.files["/proc/42/net/tcp"]...)
		}},
		{"invalid-stat", "route-process-stat-invalid", func(f *runtimeFixture) { f.files["/proc/42/stat"] = []byte("bad") }},
		{"zombie", "route-process-stat-invalid", func(f *runtimeFixture) {
			f.files["/proc/42/stat"] = []byte(strings.ReplaceAll(string(f.files["/proc/42/stat"]), ") S ", ") Z "))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newRuntimeFixture(t)
			tt.change(f)
			p, err := verify(f.proc, f.root, "sing-box", f.endpoint)
			if err == nil || err.Error() != tt.want || p.ID != "" {
				t.Fatalf("passport=%+v err=%v want=%s", p, err, tt.want)
			}
		})
	}
}

func TestManagedReceiptDoesNotMakeDirectOutboundSafe(t *testing.T) {
	f := newRuntimeFixture(t)
	f.files[f.config] = []byte(`{"outbounds":[{"type":"direct"}]}`)
	f.receipt(t)
	_, err := verify(f.proc, f.root, "sing-box", f.endpoint)
	if err == nil || err.Error() != "route-direct-outbound" {
		t.Fatalf("err=%v", err)
	}
}

func TestRecordStartRejectsChangedConfigAndArguments(t *testing.T) {
	f := newRuntimeFixture(t)
	if _, err := recordStart(f.proc, 42, f.binary, f.args, f.config, Hash([]byte("older"))); err == nil {
		t.Fatal("config changed around exec accepted")
	}
	if _, err := recordStart(f.proc, 42, f.binary, []string{"run", "-c", "other"}, f.config, Hash(f.files[f.config])); err == nil {
		t.Fatal("unexpected argv accepted")
	}
}

func TestManagedArgs(t *testing.T) {
	if !managedArgs("usque", "/runtime/engine.json", "127.0.0.1:18080", []string{"/opt/bin/usque", "-c", "/runtime/engine.json", "socks", "-b", "127.0.0.1", "-p", "18080", "--always-reconnect", "-S", "-s", "example.com", "--http2"}) {
		t.Fatal("managed USQUE arguments rejected")
	}
	if managedArgs("sing-box", "/runtime/engine.json", "127.0.0.1:18081", []string{"sing-box", "run", "-c", "/runtime/engine.json", "-C", "/other"}) {
		t.Fatal("extra config directory accepted")
	}
	if !managedArgs("xray", "/runtime/engine.json", "127.0.0.1:18082", []string{"xray", "run", "-config", "/runtime/engine.json"}) {
		t.Fatal("managed Xray arguments rejected")
	}
}
