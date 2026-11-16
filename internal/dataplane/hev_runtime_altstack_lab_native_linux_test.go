//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

// A separately named LAB test. No override of the official ELF admission in
// TestHEVStartupDiagnosticPopulation or any production/native route exists.
// Inputs are the complete verified build package, never an env-supplied hash.
func TestHEVRuntimeAltstackLabPopulation(t *testing.T) {
	manifestPath := os.Getenv("RAZVILKA_HEV_ALTSTACK_LAB_MANIFEST")
	if manifestPath == "" {
		t.Skip("explicit separate source-build lab only")
	}
	if !filepath.IsAbs(manifestPath) || os.Geteuid() != 0 || os.Getpid() != 1 {
		t.Fatal("private lab namespace required")
	}
	for _, pair := range [][2]string{{"/proc/self/ns/net", "/proc/self/fd/8"}, {"/proc/self/ns/mnt", "/proc/self/fd/9"}} {
		a, e1 := os.Stat(pair[0])
		b, e2 := os.Stat(pair[1])
		if e1 != nil || e2 != nil || os.SameFile(a, b) {
			t.Fatal("outer namespace retained")
		}
	}
	root := filepath.Dir(manifestPath)
	read := func(name string, limit int64) []byte {
		t.Helper()
		f, e := os.Open(filepath.Join(root, name))
		if e != nil {
			t.Fatal("lab package member unavailable")
		}
		defer f.Close()
		data, e := io.ReadAll(io.LimitReader(f, limit+1))
		if e != nil || int64(len(data)) > limit {
			t.Fatal("bounded lab package member")
		}
		return data
	}
	var manifest struct {
		Schema     int               `json:"schema"`
		Purpose    string            `json:"purpose"`
		Commit     string            `json:"hev_commit"`
		TaskCommit string            `json:"task_commit"`
		Official   string            `json:"official_binary_sha256"`
		Toolchain  string            `json:"toolchain_release"`
		Compiler   string            `json:"compiler"`
		BuildFlags []string          `json:"build_flags"`
		Artifacts  map[string]string `json:"artifacts"`
		Licenses   []struct {
			Path          string `json:"path"`
			SHA256        string `json:"sha256"`
			SymlinkTarget string `json:"symlink_target,omitempty"`
		} `json:"licenses"`
		FaultTests string `json:"fault_tests"`
		RouteClaim bool   `json:"route_or_router_acceptance"`
	}
	decoder := json.NewDecoder(bytes.NewReader(read(filepath.Base(manifestPath), 1<<20)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Schema != 1 || manifest.Commit != "9a06bc6e7989da54e3d32ff701ef7a7ce4995d3a" || manifest.TaskCommit != "328f35d903221b51811b3d02b277d665dfbdc75f" || manifest.Toolchain != "20260515" || manifest.Official != "a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03" || manifest.FaultTests != "PASS" || manifest.RouteClaim || len(manifest.Artifacts) != 7 || len(manifest.Licenses) == 0 {
		t.Fatal("exact separate lab manifest required")
	}
	// Bind inputs to the reviewed immutable sources, not arbitrary prebuilt
	// files/hashes. Binary hashes bind the outputs of this exact CI build.
	if manifest.Artifacts["hev-socks5-tunnel-2.17.1.tar.xz"] != "a7b86050091c5a268d81de70b95d3bb0871ba4136160662b6496596761c2f9a7" || manifest.Artifacts["x86_64-unknown-linux-musl.tar.xz"] != "5f20e367608d6e547c04534d37d00ecedbaa0c2e82730df12957b3332fa36a2d" {
		t.Fatal("source/toolchain pins changed")
	}
	if manifest.Artifacts["hev-runtime-altstack.patch"] != "30dcee28f54a82305dd2da9b0b640a0dc54550d865bc2cf86cdafb404b7e7984" || manifest.Artifacts["hev-runtime-altstack-fault-test.c"] != "12d333a6eef43b1fa8f50f08c7a27e3a621ee051b8d92e2ca107db38028a4143" {
		t.Fatal("reviewed patch/fault contract changed")
	}
	for _, name := range []string{"hev-socks5-tunnel-2.17.1.tar.xz", "x86_64-unknown-linux-musl.tar.xz", "hev-runtime-altstack.patch", "hev-runtime-altstack-fault-test.c", "bin/hev-original", "bin/hev-patched", "bin/altstack-fault.test"} {
		f, e := os.Open(filepath.Join(root, name))
		if e != nil {
			t.Fatal("missing exact build input/output")
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, 100<<20))
		_ = f.Close()
		if e != nil || n >= 100<<20 || hex.EncodeToString(h.Sum(nil)) != manifest.Artifacts[name] {
			t.Fatal("build member hash drift")
		}
	}
	if string(read("fault-tests.txt", 1024)) != "HEV_RUNTIME_ALTSTACK_FAULT_CONTRACT_PASS\n" {
		t.Fatal("actual fault contract report required")
	}
	auxFile, e := os.Open("/proc/self/auxv")
	if e != nil {
		t.Fatal("actual auxv unavailable")
	}
	aux, e := io.ReadAll(io.LimitReader(auxFile, 4097))
	_ = auxFile.Close()
	if e != nil || len(aux) > 4096 || len(aux)%16 != 0 {
		t.Fatal("actual auxv unavailable")
	}
	var minimum uint64
	for i := 0; i < len(aux); i += 16 {
		if binary.LittleEndian.Uint64(aux[i:]) == 51 {
			minimum = binary.LittleEndian.Uint64(aux[i+8:])
			break
		}
	}
	clear(aux)
	if minimum == 0 || minimum > 1<<20 {
		t.Fatal("actual bounded AT_MINSIGSTKSZ required")
	}
	// Exact official musl disassembly: minimum=max(AT_MIN,1024)+1024.
	expectedOriginalFailure := max(minimum, 1024)+1024 > 8192
	t.Logf("hev_altstack_lab_platform at_minsigstksz_bytes=%d original_compatibility_failure_expected=%t production_pin_unchanged=true", minimum, expectedOriginalFailure)
	profile, e := backendprofile.HevJSON(backendprofile.HevOptions{Interface: hevStartupDiagnosticInterface, Address: "172.27.29.1/30", SOCKSPort: 1080, MTU: 1500, MaxSessions: 128})
	if e != nil {
		t.Fatal("managed profile")
	}
	defer clear(profile)
	tracer, e := exec.LookPath("strace")
	if e != nil {
		t.Fatal("trace diagnostic required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	for _, side := range []string{"original", "patched"} {
		path := filepath.Join(root, "bin", "hev-"+side)
		file, e := os.Open(path)
		if e != nil {
			t.Fatal("source build ELF")
		}
		for _, mode := range []string{"untraced", "traced-diagnostic"} {
			for sample := 0; sample < 8; sample++ {
				row, e := hevStartupDiagnosticSample(ctx, path, file, profile, tracer, mode, sample, t.TempDir())
				encoded, _ := json.Marshal(struct {
					Side string `json:"lab_side"`
					hevStartupDiagnosticResult
				}{side, row})
				t.Logf("hev_altstack_lab_sample %s", encoded)
				if e != nil {
					file.Close()
					t.Fatal("source build setup/cleanup failed")
				}
				if mode == "traced-diagnostic" && (row.Trace.Truncated || len(row.Trace.Calls) == 0 || row.Trace.AltstackUnparsed != 0) {
					t.Error("closed diagnostic trace incomplete")
				}
				if side == "original" && expectedOriginalFailure {
					if !row.Cleanup || !row.ExitedBeforeStop || row.TunObserved || row.ExitCode != 254 || row.Signal != 0 || row.ForcedKill || row.OutputBytes != 0 {
						t.Error("known source-baseline failure differs; never suppress an unrelated failure")
					}
					if mode == "traced-diagnostic" && (row.Trace.Calls["sigaltstack"] != 0 || len(row.Trace.Failures) != 0 || row.Trace.Calls["epoll_create1"] != 1 || row.Trace.ReadBytes != int64(len(profile)) || row.Trace.Unparsed != 0) {
						t.Error("expected userspace guard lacks exact closed initialization evidence")
					}
				} else {
					if !row.Cleanup || !row.TunObserved || row.ExitedBeforeStop || row.ExitCode != 0 || row.Signal != 0 || row.ForcedKill {
						t.Error("source build startup/stop failure retained")
					}
					if side == "patched" && mode == "traced-diagnostic" {
						if len(row.Trace.AltstackRequestBytes) == 0 || row.Trace.AltstackRequestBytes[0] < minimum+8192 {
							t.Error("runtime stack request does not retain userspace headroom")
						}
					}
				}
			}
		}
		if e := file.Close(); e != nil {
			t.Fatal("source build ELF close")
		}
	}
	// Completion is not success; workflow must also preserve Go exit status.
	t.Log("HEV_RUNTIME_ALTSTACK_LAB_POPULATIONS_COMPLETE original failures retained by exact expected condition; no route/router readiness claim")
}
