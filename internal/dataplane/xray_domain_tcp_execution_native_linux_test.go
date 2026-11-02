//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Actual Xray, inherited authored config/executable FDs and kernel observations.
// Process admission/read interval here is an explicit model: this is not proof
// of the complete DNS-source factory, Manager Apply or router/LAN routing.
func TestXrayDomainTCPNativeHeldProcessLifecycle(t *testing.T) {
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if binary == "" {
		t.Skip("isolated actual Xray binary required")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute Xray binary required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	listener.Close()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	doc := map[string]any{"log": map[string]any{"loglevel": "error"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": endpoint.Port(), "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{map[string]any{"protocol": "blackhole"}}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	config, err := root.WriteAtomicRetained(xrayDomainTCPConfigName, data, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	info, _ := config.Stat()
	exe, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer exe.Close()
	exeInfo, _ := exe.Stat()
	exeData, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(exeData)
	sha := hex.EncodeToString(hash[:])
	anchor, _ := root.RootInfo()
	if _, err := config.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	cmd := &exec.Cmd{Path: "/proc/self/fd/3", Args: []string{binary, "run", "-format", "json", "-config", "stdin:"}, Dir: path, Env: xraySelectedTCPNativeEnvironment(), ExtraFiles: []*os.File{exe, config}, Stdin: config, SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}
	nativeLog, err := root.OpenFile("native-fixture.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer nativeLog.Close()
	cmd.Stdout = nativeLog
	cmd.Stderr = nativeLog
	child, err := reserveXraySelectedTCPProcessWait(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		child.abandonUnstartedWait()
		t.Fatal(err)
	}
	defer func() {
		if child.child == nil {
			cmd.Process.Kill()
			cmd.Wait()
			return
		}
		if !child.waitStarted {
			_ = child.beginReservedWait()
		}
		child.child.Signal(syscall.SIGTERM)
		cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := child.Joined(cleanup); err != nil {
			child.child.Kill()
			child.Joined(cleanup)
			t.Error(err)
		}
	}()
	if err := child.acknowledgeStart(); err != nil {
		t.Fatal(err)
	}
	scope := &executionResourceScope{networkIdentity: &networkPolicyIdentity{value: identity, provider: provider}}
	material := &XrayDomainTCPOperationMaterial{}
	material.self = material
	r := &XrayDomainTCPExecutionResource{scope: scope, material: material, child: child, root: root, rootPath: path, anchor: anchor, config: config, configInfo: info, executable: &xrayDomainTCPExecutable{file: exe, info: exeInfo, path: binary, sha256: sha}, definition: ExecutionXrayDomainTCPDefinition{ConfigSHA256: nodeDefaultSourceMaterialHash(data), NetworkIdentity: identity, PrivateEndpoint: endpoint}}
	r.self = r
	material.resource = r
	marker := &xrayDomainTCPProcessRead{resource: r, process: child}
	marker.self = marker
	marker.open.Store(true)
	read := context.WithValue(context.WithValue(ctx, syntheticExecutionRegistrarKey{}, scope), xrayDomainTCPProcessReadKey{}, marker)
	opening, err := r.observeDomainProcess(read)
	if err != nil {
		domainNativeProcessDiagnostics(t, r, read)
		// This fixture contains only a blackhole outbound, no imported secrets.
		output, _ := root.ReadLimited("native-fixture.log", 8192)
		t.Log("actual blackhole Xray output", string(output))
		t.Fatal("actual inherited process/config association", err)
	}
	if err := child.beginReservedWait(); err != nil {
		t.Fatal(err)
	}
	var observed xraySelectedTCPListenerObservation
	for {
		observed, err = r.observeDomainListener(read)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(err)
		case <-child.done:
			t.Fatal("actual Xray exited before listener")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if !opening.same(observed.process) || observed.inode == 0 || observed.endpoint != endpoint {
		t.Fatal("listener is not original child")
	}
	// An actual occupied loopback address cannot disappear behind a saved
	// baseline or a merely present pool. Only a genuine successor witness may
	// attribute it, and this explicit admission model has no such issuer.
	scope.manager = New(t.TempDir())
	if err := r.observeRetainedDomainListener(ctx); err == nil {
		t.Fatal("unowned actual listener accepted without successor")
	}
	pool := &domainTCPStandbyPool{manager: scope.manager}
	pool.self = pool
	scope.manager.domainPool = pool
	cursor := &domainTCPGlobalSuccessor{pool: pool}
	cursor.self = cursor
	pool.successor = cursor
	if err := r.observeRetainedDomainListener(ctx); err == nil {
		t.Fatal("empty cursor hid actual listener")
	}
	marker.open.Store(false)
	if _, err := r.observeDomainListener(read); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("closed interval accepted", err)
	}
	marker.open.Store(true)
	if err := root.WriteAtomic(xrayDomainTCPConfigName, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.observeDomainProcess(read); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("same-byte replacement adopted", err)
	}
	child.child.Signal(syscall.SIGTERM)
	if err := child.Joined(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.observeDomainListenerAbsent(ctx); err != nil {
		t.Fatal("listener survived actual Wait", err)
	}
	if endpoint.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("test escaped loopback")
	}
}

// Read-only stage diagnostics for actual native acceptance failures. The
// output contains only association booleans/errors, never config or node data.
func domainNativeProcessDiagnostics(t *testing.T, r *XrayDomainTCPExecutionResource, ctx context.Context) {
	t.Helper()
	t.Log("native source files/current", r.filesCurrent(ctx), r.domainProcessCurrent(ctx))
	if r.child == nil {
		return
	}
	proc, err := openXraySelectedTCPProc(ctx, r.child.pid)
	if err != nil {
		t.Log("native proc open", err)
		return
	}
	defer proc.close()
	stat, statErr := proc.read(ctx, proc.child, "stat", 8192)
	_, parent, group, parseErr := xraySelectedTCPStat(stat, r.child.pid)
	t.Log("native stat", statErr, parseErr, "parent matches", parent == r.child.parent, "group matches", group == r.child.pid)
	if parseErr != nil {
		t.Logf("native stat kernel shape %q", stat)
	}
	image, imageErr := proc.domainKernelImage(ctx, r.definition.NetworkIdentity)
	t.Log("native image", imageErr, "path matches", image.exe == r.executable.path, "inode matches", sameXrayDomainTCPFile(r.executable.info, image.executable), "argv matches", image.matches(r.child.image.args, r.executable.path, r.executable.info))
	t.Log("native config FD", r.readDomainConfigFD(ctx, proc))
}
