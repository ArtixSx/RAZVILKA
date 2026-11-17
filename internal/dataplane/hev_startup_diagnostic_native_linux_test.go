//go:build linux && amd64 && razvilka_native_fixture

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"golang.org/x/sys/unix"
)

// Standalone diagnostic ONLY: tracing changes ancestry/TracerPid and is never
// used for original route admission, service evidence, or latency acceptance.
// Both populations use the official ELF and the real managed profile generator.
const hevStartupDiagnosticInterface = "rz-hev-diag"
const hevStartupDiagnosticCalls = "open,openat,read,readv,close,dup,dup2,dup3,fcntl,epoll_create,epoll_create1,epoll_ctl,mmap,mremap,munmap,brk,rt_sigaction,sigaltstack,setrlimit,prlimit64,socket,socketpair,ioctl,exit_group,exit,execve,execveat"

type hevStartupDiagnosticBuffer struct {
	mu        sync.Mutex
	data      [64 << 10]byte
	used      int
	truncated bool
}

func (b *hevStartupDiagnosticBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := copy(b.data[b.used:], p)
	b.used += n
	b.truncated = b.truncated || n != len(p)
	return len(p), nil // Always drain; never backpressure after the cap.
}

type hevStartupDiagnosticTrace struct {
	Calls                map[string]int `json:"calls"`
	Failures             map[string]int `json:"failures"`
	ReadBytes            int64          `json:"read_bytes"`
	Unparsed             int            `json:"unparsed_lines"`
	Truncated            bool           `json:"truncated"`
	AltstackRequestBytes []uint64       `json:"altstack_request_bytes"`
	AltstackUnparsed     int            `json:"altstack_unparsed"`
}

var hevStartupDiagnosticLine = regexp.MustCompile(`^(?:[0-9]+\s+)?([a-z0-9_]+)\(.*\)\s+=\s+(.*)$`)

// Only the FIRST argument's requested size is retained. ss_sp, old stack and
// all other decoded values are deliberately absent from exported diagnostics.
var hevStartupDiagnosticAltstack = regexp.MustCompile(`sigaltstack\(\{[^{}]*\bss_size=([0-9]+)(?:\s*,[^{}]*)?\s*\}`)
var hevStartupDiagnosticErrnos = map[string]bool{"EPERM": true, "ENOENT": true, "EINTR": true, "EIO": true, "EBADF": true, "ENOMEM": true, "EACCES": true, "EFAULT": true, "EBUSY": true, "EEXIST": true, "ENODEV": true, "EINVAL": true, "ENFILE": true, "EMFILE": true, "ENOSPC": true, "ENOSYS": true, "EAGAIN": true, "EOPNOTSUPP": true}

func hevStartupDiagnosticParse(raw []byte, truncated bool) hevStartupDiagnosticTrace {
	out := hevStartupDiagnosticTrace{Calls: map[string]int{}, Failures: map[string]int{}, Truncated: truncated}
	allowed := map[string]bool{}
	for _, call := range strings.Split(hevStartupDiagnosticCalls, ",") {
		allowed[call] = true
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		match := hevStartupDiagnosticLine.FindStringSubmatch(line)
		if len(match) != 3 || !allowed[match[1]] {
			out.Unparsed++
			continue
		}
		call := match[1]
		out.Calls[call]++
		if call == "sigaltstack" {
			requested := hevStartupDiagnosticAltstack.FindStringSubmatch(line)
			if len(requested) == 2 {
				size, err := strconv.ParseUint(requested[1], 10, 64)
				if err == nil && size <= 1<<30 && len(out.AltstackRequestBytes) < 8 {
					out.AltstackRequestBytes = append(out.AltstackRequestBytes, size)
				} else {
					out.AltstackUnparsed++
				}
			} else if !strings.Contains(line, "sigaltstack(NULL,") {
				out.AltstackUnparsed++
			}
		}
		fields := strings.Fields(match[2])
		if len(fields) == 0 {
			out.Unparsed++
			continue
		}
		if fields[0] == "-1" {
			code := "unknown"
			if len(fields) > 1 && hevStartupDiagnosticErrnos[fields[1]] {
				code = fields[1]
			}
			out.Failures[call+":"+code]++
		} else if call == "read" || call == "readv" {
			if n, e := strconv.ParseInt(fields[0], 0, 64); e == nil && n >= 0 && n <= 1<<20 {
				out.ReadBytes += n
			}
		}
	}
	return out
}

func TestHEVStartupDiagnosticClosedTrace(t *testing.T) {
	raw := []byte("55 dup(0x2) = 0x6\n55 epoll_create(0x80) = -1 EMFILE (private-path-secret)\n55 read(0x7, 0xdeadbeef, 0x1000) = 0x12\n55 secret_syscall(0) = -1 SECRET\n55 ioctl(0x7, 0x400454ca, 0xcafef00d) = -1 UNKNOWN_SECRET (password)\n55 sigaltstack({ss_sp=0xdeadbeef, ss_flags=0, ss_size=8192}, {ss_sp=0xcafef00d, ss_flags=0, ss_size=9999}) = -1 ENOMEM (private secret)\n")
	r := hevStartupDiagnosticParse(raw, false)
	if r.Calls["dup"] != 1 || r.Failures["epoll_create:EMFILE"] != 1 || r.Failures["ioctl:unknown"] != 1 || r.ReadBytes != 18 || r.Unparsed != 1 {
		t.Fatal("closed trace classification")
	}
	if len(r.AltstackRequestBytes) != 1 || r.AltstackRequestBytes[0] != 8192 || r.AltstackUnparsed != 0 || r.Failures["sigaltstack:ENOMEM"] != 1 {
		t.Fatal("first requested numeric altstack only")
	}
	bad := hevStartupDiagnosticParse([]byte("sigaltstack({ss_sp=0xdeadbeef, ss_size=184467440737095516160}, NULL) = -1 ENOMEM\nsigaltstack({ss_sp=0xdeadbeef, ss_size=0xcafef00d}, NULL) = -1 ENOMEM\nsigaltstack(NULL, {ss_sp=0xdeadbeef, ss_size=9999}) = 0\n"), false)
	if len(bad.AltstackRequestBytes) != 0 || bad.AltstackUnparsed != 2 {
		t.Fatal("untrusted altstack numeric refusal")
	}
	encoded, _ := json.Marshal(r)
	for _, secret := range []string{"private", "secret", "password", "deadbeef", "cafef00d"} {
		if strings.Contains(strings.ToLower(string(encoded)), secret) {
			t.Fatal("raw trace leaked")
		}
	}
	var b hevStartupDiagnosticBuffer
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 32; j++ {
				p := make([]byte, 1024)
				if n, e := b.Write(p); n != len(p) || e != nil {
					t.Error("drain changed")
				}
			}
		}()
	}
	group.Wait()
	if b.used != len(b.data) || !b.truncated {
		t.Fatal("bounded trace capture")
	}
}

type hevStartupDiagnosticResult struct {
	Mode             string                    `json:"mode"`
	Sample           int                       `json:"sample"`
	TunObserved      bool                      `json:"tun_observed"`
	ExitedBeforeStop bool                      `json:"exited_before_stop"`
	ExitCode         int                       `json:"exit_code"`
	Signal           int                       `json:"signal"`
	OutputBytes      int                       `json:"output_bytes_capped"`
	OutputTruncated  bool                      `json:"output_truncated"`
	OutputCategory   string                    `json:"output_category"`
	ForcedKill       bool                      `json:"forced_kill"`
	Cleanup          bool                      `json:"cleanup_verified"`
	Trace            hevStartupDiagnosticTrace `json:"trace"`
}

func TestHEVStartupDiagnosticPopulation(t *testing.T) {
	if os.Getenv("RAZVILKA_HEV_STARTUP_DIAGNOSTIC") != "1" {
		t.Skip("explicit standalone disposable diagnostic only")
	}
	if os.Geteuid() != 0 || os.Getpid() != 1 || os.Getenv("RAZVILKA_HEV_STARTUP_NAMESPACE") != "1" {
		t.Fatal("isolated script required")
	}
	// The script holds original outer namespaces open before unshare. An env
	// variable alone cannot authorize creating a TUN in the host namespace.
	for _, pair := range [][2]string{{"/proc/self/ns/net", "/proc/self/fd/8"}, {"/proc/self/ns/mnt", "/proc/self/fd/9"}} {
		current, e1 := os.Stat(pair[0])
		outer, e2 := os.Stat(pair[1])
		if e1 != nil || e2 != nil || os.SameFile(current, outer) {
			t.Fatal("actual network and mount namespace separation required")
		}
	}
	aux, err := os.Open("/proc/self/auxv")
	if err != nil {
		t.Fatal("numeric aux vector unavailable")
	}
	auxBytes, err := io.ReadAll(io.LimitReader(aux, 4097))
	_ = aux.Close()
	if err != nil || len(auxBytes) > 4096 || len(auxBytes)%16 != 0 {
		t.Fatal("bounded amd64 aux vector")
	}
	var minimumSignalStack uint64
	for offset := 0; offset < len(auxBytes); offset += 16 {
		if binary.LittleEndian.Uint64(auxBytes[offset:]) == 51 {
			minimumSignalStack = binary.LittleEndian.Uint64(auxBytes[offset+8:])
			break
		}
	}
	clear(auxBytes)
	t.Logf("standalone_hev_platform at_minsigstksz_bytes=%d source_stack_detector_enabled=true configured_sigstksz_bytes_unverified=true", minimumSignalStack)
	binary := os.Getenv("RAZVILKA_HEV_NATIVE")
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute official ELF required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal("open official ELF")
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(file, 32<<20))
	if err != nil || size >= 32<<20 || hex.EncodeToString(digest.Sum(nil)) != "a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03" {
		t.Fatal("official HEV2.17.1 identity mismatch")
	}
	profile, err := backendprofile.HevJSON(backendprofile.HevOptions{Interface: hevStartupDiagnosticInterface, Address: "172.27.29.1/30", SOCKSPort: 1080, MTU: 1500, MaxSessions: 128})
	if err != nil {
		t.Fatal("actual managed profile")
	}
	defer clear(profile)
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Fatal("standalone diagnostic requires strace")
	}
	// Fixed populations, never retry-until-pass. Every observed startup failure
	// remains a test failure even if later samples start; cleanup failure aborts.
	for _, mode := range []string{"untraced", "traced-diagnostic"} {
		for sample := 0; sample < 8; sample++ {
			row, err := hevStartupDiagnosticSample(ctx, binary, file, profile, strace, mode, sample, t.TempDir())
			encoded, _ := json.Marshal(row)
			t.Logf("standalone_hev_startup %s", encoded)
			if err != nil {
				t.Fatal("diagnostic setup/cleanup failed (closed result above)")
			}
			if !row.TunObserved || row.ExitedBeforeStop || row.ExitCode != 0 || row.Signal != 0 || row.ForcedKill {
				t.Error("standalone official HEV startup/stop failure retained")
			}
		}
	}
	t.Log("fixed standalone populations completed; no route/service/LAN proof and no original acceptance process was traced")
}

func hevStartupDiagnosticSample(ctx context.Context, binary string, image *os.File, config []byte, strace, mode string, sample int, dir string) (row hevStartupDiagnosticResult, result error) {
	row.Mode, row.Sample = mode, sample
	if _, err := net.InterfaceByName(hevStartupDiagnosticInterface); err == nil {
		return row, errors.New("preexisting diagnostic TUN")
	}
	if ctx.Err() != nil {
		return row, ctx.Err()
	}
	fd, err := unix.MemfdCreate("razvilka-live-sidecar", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return row, err
	}
	profile := os.NewFile(uintptr(fd), "[sealed synthetic HEV diagnostic profile]")
	defer profile.Close()
	if _, err = profile.Write(config); err != nil {
		return row, err
	}
	if _, err = unix.FcntlInt(profile.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return row, err
	}
	command := exec.Command("/proc/self/fd/3", "/proc/self/fd/4")
	command.Args[0] = binary
	command.ExtraFiles = []*os.File{image, profile}
	output := &mihomoSidecarOutput{}
	command.Stdout, command.Stderr = output, output
	var trace hevStartupDiagnosticBuffer
	var reader, writer *os.File
	var traceDone chan error
	traceJoined := false
	if mode == "traced-diagnostic" {
		reader, writer, err = os.Pipe()
		if err != nil {
			return row, err
		}
		defer reader.Close()
		defer writer.Close()
		// The owned group receives TERM, but the tracer must remain to reap and
		// report the official child's original exit (strace -o default, explicit).
		// Only sigaltstack is decoded internally, to observe its exact numeric
		// requested ss_size. The closed parser exports no pointer/raw structure.
		command = exec.Command(strace, "-f", "-qq", "--interruptible=3", "-e", "raw=!sigaltstack", "-e", "trace="+hevStartupDiagnosticCalls, "-o", "/proc/self/fd/5", "--argv0="+binary, "--", "/proc/self/fd/3", "/proc/self/fd/4")
		command.ExtraFiles = []*os.File{image, profile, writer}
		command.Stdout, command.Stderr = output, output
		traceDone = make(chan error, 1)
		go func() { _, e := io.Copy(&trace, reader); traceDone <- e }()
		defer func() {
			// Even an error/timeout closes the owned pipe and joins the sole
			// drain before clearing storage. No raw trace survives a return.
			_ = writer.Close()
			_ = reader.Close()
			if !traceJoined {
				<-traceDone
			}
			clear(trace.data[:])
		}()
	}
	command.Dir = dir
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = command.Start(); err != nil {
		if writer != nil {
			writer.Close()
			<-traceDone
			traceJoined = true
		}
		return row, err
	}
	if writer != nil {
		writer.Close()
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	joined := false
	defer func() {
		// Always join this exact process/group, including cancellation/setup error.
		if !joined {
			_ = unix.Kill(-command.Process.Pid, unix.SIGKILL)
			<-done
		}
	}()
	startDeadline := time.NewTimer(3 * time.Second)
	defer startDeadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
observe:
	for {
		select {
		case <-done:
			joined = true
			row.ExitedBeforeStop = true
			break observe
		case <-ctx.Done():
			break observe
		case <-startDeadline.C:
			break observe
		case <-tick.C:
			if _, e := net.InterfaceByName(hevStartupDiagnosticInterface); e == nil {
				row.TunObserved = true
				break observe
			}
		}
	}
	// A created interface alone is not completed initialization: keep a fixed
	// diagnostic settling window; early exit remains failure, never readiness.
	if !joined && row.TunObserved {
		select {
		case <-done:
			joined = true
			row.ExitedBeforeStop = true
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !joined {
		_ = unix.Kill(-command.Process.Pid, unix.SIGTERM)
		select {
		case <-done:
			joined = true
		case <-time.After(2 * time.Second):
			row.ForcedKill = true
			_ = unix.Kill(-command.Process.Pid, unix.SIGKILL)
			<-done
			joined = true
		}
	}
	row.ExitCode = command.ProcessState.ExitCode()
	if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		row.Signal = int(status.Signal())
	}
	output.finish()
	row.OutputBytes, row.OutputTruncated, row.OutputCategory = output.captured, output.truncated, output.category
	if traceDone != nil {
		select {
		case e := <-traceDone:
			traceJoined = true
			if e != nil {
				return row, errors.New("trace drain failed")
			}
		case <-time.After(time.Second):
			return row, errors.New("trace still owned")
		}
		row.Trace = hevStartupDiagnosticParse(trace.data[:trace.used], trace.truncated)
	}
	_, tunErr := net.InterfaceByName(hevStartupDiagnosticInterface)
	row.Cleanup = errors.Is(unix.Kill(-command.Process.Pid, 0), unix.ESRCH) && tunErr != nil
	if !row.Cleanup {
		return row, errors.New("owned group or TUN retained")
	}
	if ctx.Err() != nil {
		return row, ctx.Err()
	}
	return row, nil
}
