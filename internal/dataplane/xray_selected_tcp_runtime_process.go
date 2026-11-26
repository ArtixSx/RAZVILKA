package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var errXraySelectedTCPRuntime = errors.New("original selected Xray TCP runtime readback unavailable or changed")

// This is a bounded association of actual live Cmd pointers, solely to prevent
// two readers from becoming two Wait owners. It issues no process, scope or
// journal permission. Actual completion removes the association; the original
// handle retains its immutable terminal result without admitting a replay.
var xraySelectedTCPWaits = struct {
	sync.Mutex
	live map[*exec.Cmd]*xraySelectedTCPProcess
}{live: make(map[*exec.Cmd]*xraySelectedTCPProcess)}

type xraySelectedTCPCommandImage struct {
	path, dir string
	args, env []string
	extras    []*os.File
}

type xraySelectedTCPProcess struct {
	self        *xraySelectedTCPProcess
	cmd         *exec.Cmd
	child       *os.Process
	pid         int
	parent      int
	image       xraySelectedTCPCommandImage
	ctx         context.Context
	cancel      context.CancelFunc
	closed      atomic.Bool
	done        chan struct{}
	state       *os.ProcessState
	waitErr     error
	waitStarted bool // Protected by the original Cmd association mutex.
}

func (*xraySelectedTCPProcess) String() string   { return "[private original Xray child Wait owner]" }
func (*xraySelectedTCPProcess) GoString() string { return "[private original Xray child Wait owner]" }

// retainXraySelectedTCPProcessWait takes the SAME already-started Cmd from the
// actual launcher, never a PID file, ProcessController or DTO. It does NOT
// start/signal a process, publish a runtime, prove readiness or grant cleanup.
// CORE must correlate its original durable runtime registration BEFORE Start,
// then transfer this Cmd's sole Wait here instead of launching a legacy waiter.
// An already-canceled ORIGINAL finite context is allowed to retain/reap an
// actual child after Start ACK; it can never authorize forward readback.
func retainXraySelectedTCPProcessWait(ctx context.Context, cmd *exec.Cmd) (*xraySelectedTCPProcess, error) {
	if ctx == nil || cmd == nil {
		return nil, errXraySelectedTCPRuntime
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, errXraySelectedTCPRuntime
	}
	xraySelectedTCPWaits.Lock()
	defer xraySelectedTCPWaits.Unlock()
	if xraySelectedTCPWaits.live[cmd] != nil || len(xraySelectedTCPWaits.live) >= maxExecutionResources {
		return nil, errXraySelectedTCPRuntime
	}
	// ProcessState is read only before the one Wait owner is published, and
	// never while Wait writes it. An externally/already waited Cmd is refused.
	if cmd.Process == nil || cmd.Process.Pid <= 1 || cmd.ProcessState != nil || cmd.Cancel != nil ||
		!filepath.IsAbs(cmd.Path) || filepath.Clean(cmd.Path) != cmd.Path || !filepath.IsAbs(cmd.Dir) || filepath.Clean(cmd.Dir) != cmd.Dir ||
		len(cmd.Args) == 0 || len(cmd.Args) > 16 || len(cmd.Env) > 128 || len(cmd.ExtraFiles) > 8 {
		return nil, errXraySelectedTCPRuntime
	}
	bytes := len(cmd.Path) + len(cmd.Dir)
	for _, values := range [][]string{cmd.Args, cmd.Env} {
		for _, value := range values {
			if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
				return nil, errXraySelectedTCPRuntime
			}
			bytes += len(value)
		}
	}
	if bytes > 64<<10 {
		return nil, errXraySelectedTCPRuntime
	}
	life, cancel := context.WithCancel(ctx)
	p := &xraySelectedTCPProcess{cmd: cmd, child: cmd.Process, pid: cmd.Process.Pid, parent: os.Getpid(), ctx: life, cancel: cancel, done: make(chan struct{}),
		image: xraySelectedTCPCommandImage{path: cmd.Path, dir: cmd.Dir, args: slices.Clone(cmd.Args), env: slices.Clone(cmd.Env), extras: slices.Clone(cmd.ExtraFiles)}}
	p.self = p
	p.waitStarted = true
	xraySelectedTCPWaits.live[cmd] = p
	go p.wait()
	return p, nil
}

// Reserve sole-Wait capacity BEFORE the upper original publisher's Start.
// Reservation grants no Start: only that actual resource/control publisher can
// use its private Cmd. A failed syscall releases only a never-started slot.
func reserveXraySelectedTCPProcessWait(ctx context.Context, cmd *exec.Cmd) (*xraySelectedTCPProcess, error) {
	if xraySelectedTCPFinite(ctx) != nil || cmd == nil || cmd.Process != nil || cmd.ProcessState != nil || cmd.Cancel != nil ||
		!filepath.IsAbs(cmd.Path) || filepath.Clean(cmd.Path) != cmd.Path || !filepath.IsAbs(cmd.Dir) || filepath.Clean(cmd.Dir) != cmd.Dir ||
		len(cmd.Args) == 0 || len(cmd.Args) > 16 || len(cmd.Env) > 128 || len(cmd.ExtraFiles) > 8 {
		return nil, errXraySelectedTCPRuntime
	}
	bytes := len(cmd.Path) + len(cmd.Dir)
	for _, values := range [][]string{cmd.Args, cmd.Env} {
		for _, value := range values {
			if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
				return nil, errXraySelectedTCPRuntime
			}
			bytes += len(value)
		}
	}
	if bytes > 64<<10 {
		return nil, errXraySelectedTCPRuntime
	}
	xraySelectedTCPWaits.Lock()
	defer xraySelectedTCPWaits.Unlock()
	if xraySelectedTCPWaits.live[cmd] != nil || len(xraySelectedTCPWaits.live) >= maxExecutionResources {
		return nil, errXraySelectedTCPRuntime
	}
	life, cancel := context.WithCancel(ctx)
	p := &xraySelectedTCPProcess{cmd: cmd, parent: os.Getpid(), ctx: life, cancel: cancel, done: make(chan struct{}),
		image: xraySelectedTCPCommandImage{path: cmd.Path, dir: cmd.Dir, args: slices.Clone(cmd.Args), env: slices.Clone(cmd.Env), extras: slices.Clone(cmd.ExtraFiles)}}
	p.self = p
	xraySelectedTCPWaits.live[cmd] = p
	return p, nil
}

// Acknowledge the actual SAME Cmd's Start without yet reaping it. The native
// publisher captures process birth while the actual child cannot be PID-reused.
func (p *xraySelectedTCPProcess) acknowledgeStart() error {
	if p == nil || p.self != p {
		return errXraySelectedTCPRuntime
	}
	xraySelectedTCPWaits.Lock()
	defer xraySelectedTCPWaits.Unlock()
	if xraySelectedTCPWaits.live[p.cmd] != p || p.waitStarted || p.child != nil || p.cmd.Process == nil || p.cmd.Process.Pid <= 1 || p.cmd.ProcessState != nil {
		return errXraySelectedTCPRuntime
	}
	p.child, p.pid = p.cmd.Process, p.cmd.Process.Pid
	return p.commandCurrent()
}

func (p *xraySelectedTCPProcess) beginReservedWait() error {
	if p == nil || p.self != p {
		return errXraySelectedTCPRuntime
	}
	xraySelectedTCPWaits.Lock()
	defer xraySelectedTCPWaits.Unlock()
	if xraySelectedTCPWaits.live[p.cmd] != p || p.waitStarted || p.child == nil || p.cmd.Process != p.child {
		return errXraySelectedTCPRuntime
	}
	p.waitStarted = true
	go p.wait()
	return nil
}

func (p *xraySelectedTCPProcess) abandonUnstartedWait() error {
	if p == nil || p.self != p {
		return errXraySelectedTCPRuntime
	}
	xraySelectedTCPWaits.Lock()
	defer xraySelectedTCPWaits.Unlock()
	if xraySelectedTCPWaits.live[p.cmd] != p || p.waitStarted || p.child != nil || p.cmd.Process != nil || p.cmd.ProcessState != nil {
		return errXraySelectedTCPRuntime
	}
	delete(xraySelectedTCPWaits.live, p.cmd)
	p.closed.Store(true)
	p.cancel()
	return nil
}

func (p *xraySelectedTCPProcess) wait() {
	p.waitErr = p.cmd.Wait() // The sole actual Wait; no caller callback or PID lookup.
	p.state = p.cmd.ProcessState
	xraySelectedTCPWaits.Lock()
	delete(xraySelectedTCPWaits.live, p.cmd)
	close(p.done) // Publishes both actual Wait result and ProcessState.
	xraySelectedTCPWaits.Unlock()
}

func xraySelectedTCPFinite(ctx context.Context) error {
	if ctx == nil {
		return errXraySelectedTCPRuntime
	}
	if _, finite := ctx.Deadline(); !finite {
		return errXraySelectedTCPRuntime
	}
	return ctx.Err()
}

func (p *xraySelectedTCPProcess) commandCurrent() error {
	if p == nil || p.self != p || p.ctx == nil || p.cancel == nil || p.done == nil || p.cmd == nil || p.child == nil || p.cmd.Process != p.child ||
		p.cmd.Path != p.image.path || p.cmd.Dir != p.image.dir || !slices.Equal(p.cmd.Args, p.image.args) ||
		!slices.Equal(p.cmd.Env, p.image.env) || (p.cmd.Env == nil) != (p.image.env == nil) || !slices.Equal(p.cmd.ExtraFiles, p.image.extras) || p.cmd.Cancel != nil {
		return errXraySelectedTCPRuntime
	}
	return nil
}

func (p *xraySelectedTCPProcess) forwardContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if p.liveCurrent(ctx) != nil {
		return nil, nil, errXraySelectedTCPRuntime
	}
	if xraySelectedTCPOriginalProcessRead(ctx, p) {
		c, cancel := context.WithCancel(ctx)
		return c, cancel, nil
	}
	deadline, _ := p.ctx.Deadline()
	c, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(p.ctx, cancel)
	return c, func() { stop(); cancel() }, nil
}

func (p *xraySelectedTCPProcess) liveCurrent(ctx context.Context) error {
	if p == nil || p.self != p || p.ctx == nil || p.closed.Load() || p.ctx.Err() != nil && !xraySelectedTCPOriginalProcessRead(ctx, p) || xraySelectedTCPFinite(ctx) != nil || p.commandCurrent() != nil {
		return errXraySelectedTCPRuntime
	}
	select {
	case <-p.done:
		return errXraySelectedTCPRuntime
	default:
	}
	return nil
}

// Joined returns only the actual retained child's terminal Wait observation.
// It permits fresh finite cleanup after forward cancellation; the independent
// SAME original cleanup owner/COMMON/conntrack/socket absence checks remain
// CORE's obligation. A terminal DTO or a Wait error without reaping is unknown.
func (p *xraySelectedTCPProcess) Joined(ctx context.Context) error {
	if p == nil || p.self != p || xraySelectedTCPFinite(ctx) != nil {
		return errXraySelectedTCPRuntime
	}
	select {
	case <-ctx.Done():
		return errors.Join(errXraySelectedTCPRuntime, ctx.Err())
	case <-p.done:
	}
	if ctx.Err() != nil || p.commandCurrent() != nil || !xraySelectedTCPWaitResult(p.pid, p.state, p.waitErr) {
		return errXraySelectedTCPRuntime
	}
	return nil
}

// Close revokes forward readers immediately and bounds the join. It never
// signals/kills the child or converts a join timeout to proof of inactivity.
func (p *xraySelectedTCPProcess) Close(ctx context.Context) error {
	if p == nil || p.self != p || p.cancel == nil {
		return errXraySelectedTCPRuntime
	}
	p.closed.Store(true)
	p.cancel()
	return p.Joined(ctx)
}

// These are readback observations, not public passports or runtime issuers.
type xraySelectedTCPProcessObservation struct {
	pid, parent, group                              int
	boot, start, exe, argumentsSHA256, configSHA256 string
	executable, config                              os.FileInfo
	network                                         netidentity.Identity
}

type xraySelectedTCPListenerObservation struct {
	process  xraySelectedTCPProcessObservation
	endpoint netip.AddrPort
	inode    uint64
}

func xraySelectedTCPStat(data []byte, pid int) (string, int, int, error) {
	if len(data) == 0 || len(data) > 8192 || pid <= 1 || data[len(data)-1] != '\n' || strings.Count(string(data), "\n") != 1 {
		return "", 0, 0, errXraySelectedTCPRuntime
	}
	s := strings.TrimSuffix(string(data), "\n")
	opening := strings.Index(s, " (")
	end := strings.LastIndex(s, ") ")
	if opening < 1 || end <= opening+1 || s[:opening] != strconv.Itoa(pid) {
		return "", 0, 0, errXraySelectedTCPRuntime
	}
	fields := strings.Fields(s[end+2:])
	if len(fields) < 50 || len(fields) > 64 || len(fields[0]) != 1 || !strings.Contains("RSDTtKWPI", fields[0]) {
		return "", 0, 0, errXraySelectedTCPRuntime
	}
	for _, field := range fields[1:] {
		unsigned := strings.TrimPrefix(field, "-")
		if !xraySelectedTCPDigits(unsigned, false) {
			return "", 0, 0, errXraySelectedTCPRuntime
		}
		if strings.HasPrefix(field, "-") {
			if _, err := strconv.ParseInt(field, 10, 64); err != nil {
				return "", 0, 0, errXraySelectedTCPRuntime
			}
		} else if _, err := strconv.ParseUint(field, 10, 64); err != nil {
			return "", 0, 0, errXraySelectedTCPRuntime
		}
	}
	positive := func(text string) (uint64, bool) {
		v, err := strconv.ParseUint(text, 10, 63)
		return v, err == nil && v > 0 && strconv.FormatUint(v, 10) == text
	}
	parent, parentOK := positive(fields[1])
	group, groupOK := positive(fields[2])
	_, startOK := positive(fields[19])
	if !parentOK || !groupOK || !startOK || parent > uint64(^uint(0)>>1) || group > uint64(^uint(0)>>1) || strings.ContainsAny(s, "\x00\r") {
		return "", 0, 0, errXraySelectedTCPRuntime
	}
	return fields[19], int(parent), int(group), nil
}

type xraySelectedTCPSocketRow struct {
	local, remote netip.AddrPort
	state         uint8
	inode         uint64
}

func xraySelectedTCPDigits(text string, hex bool) bool {
	if text == "" {
		return false
	}
	for _, c := range text {
		if c >= '0' && c <= '9' || hex && (c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

// Parse every row, including unrelated rows: malformed/truncated input must
// never become an apparently complete negative listener observation. IPv4/6
// proc addresses consist of native-endian 32-bit words (Linux tcp seq ABI).
func xraySelectedTCPSockets(data []byte, ipv6 bool) ([]xraySelectedTCPSocketRow, error) {
	if len(data) == 0 || len(data) > 8<<20 || data[len(data)-1] != '\n' || strings.ContainsAny(string(data), "\x00\r") {
		return nil, errXraySelectedTCPRuntime
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	header := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	if ipv6 {
		header = "sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	}
	if strings.Join(strings.Fields(lines[0]), " ") != header || len(lines) > 65537 {
		return nil, errXraySelectedTCPRuntime
	}
	address := func(raw string) (netip.AddrPort, error) {
		parts := strings.Split(raw, ":")
		n := 8
		if ipv6 {
			n = 32
		}
		if len(parts) != 2 || len(parts[0]) != n || len(parts[1]) != 4 || !xraySelectedTCPDigits(parts[0], true) || !xraySelectedTCPDigits(parts[1], true) {
			return netip.AddrPort{}, errXraySelectedTCPRuntime
		}
		var bytes [16]byte
		for i := 0; i < n/8; i++ {
			word, err := strconv.ParseUint(parts[0][i*8:(i+1)*8], 16, 32)
			if err != nil {
				return netip.AddrPort{}, errXraySelectedTCPRuntime
			}
			binary.NativeEndian.PutUint32(bytes[i*4:], uint32(word))
		}
		port, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil {
			return netip.AddrPort{}, errXraySelectedTCPRuntime
		}
		ip := netip.AddrFrom16(bytes)
		if !ipv6 {
			ip = netip.AddrFrom4([4]byte(bytes[:4]))
		}
		return netip.AddrPortFrom(ip, uint16(port)), nil
	}
	var rows []xraySelectedTCPSocketRow
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != 12 && len(f) != 17 || !strings.HasSuffix(f[0], ":") {
			return nil, errXraySelectedTCPRuntime
		}
		if slot := strings.TrimSuffix(f[0], ":"); !xraySelectedTCPDigits(slot, false) {
			return nil, errXraySelectedTCPRuntime
		} else if _, err := strconv.ParseUint(slot, 10, 32); err != nil {
			return nil, errXraySelectedTCPRuntime
		}
		local, e1 := address(f[1])
		remote, e2 := address(f[2])
		state, e3 := strconv.ParseUint(f[3], 16, 8)
		inode, e4 := strconv.ParseUint(f[9], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !xraySelectedTCPDigits(f[3], true) || !xraySelectedTCPDigits(f[9], false) || len(f[3]) != 2 || state == 0 || state > 12 || state == 10 && (inode == 0 || !remote.Addr().IsUnspecified() || remote.Port() != 0 || local.Port() == 0) {
			return nil, errXraySelectedTCPRuntime
		}
		if len(f) == 12 && (state != 3 && state != 5 && state != 6 || inode != 0) {
			return nil, errXraySelectedTCPRuntime
		}
		for _, i := range []int{4, 5} {
			pair := strings.Split(f[i], ":")
			if len(pair) != 2 {
				return nil, errXraySelectedTCPRuntime
			}
			if i == 4 && (len(pair[0]) != 8 || len(pair[1]) != 8) || i == 5 && (len(pair[0]) != 2 || len(pair[1]) < 8 || len(pair[1]) > 16) {
				return nil, errXraySelectedTCPRuntime
			}
			for _, text := range pair {
				if _, err := strconv.ParseUint(text, 16, 64); err != nil || !xraySelectedTCPDigits(text, true) {
					return nil, errXraySelectedTCPRuntime
				}
			}
		}
		if _, err := strconv.ParseUint(f[6], 16, 32); err != nil || len(f[6]) != 8 || !xraySelectedTCPDigits(f[6], true) {
			return nil, errXraySelectedTCPRuntime
		}
		for _, i := range []int{7, 8, 10} {
			if _, err := strconv.ParseUint(f[i], 10, 64); err != nil || !xraySelectedTCPDigits(f[i], false) {
				return nil, errXraySelectedTCPRuntime
			}
		}
		if _, err := strconv.ParseUint(f[11], 16, 64); err != nil || !xraySelectedTCPDigits(f[11], true) {
			return nil, errXraySelectedTCPRuntime
		}
		if len(f) == 17 {
			for _, text := range f[12:16] {
				if _, err := strconv.ParseUint(text, 10, 64); err != nil || !xraySelectedTCPDigits(text, false) {
					return nil, errXraySelectedTCPRuntime
				}
			}
			if _, err := strconv.ParseInt(f[16], 10, 64); err != nil || !xraySelectedTCPDigits(strings.TrimPrefix(f[16], "-"), false) {
				return nil, errXraySelectedTCPRuntime
			}
		}
		rows = append(rows, xraySelectedTCPSocketRow{local: local, remote: remote, state: uint8(state), inode: inode})
	}
	return rows, nil
}

func xraySelectedTCPListenerInode(v4, v6 []xraySelectedTCPSocketRow, endpoint netip.AddrPort) (uint64, error) {
	if !endpoint.IsValid() || !endpoint.Addr().Is4() || !endpoint.Addr().IsGlobalUnicast() || endpoint.Addr().IsLoopback() || endpoint.Addr().IsLinkLocalUnicast() || endpoint.Port() < 1024 {
		return 0, errXraySelectedTCPRuntime
	}
	var inode uint64
	for _, row := range v4 {
		if row.state != 10 || row.local.Port() != endpoint.Port() {
			continue
		}
		if row.local.Addr().IsUnspecified() || row.local == endpoint {
			if row.local != endpoint || inode != 0 {
				return 0, errXraySelectedTCPRuntime
			}
			inode = row.inode
		}
	}
	for _, row := range v6 {
		if row.state == 10 && row.local.Port() == endpoint.Port() && (row.local.Addr().IsUnspecified() || row.local.Addr().Unmap() == endpoint.Addr()) {
			return 0, errXraySelectedTCPRuntime // v6only/reuseport cannot be inferred from proc text.
		}
	}
	if inode == 0 {
		return 0, errXraySelectedTCPRuntime
	}
	return inode, nil
}

func (o xraySelectedTCPProcessObservation) same(other xraySelectedTCPProcessObservation) bool {
	return o.pid > 1 && o.pid == other.pid && o.parent == other.parent && o.group == other.group && o.boot == other.boot && o.start == other.start &&
		o.exe == other.exe && o.argumentsSHA256 == other.argumentsSHA256 && o.configSHA256 == other.configSHA256 && o.network == other.network &&
		o.executable != nil && other.executable != nil && os.SameFile(o.executable, other.executable) &&
		o.config != nil && other.config != nil && os.SameFile(o.config, other.config)
}

func (xraySelectedTCPProcessObservation) String() string { return "[private Xray process comparison]" }
func (xraySelectedTCPProcessObservation) GoString() string {
	return "[private Xray process comparison]"
}
func (xraySelectedTCPListenerObservation) String() string {
	return "[private Xray listener comparison]"
}
func (xraySelectedTCPListenerObservation) GoString() string {
	return "[private Xray listener comparison]"
}
