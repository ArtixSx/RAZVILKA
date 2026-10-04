package usquediag

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

const ownedUSQUESource = "6aa03fc97d12848dce34eedbd187fb1077b5d1ea"

// Exact executable hashes, NOT ZIP digests, from official v4.2.1 assets whose
// archive hashes matched both checksums.txt and GitHub asset.digest. Unknown
// opkg/version labels do not adopt this profile. SourceCommit is the upstream
// tag reference; release buildinfo says vcs.modified=true, so clean-tree
// reproducibility/equivalence is NOT attested. Path inference is labelled as
// such and never promoted to directly observed negotiated transport.
var ownedUSQUE421 = map[string]string{
	"a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10": "amd64",
	"8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002": "arm64",
	"c7dd8a80eca37e5e5770073d72c85630d671e6d288214185c2f9bf246f01f59d": "mips",
	"2b466b9595704c6741472d1ffd17ef004d676871005504401105b5cd277c0dbf": "mipsle",
}

func ownedPublicAddress(address netip.Addr) bool { return publicfetch.PublicAddress(address) }

func stringsHasOwnedRuntime(i OwnedRuntimeIdentity) bool {
	const prefix = "managed:usque:"
	if !strings.HasPrefix(i.RuntimeID, prefix) || !canaryDigest(strings.TrimPrefix(i.RuntimeID, prefix)) || i.SourceCommit != ownedUSQUESource || ownedUSQUE421[i.BinarySHA256] == "" {
		return false
	}
	for _, digest := range []string{i.BindingID, i.SessionSHA256, i.ArgsSHA256, i.EnvironmentID, i.SocketBinding} {
		if !canaryDigest(digest) {
			return false
		}
	}
	peer, err := netip.ParseAddrPort(i.Endpoint)
	if err != nil || peer.String() != i.Endpoint || !peer.Addr().Is4() || peer.Port() != 443 || !ownedPublicAddress(peer.Addr()) {
		return false
	}
	if i.Transport == "HTTP/2" {
		return i.PeerObservation == "tcp-established-peer"
	}
	return i.Transport == "QUIC" && (i.PeerObservation == "udp-unconnected-exclusive-config-inference" || i.PeerObservation == "udp-connected-default-peer")
}

type ownedRuntimeIO struct {
	read   func(string, int64) ([]byte, error)
	fds    func(int) ([]string, error)
	verify func(string, string, string) (routeidentity.Passport, error)
	hash   func(int, string) (string, error)
	little bool
}

func observeOwnedUSQUE(ctx context.Context, r OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
	if runtime.GOOS != "linux" {
		return OwnedRuntimeIdentity{}, errors.New("owned-runtime-linux-required")
	}
	root, err := ownedfs.Open(r.Root)
	if err != nil {
		return OwnedRuntimeIdentity{}, errors.New("owned-runtime-root-unavailable")
	}
	defer root.Close()
	reader := func(path string, limit int64) ([]byte, error) {
		if filepath.Clean(filepath.Dir(path)) == filepath.Clean(r.Root) {
			return root.ReadLimited(filepath.Base(path), limit)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(data)) > limit {
			return nil, errors.New("owned-runtime-read-limit")
		}
		return data, nil
	}
	return captureOwnedUSQUE(ctx, r, ownedRuntimeIO{read: reader, fds: ownedSocketFDs, verify: routeidentity.Verify, hash: ownedExecutableHash, little: binary.NativeEndian.Uint32([]byte{1, 0, 0, 0}) == 1})
}

func captureOwnedUSQUE(ctx context.Context, r OwnedRuntimeRequest, inspect ownedRuntimeIO) (OwnedRuntimeIdentity, error) {
	refuse := func(code string) (OwnedRuntimeIdentity, error) { return OwnedRuntimeIdentity{}, errors.New(code) }
	if ctx.Err() != nil {
		return refuse("owned-runtime-canceled")
	}
	env, err := r.Environment(ctx)
	if err != nil || !canaryDigest(env) {
		return refuse("owned-runtime-epoch-unavailable")
	}
	before, err := inspect.verify(r.Root, "usque", r.SOCKSAddress)
	if err != nil || !strings.HasPrefix(before.ID, "managed:usque:") || before.PID <= 1 {
		return refuse("owned-runtime-identity-unavailable")
	}
	proc := "/proc/" + strconv.Itoa(before.PID)
	config, e1 := inspect.read(filepath.Join(r.Root, "engine.json"), 8<<20)
	defer eraseOwned(config)
	argv, e2 := inspect.read(proc+"/cmdline", 32<<10)
	defer eraseOwned(argv)
	processEnv, e3 := inspect.read(proc+"/environ", 128<<10)
	defer eraseOwned(processEnv)
	if e1 != nil || e2 != nil || e3 != nil || before.ConfigHash != routeidentity.Hash(config) || !ownedArgs(r, argv) || !ownedProxyEnvironmentClear(processEnv) || !ownedConfigPin(config, r) {
		return refuse("owned-runtime-session-or-path-unverified")
	}
	exeSHA, err := inspect.hash(before.PID, r.Binary)
	if err != nil || ownedUSQUE421[exeSHA] == "" {
		return refuse("owned-runtime-binary-not-audited")
	}
	fds, err := inspect.fds(before.PID)
	if err != nil {
		return refuse("owned-runtime-socket-owner-unavailable")
	}
	sockets := []ownedSocket{}
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := inspect.read(proc+"/net/"+table, 2<<20)
		if errors.Is(err, os.ErrNotExist) && (table == "tcp6" || table == "udp6") {
			continue // IPv6 kernel facility absent; IPv4 tables still mandatory.
		}
		if err != nil {
			return refuse("owned-runtime-socket-table-unavailable")
		}
		parsed, err := parseOwnedSocketTable(data, table, fds, inspect.little)
		if err != nil {
			return refuse("owned-runtime-socket-table-invalid")
		}
		sockets = append(sockets, parsed...)
	}
	peer, kind, err := selectOwnedSocket(sockets, r)
	if err != nil {
		return refuse("owned-runtime-underlay-ambiguous")
	}
	afterFD, err := inspect.fds(before.PID)
	if err != nil || strings.Join(fds, ",") != strings.Join(afterFD, ",") {
		return refuse("owned-runtime-socket-owner-changed")
	}
	after, err := inspect.verify(r.Root, "usque", r.SOCKSAddress)
	if err != nil || after != before {
		return refuse("owned-runtime-identity-changed")
	}
	exeAfter, err := inspect.hash(before.PID, r.Binary)
	if err != nil || exeAfter != exeSHA {
		return refuse("owned-runtime-binary-changed")
	}
	envAfter, err := r.Environment(ctx)
	processEnvAfter, envReadErr := inspect.read(proc+"/environ", 128<<10)
	defer eraseOwned(processEnvAfter)
	if err != nil || envAfter != env || envReadErr != nil || !ownedProxyEnvironmentClear(processEnvAfter) || ctx.Err() != nil {
		return refuse("owned-runtime-environment-changed")
	}
	i := OwnedRuntimeIdentity{RuntimeID: before.ID, BinarySHA256: exeSHA, SessionSHA256: before.ConfigHash, ArgsSHA256: routeidentity.Hash(argv), EnvironmentID: env, Transport: r.Transport, Endpoint: r.Endpoint.String(), PeerObservation: kind, SocketBinding: routeidentity.Hash([]byte(peer.table + "|" + peer.inode + "|" + peer.local.String() + "|" + peer.remote.String())), SourceCommit: ownedUSQUESource}
	i.BindingID = ownedIdentityBinding(i)
	return i, nil
}

func eraseOwned(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func ownedArgs(r OwnedRuntimeRequest, raw []byte) bool {
	if len(raw) == 0 || raw[len(raw)-1] != 0 {
		return false
	}
	args := strings.Split(string(raw[:len(raw)-1]), "\x00")
	listener, err := netip.ParseAddrPort(r.SOCKSAddress)
	if err != nil {
		return false
	}
	want := []string{r.Binary, "-c", filepath.Join(r.Root, "engine.json"), "socks", "-b", "127.0.0.1", "-p", strconv.Itoa(int(listener.Port())), "--always-reconnect", "-S"}
	if len(args) < len(want) {
		return false
	}
	for i := range want {
		if args[i] != want[i] {
			return false
		}
	}
	h2, sni := false, false
	for index := len(want); index < len(args); index++ {
		switch args[index] {
		case "--http2":
			if h2 {
				return false
			}
			h2 = true
		case "-s":
			if sni || index+1 >= len(args) || !ownedSNI(args[index+1]) {
				return false
			}
			sni = true
			index++
		default:
			return false
		}
	}
	return h2 == (r.Transport == "HTTP/2")
}

func ownedSNI(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func ownedProxyEnvironmentClear(raw []byte) bool {
	for _, value := range bytes.Split(raw, []byte{0}) {
		parts := bytes.SplitN(value, []byte{'='}, 2)
		if len(parts) == 2 && len(parts[1]) != 0 {
			switch strings.ToUpper(string(parts[0])) {
			case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
				return false
			}
		}
	}
	return true
}

func ownedConfigPin(raw []byte, r OwnedRuntimeRequest) bool {
	config, err := ownedConfigValues(raw)
	if err != nil {
		return false
	}
	key := "endpoint_v4"
	if r.Transport == "HTTP/2" {
		key = "endpoint_h2_v4"
	}
	var address string
	if json.Unmarshal(config[key], &address) != nil || address != r.Endpoint.Addr().String() {
		return false
	}
	for _, key := range []string{"private_key", "endpoint_pub_key", "id", "access_token"} {
		var value string
		if json.Unmarshal(config[key], &value) != nil || value == "" {
			return false
		}
	}
	return true
}

func ownedExecutableHash(pid int, installed string) (string, error) {
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", err
	}
	defer file.Close()
	actual, a := file.Stat()
	expected, b := os.Stat(installed)
	if a != nil || b != nil || !actual.Mode().IsRegular() || !os.SameFile(actual, expected) || actual.Size() <= 0 || actual.Size() > 64<<20 {
		return "", errors.New("owned-executable-mismatch")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, (64<<20)+1))
	if err != nil || n != actual.Size() {
		return "", errors.New("owned-executable-read-failed")
	}
	after, err := file.Stat()
	current, currentErr := os.Stat(installed)
	if err != nil || currentErr != nil || !os.SameFile(actual, current) || actual.Size() != after.Size() || actual.ModTime() != after.ModTime() {
		return "", errors.New("owned-executable-changed")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ownedSocketFDs(pid int) ([]string, error) {
	root := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 4096 {
		return nil, errors.New("owned-fd-unavailable")
	}
	inodes := []string{}
	seen := map[string]bool{}
	for _, entry := range entries {
		link, err := os.Readlink(root + "/" + entry.Name())
		if err != nil {
			return nil, errors.New("owned-fd-changed")
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if value, err := strconv.ParseUint(inode, 10, 64); err != nil || value == 0 {
				return nil, errors.New("owned-fd-invalid")
			}
			binding := entry.Name() + ":" + inode
			if seen[binding] {
				return nil, errors.New("owned-fd-ambiguous")
			}
			seen[binding] = true
			inodes = append(inodes, binding)
		}
	}
	sort.Strings(inodes)
	return inodes, nil
}

type ownedSocket struct {
	table, inode, state string
	local, remote       netip.AddrPort
}

func parseOwnedSocketTable(raw []byte, table string, fds []string, little bool) ([]ownedSocket, error) {
	owners := map[string]bool{}
	for _, fd := range fds {
		parts := strings.SplitN(fd, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("owned-fd-invalid")
		}
		owners[parts[1]] = true
	}
	result := []ownedSocket{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "sl" {
			continue
		}
		if len(fields) < 10 {
			return nil, errors.New("owned-table-invalid")
		}
		if !owners[fields[9]] {
			continue
		}
		local, e1 := parseOwnedProcAddress(fields[1], little)
		remote, e2 := parseOwnedProcAddress(fields[2], little)
		if e1 != nil || e2 != nil || seen[fields[9]] {
			return nil, errors.New("owned-table-invalid")
		}
		seen[fields[9]] = true
		result = append(result, ownedSocket{table: table, inode: fields[9], state: fields[3], local: local, remote: remote})
	}
	return result, nil
}

func parseOwnedProcAddress(raw string, little bool) (netip.AddrPort, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return netip.AddrPort{}, errors.New("owned-address-invalid")
	}
	data, err := hex.DecodeString(parts[0])
	port, pErr := strconv.ParseUint(parts[1], 16, 16)
	if err != nil || pErr != nil || len(data) != 4 && len(data) != 16 {
		return netip.AddrPort{}, errors.New("owned-address-invalid")
	}
	if little {
		for i := 0; i < len(data); i += 4 {
			data[i], data[i+3] = data[i+3], data[i]
			data[i+1], data[i+2] = data[i+2], data[i+1]
		}
	}
	address, ok := netip.AddrFromSlice(data)
	if !ok {
		return netip.AddrPort{}, errors.New("owned-address-invalid")
	}
	return netip.AddrPortFrom(address.Unmap(), uint16(port)), nil
}

func selectOwnedSocket(sockets []ownedSocket, r OwnedRuntimeRequest) (ownedSocket, string, error) {
	var selected ownedSocket
	kind, found := "", false
	for _, socket := range sockets {
		if socket.remote.Addr().IsLoopback() || socket.local.Addr().IsLoopback() {
			continue
		}
		if strings.HasPrefix(socket.table, "tcp") {
			if socket.remote.Port() == 0 && socket.remote.Addr().IsUnspecified() {
				continue
			}
			if r.Transport != "HTTP/2" || socket.remote != r.Endpoint || socket.state != "01" || socket.local.Port() == 0 || socket.local.Addr().IsUnspecified() || found {
				return selected, "", errors.New("owned-underlay-ambiguous")
			}
			selected, kind, found = socket, "tcp-established-peer", true
		} else {
			if r.Transport != "QUIC" || socket.local.Port() == 0 || found {
				return selected, "", errors.New("owned-underlay-ambiguous")
			}
			if socket.remote.Port() == 0 && socket.remote.Addr().IsUnspecified() && socket.state == "07" {
				selected, kind, found = socket, "udp-unconnected-exclusive-config-inference", true
			} else if socket.remote == r.Endpoint && socket.state == "01" {
				selected, kind, found = socket, "udp-connected-default-peer", true
			} else {
				return selected, "", errors.New("owned-underlay-ambiguous")
			}
		}
	}
	if !found {
		return selected, "", errors.New("owned-underlay-unavailable")
	}
	return selected, kind, nil
}
