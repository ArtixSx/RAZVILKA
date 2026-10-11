//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"golang.org/x/sys/unix"
)

func selfUpdateRuntimeUnameScalar(raw []byte) (string, error) {
	end := 0
	for end < len(raw) && raw[end] != 0 {
		end++
	}
	if end == 0 || end == len(raw) {
		return "", dataplane.ErrRuntimeInactivity
	}
	for _, b := range raw[:end] {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("._+-", rune(b))) {
			return "", dataplane.ErrRuntimeInactivity
		}
	}
	return string(raw[:end]), nil
}

func selfUpdateRuntimeUname(ctx context.Context) (selfUpdateRuntimePlatformFacts, error) {
	if ctx == nil || ctx.Err() != nil {
		return selfUpdateRuntimePlatformFacts{}, dataplane.ErrRuntimeInactivity
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return selfUpdateRuntimePlatformFacts{}, err
	}
	system, e1 := selfUpdateRuntimeUnameScalar(uts.Sysname[:])
	release, e2 := selfUpdateRuntimeUnameScalar(uts.Release[:])
	machine, e3 := selfUpdateRuntimeUnameScalar(uts.Machine[:])
	if e1 != nil || e2 != nil || e3 != nil || system != "Linux" || ctx.Err() != nil {
		return selfUpdateRuntimePlatformFacts{}, dataplane.ErrRuntimeInactivity
	}
	return selfUpdateRuntimePlatformFacts{system: system, arch: runtime.GOARCH, release: release, machine: machine}, nil
}

func observeSelfUpdateRuntimePlatform(ctx context.Context) (selfUpdateRuntimePlatformFacts, error) {
	if ctx == nil || ctx.Err() != nil {
		return selfUpdateRuntimePlatformFacts{}, dataplane.ErrRuntimeInactivity
	}
	if _, finite := ctx.Deadline(); !finite {
		return selfUpdateRuntimePlatformFacts{}, dataplane.ErrRuntimeInactivity
	}
	opening, err := selfUpdateRuntimeUname(ctx)
	if err != nil {
		return selfUpdateRuntimePlatformFacts{}, err
	}
	facts := opening
	if facts.arch == "amd64" && facts.machine == "x86_64" {
		facts.distribution, facts.version, facts.metadataOwner, err = readSelfUpdateUbuntuRelease(ctx)
		if err != nil {
			return selfUpdateRuntimePlatformFacts{}, err
		}
	}
	closing, err := selfUpdateRuntimeUname(ctx)
	if err != nil || closing != opening || ctx.Err() != nil {
		return selfUpdateRuntimePlatformFacts{}, errors.Join(dataplane.ErrRuntimeInactivity, err, ctx.Err())
	}
	return facts, nil
}

func selfUpdateRuntimeProtectedNode(st unix.Stat_t, directory bool) bool {
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	return st.Mode&unix.S_IFMT == kind && st.Uid == 0 && st.Mode&(0022|unix.S_ISUID|unix.S_ISGID) == 0
}

func selfUpdateRuntimeSameNode(a, b unix.Stat_t, directory bool) bool {
	return selfUpdateRuntimeProtectedNode(b, directory) && a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode &&
		a.Uid == b.Uid && a.Gid == b.Gid && (directory || a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim)
}

// Fixed protected metadata only. Every ancestor and the file are opened without
// following symlinks; descriptor/path bookends reject replacement or writable
// inputs. No shell evaluation, environment, alternate path or discovery exists.
func readSelfUpdateUbuntuRelease(ctx context.Context) (distribution, version string, metadataOwner [32]byte, result error) {
	const limit = 16 << 10
	var fds []int
	defer func() {
		for i := len(fds) - 1; i >= 0; i-- {
			result = errors.Join(result, unix.Close(fds[i]))
		}
	}()
	refuse := func(err error) (string, string, [32]byte, error) {
		return "", "", [32]byte{}, errors.Join(dataplane.ErrRuntimeInactivity, err)
	}
	if ctx == nil || ctx.Err() != nil {
		return refuse(nil)
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	root, err := unix.Open("/", flags|unix.O_DIRECTORY, 0)
	if err != nil {
		return refuse(err)
	}
	fds = append(fds, root)
	var original []unix.Stat_t
	var rootStat unix.Stat_t
	if err := unix.Fstat(root, &rootStat); err != nil || !selfUpdateRuntimeProtectedNode(rootStat, true) {
		return refuse(err)
	}
	original = append(original, rootStat)
	for _, name := range []string{"usr", "lib", "os-release"} {
		if ctx.Err() != nil {
			return refuse(ctx.Err())
		}
		directory := name != "os-release"
		openFlags := flags
		if directory {
			openFlags |= unix.O_DIRECTORY
		}
		parent := fds[len(fds)-1]
		fd, err := unix.Openat(parent, name, openFlags, 0)
		if err != nil {
			return refuse(err)
		}
		fds = append(fds, fd)
		var held, path unix.Stat_t
		if e1, e2 := unix.Fstat(fd, &held), unix.Fstatat(parent, name, &path, unix.AT_SYMLINK_NOFOLLOW); e1 != nil || e2 != nil ||
			!selfUpdateRuntimeProtectedNode(held, directory) || !selfUpdateRuntimeSameNode(held, path, directory) {
			return refuse(errors.Join(e1, e2))
		}
		original = append(original, held)
	}
	file := fds[len(fds)-1]
	if original[3].Size <= 0 || original[3].Size > limit {
		return refuse(nil)
	}
	data := make([]byte, limit+1)
	total := 0
	for total < len(data) {
		if ctx.Err() != nil {
			return refuse(ctx.Err())
		}
		n, err := unix.Read(file, data[total:])
		if err != nil {
			return refuse(err)
		}
		if n == 0 {
			break
		}
		total += n
	}
	if total > limit || int64(total) != original[3].Size {
		return refuse(nil)
	}
	for i, name := range []string{"/", "usr", "lib", "os-release"} {
		var held, path unix.Stat_t
		err := unix.Fstat(fds[i], &held)
		if i == 0 {
			err = errors.Join(err, unix.Lstat(name, &path))
		} else {
			err = errors.Join(err, unix.Fstatat(fds[i-1], name, &path, unix.AT_SYMLINK_NOFOLLOW))
		}
		if err != nil || !selfUpdateRuntimeSameNode(original[i], held, i != 3) || !selfUpdateRuntimeSameNode(held, path, i != 3) {
			return refuse(err)
		}
	}
	if ctx.Err() != nil {
		return refuse(ctx.Err())
	}
	distribution, version, err = parseSelfUpdateUbuntuRelease(data[:total])
	if err != nil {
		return refuse(err)
	}
	// Retain the protected ancestor/file identity and exact bytes across the
	// whole assembly too: a same-byte replacement cannot pass its final cut.
	digest := sha256.New()
	for i, node := range original {
		fmt.Fprintf(digest, "%d:%d:%d:%d:%d\n", node.Dev, node.Ino, node.Uid, node.Gid, node.Mode)
		if i == 3 {
			fmt.Fprintf(digest, "%d:%d:%d:%d:%d\n", node.Size, node.Mtim.Sec, node.Mtim.Nsec, node.Ctim.Sec, node.Ctim.Nsec)
		}
	}
	digest.Write(data[:total])
	copy(metadataOwner[:], digest.Sum(nil))
	return distribution, version, metadataOwner, nil
}

func parseSelfUpdateUbuntuRelease(data []byte) (string, string, error) {
	if len(data) == 0 || len(data) > 16<<10 || !utf8.Valid(data) || strings.ContainsAny(string(data), "\x00\r") {
		return "", "", dataplane.ErrRuntimeInactivity
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key != "ID" && key != "VERSION_ID" {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return "", "", dataplane.ErrRuntimeInactivity
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if value == "" || len(value) > 64 || strings.ContainsAny(value, "\"'$`\\ \t") {
			return "", "", dataplane.ErrRuntimeInactivity
		}
		values[key] = value
	}
	if values["ID"] == "" || values["VERSION_ID"] == "" {
		return "", "", dataplane.ErrRuntimeInactivity
	}
	return values["ID"], values["VERSION_ID"], nil
}
