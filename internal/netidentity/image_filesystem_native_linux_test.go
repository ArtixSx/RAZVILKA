//go:build linux && (amd64 || arm64)

package netidentity

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Root-only fact collection from the SAME production ndmc/loader/dependency
// opener and bounded ELF decoder. This does NOT execute ndmc, issue identity,
// cache a build report or classify a filesystem as immutable. Keep its numeric
// inode/device/filesystem output in Root's private diagnostic log. Paths,
// credentials, command output and network addresses are never printed.
func TestNativeReviewedStockImageFilesystem(t *testing.T) {
	if os.Getenv("RAZVILKA_NETIDENTITY_IMAGE_FS_DIAGNOSTIC") != "1" {
		t.Skip("Root-only held image filesystem fact probe requires explicit opt-in")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("stage=inputs code=root_stock_arm64_required capability=ungranted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	release, machine, ok := kernelTuple()
	profile := nc1812Profile()
	if !ok || release != profile.KernelRelease || machine != profile.Machine {
		t.Fatal("stage=inputs code=reviewed_kernel_required capability=ungranted")
	}
	images := &systemImages{seen: map[string]bool{}}
	defer images.close()
	image, err := images.open(ctx, "/bin/ndmc", true)
	if err != nil || images.dependencies(ctx, image) != nil || !images.unchanged(ctx) {
		t.Fatal("stage=images code=original_chain_unconfirmed capability=ungranted")
	}
	for index, image := range images.files {
		info, err := image.file.Stat()
		if err != nil || !os.SameFile(image.info, info) || !nodesUnchanged(image.nodes) || ctx.Err() != nil {
			t.Fatal("stage=images code=held_image_changed capability=ungranted")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		var fs syscall.Statfs_t
		if !ok || syscall.Fstatfs(int(image.file.Fd()), &fs) != nil {
			t.Fatal("stage=images code=held_filesystem_unknown capability=ungranted")
		}
		t.Logf("image=%d fs_type=%#x fs_flags=%#x fs_id=%v dev=%d inode=%d size=%d capability=ungranted", index, fs.Type, fs.Flags, fs.Fsid, stat.Dev, stat.Ino, info.Size())
	}
	if len(images.files) == 0 || !images.unchanged(ctx) || ctx.Err() != nil {
		t.Fatal("stage=closing code=original_chain_unconfirmed capability=ungranted")
	}
	t.Logf("stage=closing images=%d exact_chain_unchanged=true executable_commands=0 capability=ungranted", len(images.files))
}

func nativeImageReadChars() (uint64, error) {
	fd, err := syscall.Open("/proc/self/io", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(fd), "self-io-facts")
	defer f.Close()
	var buf [4096]byte
	n, err := f.Read(buf[:])
	if err != nil || n == len(buf) {
		return 0, ErrUnknown
	}
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if strings.HasPrefix(line, "rchar: ") {
			return strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "rchar:")), 10, 64)
		}
	}
	return 0, ErrUnknown
}

// Semantic RED on the actual retained immutable chain, not a mocked hash.
// Root can run this before/after the optimization. Initial full hashing and
// dependency discovery happen before the measured pair of closing checks.
func TestNativeReviewedStockImmutableImageReadBudget(t *testing.T) {
	if os.Getenv("RAZVILKA_NETIDENTITY_IMMUTABLE_READ_BUDGET") != "1" {
		t.Skip("Root-only actual immutable image read budget")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("stage=inputs code=root_stock_arm64_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, machine, ok := kernelTuple()
	profile := nc1812Profile()
	if !ok || release != profile.KernelRelease || machine != profile.Machine {
		t.Fatal("stage=inputs code=reviewed_kernel_required")
	}
	images := &systemImages{seen: map[string]bool{}}
	defer images.close()
	image, err := images.open(ctx, "/bin/ndmc", true)
	if err != nil || images.dependencies(ctx, image) != nil {
		t.Fatal("stage=images code=original_chain_unconfirmed")
	}
	for _, image := range images.files {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(image.file.Fd()), &fs) != nil || fs.Type != 0x73717368 || fs.Flags&1 == 0 {
			t.Fatal("stage=inputs code=actual_squashfs_readonly_chain_required")
		}
	}
	before, err := nativeImageReadChars()
	if err != nil || !images.unchanged(ctx) || !images.unchanged(ctx) {
		t.Fatal("stage=bookends code=original_chain_unconfirmed")
	}
	after, err := nativeImageReadChars()
	if err != nil || after < before || ctx.Err() != nil {
		t.Fatal("stage=read_budget code=kernel_counter_unconfirmed")
	}
	t.Logf("stage=read_budget image_bytes=%d closing_read_chars=%d executable_commands=0 capability=ungranted", images.bytes, after-before)
	if after-before > 64<<10 {
		t.Fatal("stage=read_budget code=redundant_immutable_image_reads")
	}
}
