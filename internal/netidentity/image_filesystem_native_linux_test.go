//go:build linux && (amd64 || arm64)

package netidentity

import (
	"context"
	"os"
	"runtime"
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
