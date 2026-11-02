//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Real original private directories/receipt/history. Only complete offline
// process/kernel absence is MODEL input; these tests issue no native authority.
func mihomoColdHomeFixture(t *testing.T) (ExecutionMihomoLiveDefinition, string, []byte, netidentity.Identity, context.Context) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("original private cold-home ownership requires root")
	}
	parent, err := ownedfs.Open(filepath.Clean(os.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	name, err := parent.MkdirTemp(".", ".razvilka-mihomo-live-")
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Clean(os.TempDir()), name)
	// Remove only this fixture's freshly created fixed-parent child.
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	p, e1 := parent.RootInfo()
	child, e2 := parent.Stat(name)
	e3 := parent.Close()
	if e1 != nil || e2 != nil || e3 != nil {
		t.Fatal(e1, e2, e3)
	}
	ps, cs := p.Sys().(*syscall.Stat_t), child.Sys().(*syscall.Stat_t)
	d := mihomoLiveDefinitionFixture(t)
	receipt := components.MihomoLiveHomeReceipt{Schema: 1, Source: d.Source, ProfileSHA: d.Profile.ConfigSHA256, Nonce: strings.Repeat("a", 32), ParentDevice: uint64(ps.Dev), ParentInode: ps.Ino, Device: uint64(cs.Dev), Inode: cs.Ino}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, components.MihomoLiveHomeReceiptName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cache.db"), []byte("closed private history"), 0600); err != nil {
		t.Fatal(err)
	}
	d.NativeHome = &components.MihomoLiveHomeReference{Schema: 1, Parent: filepath.Clean(os.TempDir()), Name: name, ParentDevice: uint64(ps.Dev), ParentInode: ps.Ino, Device: uint64(cs.Dev), Inode: cs.Ino, ReceiptSHA256: nodeDefaultSourceMaterialHash(raw)}
	identity := d.NetworkIdentity
	identity.BootID = "11111111-2222-4333-8444-555555555555"
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	return d, path, raw, identity, ctx
}

func TestMihomoLiveColdHomeExactPresentAndAfterBootAbsence(t *testing.T) {
	for _, mode := range []string{"present", "absent-original-parent", "absent-changed-parent"} {
		t.Run(mode, func(t *testing.T) {
			d, path, raw, identity, ctx := mihomoColdHomeFixture(t)
			if strings.HasPrefix(mode, "absent") {
				if err := os.RemoveAll(path); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "absent-changed-parent" {
				d.NativeHome.ParentInode++
			}
			calls := 0
			out, err := observeMihomoColdHome(ctx, d, func(context.Context) (netidentity.Identity, error) { calls++; return identity, nil })
			if err != nil || calls != 2 || out.Schema != 1 || out.Reference != *d.NativeHome || out.ObservedParent == "" || out.OriginalParent != (mode != "absent-changed-parent") {
				t.Fatal(out, calls, err)
			}
			if mode == "present" {
				if out.State != "present" || !bytes.Equal(out.Receipt, raw) || string(out.Files["cache.db"]) != "closed private history" {
					t.Fatal("exact history missing", out)
				}
				current, err := os.ReadFile(filepath.Join(path, components.MihomoLiveHomeReceiptName))
				if err != nil || !bytes.Equal(current, raw) {
					t.Fatal("observer changed scratch", err)
				}
			} else if out.State != "absent" || len(out.Receipt) != 0 || len(out.Files) != 0 {
				t.Fatal("absence fabricated original history", out)
			}
		})
	}
}

func TestMihomoLiveColdHomeRefusesForeignMalformedAndUnboundedHistory(t *testing.T) {
	for _, mode := range []string{"same-boot", "parent", "child", "arbitrary-parent", "bad-name", "receipt-hash", "receipt-source", "receipt-fifo", "receipt-symlink", "hardlink", "public", "oversize", "many-files", "deep"} {
		t.Run(mode, func(t *testing.T) {
			d, path, raw, identity, ctx := mihomoColdHomeFixture(t)
			receiptPath := filepath.Join(path, components.MihomoLiveHomeReceiptName)
			switch mode {
			case "same-boot":
				identity = d.NetworkIdentity
			case "parent":
				d.NativeHome.ParentInode++
			case "child":
				d.NativeHome.Inode++
			case "arbitrary-parent":
				d.NativeHome.Parent = filepath.Join(path, "arbitrary")
			case "bad-name":
				d.NativeHome.Name = ".razvilka-mihomo-live-../foreign"
			case "receipt-hash":
				d.NativeHome.ReceiptSHA256 = strings.Repeat("f", 64)
			case "receipt-source":
				var receipt components.MihomoLiveHomeReceipt
				if err := json.Unmarshal(raw, &receipt); err != nil {
					t.Fatal(err)
				}
				receipt.ProfileSHA = strings.Repeat("f", 64)
				raw, _ = json.Marshal(receipt)
				d.NativeHome.ReceiptSHA256 = nodeDefaultSourceMaterialHash(raw)
				if err := os.WriteFile(receiptPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-fifo", "receipt-symlink":
				if err := os.Remove(receiptPath); err != nil {
					t.Fatal(err)
				}
				if mode == "receipt-fifo" {
					if err := syscall.Mkfifo(receiptPath, 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink("cache.db", receiptPath); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(receiptPath, filepath.Join(path, "linked")); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(filepath.Join(path, "cache.db"), 0644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				f, err := os.OpenFile(filepath.Join(path, "large"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(f.Truncate(mihomoColdHomeLimit+1), f.Close()); err != nil {
					t.Fatal(err)
				}
			case "many-files":
				for i := 0; i < 129; i++ {
					if err := os.WriteFile(filepath.Join(path, strings.Repeat("x", i+1)), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "deep":
				if err := os.MkdirAll(filepath.Join(path, "a/b/c/d/e"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Now()
			out, err := observeMihomoColdHome(ctx, d, func(context.Context) (netidentity.Identity, error) { return identity, nil })
			if err == nil || !reflect.DeepEqual(out, mihomoColdHomeArchive{}) {
				t.Fatal("foreign/invalid history accepted", out, err)
			}
			if mode == "receipt-fifo" && time.Since(started) > time.Second {
				t.Fatal("FIFO historical read blocked")
			}
		})
	}
}

func TestMihomoLiveColdHomeClosingBookendsDiscardAllHistory(t *testing.T) {
	for _, mode := range []string{"negative-error", "boot-drift", "bytes", "inode", "absent-appears", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			d, path, _, identity, ctx := mihomoColdHomeFixture(t)
			if mode == "absent-appears" {
				if err := os.RemoveAll(path); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			calls := 0
			originalErr := errors.New("complete offline observer revoked")
			out, err := observeMihomoColdHome(ctx, d, func(context.Context) (netidentity.Identity, error) {
				calls++
				if calls == 1 {
					return identity, nil
				}
				switch mode {
				case "negative-error":
					return identity, originalErr
				case "boot-drift":
					identity.BootID = "22222222-2222-4333-8444-555555555555"
				case "bytes":
					if err := os.WriteFile(filepath.Join(path, "cache.db"), []byte("changed private history"), 0600); err != nil {
						t.Fatal(err)
					}
				case "inode":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					defer os.RemoveAll(path + ".old")
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "absent-appears":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "cancel":
					cancel()
				}
				return identity, nil
			})
			if err == nil || !reflect.DeepEqual(out, mihomoColdHomeArchive{}) {
				t.Fatal("closing revocation published history", out, err)
			}
			if mode == "negative-error" && !errors.Is(err, originalErr) {
				t.Fatal("original exception lost", err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		})
	}
}

func TestMihomoLiveColdHomeSavedArchiveValidationRejectsTampering(t *testing.T) {
	d, _, _, identity, ctx := mihomoColdHomeFixture(t)
	history, err := observeMihomoColdHome(ctx, d, func(context.Context) (netidentity.Identity, error) { return identity, nil })
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"none", "schema", "reference", "parent-path", "observed-parent", "original-parent", "state", "receipt", "file-identity", "file-size", "directory", "impossible-directory-type", "same-file-and-dir", "path", "extra-identity", "absence-with-bytes"} {
		t.Run(mode, func(t *testing.T) {
			var h mihomoColdHomeArchive
			definition := d
			reference := *d.NativeHome
			definition.NativeHome = &reference
			if err := json.Unmarshal(wire, &h); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "schema":
				h.Schema++
			case "reference":
				h.Reference.Inode++
			case "parent-path":
				h.Reference.Parent = filepath.Join(h.Reference.Parent, "arbitrary")
				definition.NativeHome.Parent = h.Reference.Parent
			case "observed-parent":
				h.ObservedParent = "01:2:0:0:2"
			case "original-parent":
				h.OriginalParent = false
			case "state":
				h.State = "unknown"
			case "receipt":
				h.Receipt[0] ^= 1
			case "file-identity":
				h.Identities["cache.db"] = "untrusted"
			case "file-size":
				h.Files["cache.db"] = append(h.Files["cache.db"], 0)
			case "directory":
				delete(h.Directories, ".")
			case "impossible-directory-type":
				parts := strings.Split(h.Directories["."], ":")
				value, err := strconv.ParseUint(parts[5], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				parts[5] = strconv.FormatUint(value|uint64(os.ModeSocket), 10)
				h.Directories["."] = strings.Join(parts, ":")
			case "same-file-and-dir":
				h.Directories["cache.db"] = h.Directories["."]
			case "path":
				h.Files["../outside"] = h.Files["cache.db"]
				h.Identities["../outside"] = h.Identities["cache.db"]
				delete(h.Files, "cache.db")
				delete(h.Identities, "cache.db")
			case "extra-identity":
				h.Identities["not-in-inventory"] = h.Identities["cache.db"]
			case "absence-with-bytes":
				h.State = "absent"
			}
			if err := validateMihomoColdHomeArchive(definition, h); (err == nil) != (mode == "none") {
				t.Fatal("saved comparison validation", mode, err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(d.NativeHome.Parent, d.NativeHome.Name)); err != nil {
		t.Fatal("documentary validation mutated original home", err)
	}
}
