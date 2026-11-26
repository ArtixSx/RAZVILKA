package strategylab

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Go's nested test directories can be 0755 on Linux. Domain material requires
// a private parent, including protected ancestry when the native leaf checks it.
func nfqDomainPrivateTestDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return t.TempDir()
	}
	path, err := os.MkdirTemp("", "razvilka-nfq-domain-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	return path
}

// Real private files, no process/lease/source or native compatibility claim.
func TestNFQDomainFilesMaterializeExactSetsAndCommand(t *testing.T) {
	f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), []string{"video.example", "api.video.example", "video.example"}, []string{"private.video.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.close() })
	if err := f.current(); err != nil {
		t.Fatal(err)
	}
	positive, err := os.ReadFile(f.include.Path)
	if err != nil || string(positive) != "# RAZVILKA CORE NFQ INCLUDE V1\napi.video.example\nvideo.example\n" {
		t.Fatal("noncanonical include", err)
	}
	negative, err := os.ReadFile(f.exclude.Path)
	if err != nil || string(negative) != "# RAZVILKA CORE NFQ EXCLUDE V1\nprivate.video.example\n" {
		t.Fatal("noncanonical exclude", err)
	}
	candidate := []string{"--filter-tcp=443", "--lua-desync=fake:blob=tls_clienthello"}
	args, err := f.arguments(candidate)
	want := append(slices.Clone(candidate), "--reasm-disable=tls_client_hello", "--fastpath-workaround=0", "--ipcache-hostname=0", "--hostlist="+f.include.Path, "--hostlist-exclude="+f.exclude.Path)
	if err != nil || !slices.Equal(args, want) {
		t.Fatal("final domain argv not bound", args, err)
	}
	if ExportableArguments(strings.Join(args, " ")) == nil {
		t.Fatal("domain purpose leaked into generic candidate grammar")
	}
	args[0] = "--new"
	if candidate[0] != "--filter-tcp=443" {
		t.Fatal("caller candidate aliased")
	}
}

func TestNFQDomainFilesRefuseEmptyUnknownAndUnboundedNames(t *testing.T) {
	for _, include := range [][]string{nil, {""}, {"*.example"}, {"^exact.example"}, {"https://video.example/"}, {"VIDEO.example"}, {"127.0.0.1"}, {"video.example\nother.example"}, {strings.Repeat("x", 254) + ".example"}, slices.Repeat([]string{"video.example"}, 257)} {
		if f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), include, nil); err == nil || f != nil {
			t.Fatal("unsupported include accepted", include)
		}
	}
	if f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), []string{"video.example"}, []string{"example"}); err == nil || f != nil {
		t.Fatal("TLD exclusion accepted")
	}
	if f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), []string{"video.example"}, []string{"video.example"}); err == nil || f != nil {
		t.Fatal("empty effective positive accepted")
	}
}

func TestNFQDomainFilesRefuseChangedReplacedAndUnknownFiles(t *testing.T) {
	for _, change := range []string{"bytes", "inode", "extra", "closed"} {
		t.Run(change, func(t *testing.T) {
			f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), []string{"video.example"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.close() })
			switch change {
			case "bytes":
				if err := os.Chmod(f.include.Path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.include.Path, []byte("other.example\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "inode":
				data, err := os.ReadFile(f.exclude.Path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.exclude.Path, f.exclude.Path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.exclude.Path, data, 0400); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(f.exclude.Path + ".old"); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(f.path, "unknown.list"), []byte("extra.example"), 0600); err != nil {
					t.Fatal(err)
				}
			case "closed":
				_ = f.close()
			}
			if f.current() == nil {
				t.Fatal("changed material accepted")
			}
		})
	}
}

func TestNFQDomainFilesRefuseOtherProfilesAndTraffic(t *testing.T) {
	f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), []string{"video.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.close() })
	for _, args := range [][]string{{"--filter-tcp=80", "--lua-desync=fake"}, {"--filter-tcp=443", "--new", "--filter-tcp=443", "--lua-desync=fake"}, {"--filter-tcp=443", "--filter-udp=443", "--lua-desync=fake"}, {"--filter-tcp=443", "--hostlist=/tmp/foreign"}, {"--filter-tcp=443", "--lua-desync=autocircular"}, {"--filter-tcp=443"}} {
		if _, err := f.arguments(args); err == nil {
			t.Fatal("unsupported domain candidate", args)
		}
	}
}

func TestNFQDomainFilesCopyCannotCloseOriginalDescriptors(t *testing.T) {
	f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), []string{"video.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.close() })
	copied := *f
	if copied.current() == nil || copied.close() == nil {
		t.Fatal("copied material acquired original file authority")
	}
	if err := f.current(); err != nil {
		t.Fatal("copy closed original descriptors", err)
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	if err := f.close(); err != nil || f.current() == nil {
		t.Fatal("original close is not idempotent or retained authority", err)
	}
}

func TestNFQDomainFilesParentReplacementRefusesSameBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows refuses rename of the retained open directory; exercise replacement on Linux")
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := newNFQDomainFiles(parent, []string{"video.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.close() })
	if err := os.Rename(parent, parent+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.path, 0700); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"include.list", "exclude.list"} {
		if err := os.WriteFile(filepath.Join(f.path, name), f.images[i], 0400); err != nil {
			t.Fatal(err)
		}
	}
	if f.current() == nil {
		t.Fatal("matching replacement path adopted original held material")
	}
}
