package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Actual atomic writers and held file inodes only. The executable bytes are
// deliberately not ELF, so this fixture cannot pass the production constructor
// or create a domain resource, process, publication or native readiness.
func TestXrayDomainTCPFilesRefuseConfigAndExecutableReplacement(t *testing.T) {
	for _, changed := range []string{"config-inode", "executable-inode", "config-content"} {
		t.Run(changed, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resource")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := ownedfs.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			anchor, err := root.RootInfo()
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("private-config-fixture")
			config, err := root.WriteAtomicRetained(xrayDomainTCPConfigName, data, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer config.Close()
			info, err := config.Stat()
			if err != nil {
				t.Fatal(err)
			}
			exeData := []byte("not-an-ELF-or-runtime-owner")
			exe, err := root.WriteAtomicRetained("xray", exeData, 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer exe.Close()
			exeInfo, err := exe.Stat()
			if err != nil {
				t.Fatal(err)
			}
			p := &xrayDomainTCPExecutable{file: exe, info: exeInfo, path: filepath.Join(path, "xray"), sha256: nodeDefaultSourceMaterialHash(exeData)}
			r := &XrayDomainTCPExecutionResource{root: root, rootPath: path, anchor: anchor, config: config, configInfo: info, executable: p,
				definition: ExecutionXrayDomainTCPDefinition{ConfigSHA256: nodeDefaultSourceMaterialHash(data)}}
			r.self = r // File-comparison model only; no material/scope/map/issuer.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := r.filesCurrent(ctx); err != nil {
				t.Fatal("actual original file comparisons failed", err)
			}
			switch changed {
			case "config-inode":
				err = root.WriteAtomic(xrayDomainTCPConfigName, data, 0600)
			case "executable-inode":
				err = root.WriteAtomic("xray", exeData, 0700)
			case "config-content":
				replacement := append([]byte(nil), data...)
				replacement[0] = 'X'
				err = os.WriteFile(filepath.Join(path, xrayDomainTCPConfigName), replacement, 0600)
				if err == nil {
					err = os.Chtimes(filepath.Join(path, xrayDomainTCPConfigName), info.ModTime(), info.ModTime())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := r.filesCurrent(ctx); !errors.Is(err, ErrXrayDomainTCPOriginal) {
				t.Fatal("matching pathname/bytes supplied an original file owner", err)
			}
			if r.config != config || r.configInfo != info || r.executable.file != exe || r.executable.info != exeInfo {
				t.Fatal("failed read adopted the replacement")
			}
		})
	}
}

func TestXrayDomainTCPFilesRefuseDifferentHeldRootWithMatchingConfig(t *testing.T) {
	parent := t.TempDir()
	pathA, pathB := filepath.Join(parent, "original"), filepath.Join(parent, "different-held")
	for _, path := range []string{pathA, pathB} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	rootA, err := ownedfs.Open(pathA)
	if err != nil {
		t.Fatal(err)
	}
	defer rootA.Close()
	anchorA, err := rootA.RootInfo()
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := ownedfs.Open(pathB)
	if err != nil {
		t.Fatal(err)
	}
	defer rootB.Close()
	data := []byte("same-private-config-fixture")
	if err := rootA.WriteAtomic(xrayDomainTCPConfigName, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := rootB.WriteAtomicRetained(xrayDomainTCPConfigName, data, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	info, err := config.Stat()
	if err != nil {
		t.Fatal(err)
	}
	exeData := []byte("not-an-ELF-or-native-proof")
	exe, err := rootB.WriteAtomicRetained("xray", exeData, 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer exe.Close()
	exeInfo, err := exe.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r := &XrayDomainTCPExecutionResource{root: rootB, rootPath: pathA, anchor: anchorA, config: config, configInfo: info,
		executable: &xrayDomainTCPExecutable{file: exe, info: exeInfo, path: filepath.Join(pathB, "xray"), sha256: nodeDefaultSourceMaterialHash(exeData)},
		definition: ExecutionXrayDomainTCPDefinition{ConfigSHA256: nodeDefaultSourceMaterialHash(data)}}
	r.self = r // Physical file-comparison model only; no material/scope/issuer.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := r.filesCurrent(ctx); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("matching bytes in a different held root supplied the original directory", err)
	}
}
