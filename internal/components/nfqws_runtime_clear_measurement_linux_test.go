//go:build linux && (amd64 || arm64)

package components

import (
	"archive/tar"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

//go:embed nfqws_bundle_runtime_image_linux.go
var runtimeClearProductionSource string

//go:embed nfqws_runtime_clear_measurement_linux_test.go
var runtimeClearMeasurementSource string

func TestManagedRuntimeClearSourceParity(t *testing.T) {
	body := func(source, name string) string {
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, "input.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if ok && function.Name.Name == name {
				var out bytes.Buffer
				if err := format.Node(&out, set, function.Body); err != nil {
					t.Fatal(err)
				}
				return out.String()
			}
		}
		t.Fatal("exact verifier body missing")
		return ""
	}
	candidate := body(runtimeClearProductionSource, "verifyManagedNFQWSRuntimeImage")
	prior := body(runtimeClearMeasurementSource, "verifyManagedNFQWSRuntimeImageDuplicateClear")
	guard := "if !node.scratchOwned {\n\t\t\t\tclear(node.content)\n\t\t\t}"
	if strings.Count(candidate, guard) != 1 || strings.Replace(candidate, guard, "clear(node.content)", 1) != prior {
		t.Fatal("full verifier comparison differs outside duplicate payload clear")
	}
}

// Whole-call file/metadata/byte/EOF verifier with explicit modeled payloads
// sized like the reviewed graph. Both timed paths include original clearing,
// all closes and digest checks. This proves no route or production authority.
func TestManagedRuntimeClearFullImagePairs(t *testing.T) {
	if os.Getenv("RAZVILKA_RUNTIME_CLEAR_MEASURE") != "1" {
		t.Skip("explicit full-verifier clear measurement")
	}
	TestManagedRuntimeClearSourceParity(t)
	manifest, err := ReviewedManagedNFQWSManifest("arm64")
	if err != nil {
		t.Fatal(err)
	}
	manifest.Flavor = "clear-full-image-size-model"
	var entries []bundleFixtureEntry
	var payloadBytes int64
	for i := range manifest.Members {
		member := &manifest.Members[i]
		data := bytes.Repeat([]byte{byte(0x31 + i)}, int(member.RawSize))
		payloadBytes += member.RawSize
		member.RawSHA256 = digest(data)
		if member.Gzip {
			data = bundleFixtureGzip(t, data)
		}
		member.Size, member.SHA256 = int64(len(data)), digest(data)
		entries = append(entries, bundleFixtureEntry{member.Path, data, tar.TypeReg})
	}
	input := bundleFixtureContainer(t, entries)
	manifest.ParentAssetSize, manifest.ParentSHA256 = int64(len(input)), digest(input)
	manager := bundleFixtureManager(t, input)
	receipt, err := manager.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	call := func(variant string) {
		verify := manager.verifyManagedNFQWSRuntimeImage
		if variant == "duplicate-clear" {
			verify = manager.verifyManagedNFQWSRuntimeImageDuplicateClear
		}
		got, err := verify(context.Background(), receipt.GenerationPath, receipt.ManifestSHA256)
		if err != nil {
			t.Fatal(err)
		}
		if hash, err := got.Digest(); err != nil || hash != receipt.ManifestSHA256 {
			t.Fatal("verifier manifest differs", err)
		}
	}
	checkClear := func() {
		if managedRuntimePayloadRetained.busy.Load() {
			t.Fatal("borrow escaped")
		}
		for _, data := range managedRuntimePayloadRetained.scratch.members {
			if !bytes.Equal(data[:cap(data)], make([]byte, cap(data))) {
				t.Fatal("payload escaped release")
			}
		}
		if !bytes.Equal(managedRuntimePayloadRetained.scratch.compare[:], make([]byte, 32<<10)) {
			t.Fatal("comparison bytes escaped")
		}
	}
	call("duplicate-clear")
	call("single-clear")
	checkClear()
	for sample, variant := range []string{"duplicate-clear", "single-clear", "single-clear", "duplicate-clear", "duplicate-clear", "single-clear", "single-clear", "duplicate-clear"} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		started := time.Now()
		for count := 0; count < 16; count++ {
			call(variant)
		}
		elapsed := time.Since(started)
		runtime.ReadMemStats(&after)
		row := struct {
			Variant      string `json:"variant"`
			Sample       int    `json:"sample"`
			Calls        int    `json:"calls"`
			WallNS       int64  `json:"wall_ns"`
			AllocBytes   uint64 `json:"alloc_bytes"`
			AllocObjects uint64 `json:"alloc_objects"`
			PayloadBytes int64  `json:"payload_bytes"`
		}{variant, sample, 16, elapsed.Nanoseconds(), after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs, payloadBytes}
		wire, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("nfq_runtime_clear_pair %s", wire)
		checkClear()
	}
}

func (m *Manager) verifyManagedNFQWSRuntimeImageDuplicateClear(ctx context.Context, path, expected string) (manifest ManagedNFQWSManifest, resultErr error) {
	if m == nil || ctx == nil || !bundleHash(expected, 64) {
		return manifest, ErrManagedNFQWSBundle
	}
	if err := ctx.Err(); err != nil {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	if err := m.publicManagedNFQWSPath(filepath.Dir(path), false); err != nil {
		return manifest, err
	}
	anchor, err := os.Lstat(path)
	if err != nil || !anchor.IsDir() || m.trustedManagedNFQWSNode(anchor) != nil || !updateModeMatches(anchor.Mode().Perm(), 0555) {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return manifest, err
	}
	var nodes []*managedRuntimeImageNode
	var scratch *managedRuntimePayloadScratch
	defer func() {
		for _, node := range nodes {
			clear(node.content)
			node.content = nil
			resultErr = errors.Join(resultErr, node.file.Close())
		}
		resultErr = errors.Join(resultErr, root.Close())
		// Only after the last descriptor closes and every slice is detached may
		// another call acquire this zeroed byte storage. It holds no evidence.
		releaseManagedRuntimePayloadScratch(scratch)
		if resultErr != nil {
			manifest = ManagedNFQWSManifest{}
			resultErr = errors.Join(ErrManagedNFQWSBundle, resultErr)
		}
	}()
	open := func(name string, directory bool, limit int64) (*managedRuntimeImageNode, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		before, err := root.Lstat(name)
		if err != nil {
			return nil, err
		}
		file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		held, e1 := file.Stat()
		named, e2 := root.Lstat(name)
		mode := os.FileMode(0444)
		if directory || name == "bin/rzv-nfqws2" {
			mode = 0555
		}
		if e1 != nil || e2 != nil || !managedRuntimeImageSameNode(before, held) || !managedRuntimeImageSameNode(held, named) || held.IsDir() != directory || !directory && (!held.Mode().IsRegular() || held.Size() < 1 || held.Size() > limit) || m.trustedManagedNFQWSNode(held) != nil || !updateModeMatches(held.Mode().Perm(), mode) {
			return nil, errors.Join(ErrManagedNFQWSBundle, e1, e2, file.Close())
		}
		node := &managedRuntimeImageNode{name: name, file: file, info: held}
		nodes = append(nodes, node)
		return node, nil
	}
	// Exact schema1 tree, not a discovered loader recipe or arbitrary member.
	directories := map[string][]string{
		".":     {"d:bin", "d:blobs", "d:lua", "f:manifest.json", "f:source-notices.json"},
		"bin":   {"f:rzv-nfqws2"},
		"lua":   {"f:zapret-antidpi.lua", "f:zapret-auto.lua", "f:zapret-lib.lua"},
		"blobs": {"f:quic_initial.bin", "f:tls_clienthello.bin"},
	}
	for _, name := range []string{".", "bin", "lua", "blobs"} {
		node, err := open(name, true, 0)
		if err != nil {
			return manifest, err
		}
		if name == "." && !managedRuntimeImageSameNode(anchor, node.info) {
			return manifest, ErrManagedNFQWSBundle
		}
		node.entries, err = managedRuntimeImageEntries(node.file)
		if err != nil || !slices.Equal(node.entries, directories[name]) {
			return manifest, errors.Join(ErrManagedNFQWSBundle, err)
		}
	}
	manifestNode, err := open("manifest.json", false, 64<<10)
	if err != nil {
		return manifest, err
	}
	wire, err := io.ReadAll(io.LimitReader(manifestNode.file, (64<<10)+1))
	manifestNode.content = wire
	if err != nil || len(wire) > 64<<10 || digest(wire) != expected || json.Unmarshal(wire, &manifest) != nil {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	canonical, err := manifest.bytes()
	if err != nil || !bytes.Equal(wire, canonical) {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	noticeNode, err := open("source-notices.json", false, 1<<20)
	if err != nil {
		return manifest, err
	}
	notices, err := io.ReadAll(io.LimitReader(noticeNode.file, (1<<20)+1))
	noticeNode.content = notices
	expectedNotices, marshalErr := json.Marshal(manifest.Notices)
	if err != nil || marshalErr != nil || len(notices) > 1<<20 || !bytes.Equal(notices, expectedNotices) {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err, marshalErr)
	}
	// Open the entire immutable member closure before any member payload read.
	var members []*managedRuntimeImageNode
	for _, member := range manifest.Members {
		node, err := open(filepath.FromSlash(member.Destination), false, 1<<20)
		if err != nil || node.info.Size() != member.RawSize {
			return manifest, errors.Join(ErrManagedNFQWSBundle, err)
		}
		members = append(members, node)
	}
	scratch = acquireManagedRuntimePayloadScratch()
	for i, node := range members {
		member := manifest.Members[i]
		data, err := scratch.member(i, member.RawSize)
		if err != nil {
			return manifest, err
		}
		node.scratchOwned = true
		count, err := io.ReadFull(managedRuntimeImageContextReader{ctx, io.LimitReader(node.file, member.RawSize+1)}, data)
		node.content = data[:count]
		noteManagedNFQWSPayloadRead(m, int64(count))
		if !errors.Is(err, io.ErrUnexpectedEOF) || int64(count) != member.RawSize || digest(node.content) != member.RawSHA256 || ctx.Err() != nil {
			return manifest, errors.Join(ErrManagedNFQWSBundle, err, ctx.Err())
		}
	}
	// Preserve the second full byte comparison for manifest, notices and ALL
	// six payloads. Metadata closing is additional, never a substitute for it.
	buffer := scratch.compare[:]
	for _, node := range nodes {
		if node.info.IsDir() {
			continue
		}
		count, err := managedRuntimeImageCompare(ctx, node.file, node.content, buffer)
		if node.name != "manifest.json" && node.name != "source-notices.json" {
			noteManagedNFQWSPayloadRead(m, count)
		}
		if err != nil {
			return manifest, err
		}
	}
	if err := m.managedRuntimeImageClosing(ctx, root, path, anchor, nodes); err != nil {
		return manifest, err
	}
	return manifest, ctx.Err()
}
