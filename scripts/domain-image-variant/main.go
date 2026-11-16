// Disposable current-source comparison variant; never a production build knob.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const target = "internal/dataplane/xray_domain_tcp_image_read.go"
const original = "lease := domainTCPImageScratch.borrow(r.executable.info.Size())"
const replacement = "var lease *xrayDomainTCPImageLease"

// Reviewed producer AND all four nil-image fallback call sites. Drift requires
// review; this is not a caller-supplied hash or an arbitrary source patch.
var reviewed = map[string]string{
	target: "8cf454171cd0df8de84ccf2aa5a282e18c00952c6415aa65226cc552733358ae",
	"internal/dataplane/xray_domain_tcp_file_observation.go":     "7d2d2fd866b01b755a4515daa2573c4ee6a89e64bf5ddfaca5cb876abcdcc72e",
	"internal/dataplane/xray_domain_tcp_execution.go":            "4777181fc947837a3f2ec7990c22a2b032c2f873a5993a9534074e03c263c23e",
	"internal/dataplane/domain_tcp_guard_read.go":                "ca57f917bbf69c864c1efb59eea0ac078f169807e9d1e6091bc55a2aa8f78a4b",
	"internal/dataplane/domain_tcp_successor_byte_comparison.go": "6a401537df0f71b285e97c1b87a21266177c45d4912301d95b98cc770afec18f",
	"internal/dataplane/xray_domain_tcp_resource_files.go":       "69126b36dd1c2604767ed145fecbdfc560399ae482445c83f48734ec29cedf74",
}

type entry struct {
	Bytes  int64
	Mode   uint32
	SHA256 string
}
type manifest map[string]entry

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func tree(root string) (manifest, error) {
	m := manifest{}
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink source refused")
		}
		if d.IsDir() {
			return nil
		}
		i, err := d.Info()
		if err != nil {
			return err
		}
		if !i.Mode().IsRegular() || i.Size() > 128<<20 || len(m) >= 50000 {
			return errors.New("source file bound/type")
		}
		total += i.Size()
		if total > 1<<30 {
			return errors.New("source tree byte bound")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if int64(len(b)) != i.Size() {
			return errors.New("source changed while reading")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		m[filepath.ToSlash(rel)] = entry{i.Size(), uint32(i.Mode().Perm()), hash(b)}
		return nil
	})
	return m, err
}
func method(f *ast.File) (*ast.FuncDecl, error) {
	var found *ast.FuncDecl
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "borrowFileObservationImage" {
			continue
		}
		if found != nil {
			return nil, errors.New("duplicate producer")
		}
		found = fn
	}
	if found == nil || found.Recv == nil || found.Body == nil {
		return nil, errors.New("missing producer")
	}
	return found, nil
}
func normalized(n ast.Node) ([]byte, error) {
	var b bytes.Buffer
	err := format.Node(&b, token.NewFileSet(), n)
	return b.Bytes(), err
}
func variant(source []byte) ([]byte, int, error) {
	set := token.NewFileSet()
	f, err := parser.ParseFile(set, target, source, 0)
	if err != nil {
		return nil, 0, err
	}
	fn, err := method(f)
	if err != nil {
		return nil, 0, err
	}
	index, start, end := -1, 0, 0
	for i, s := range fn.Body.List {
		b, err := normalized(s)
		if err != nil {
			return nil, 0, err
		}
		if string(b) != original {
			continue
		}
		if index >= 0 {
			return nil, 0, errors.New("duplicate borrow assignment")
		}
		if _, ok := s.(*ast.AssignStmt); !ok {
			return nil, 0, errors.New("assignment shape")
		}
		index, start, end = i, set.Position(s.Pos()).Offset, set.Position(s.End()).Offset
	}
	if index < 0 || string(source[start:end]) != original {
		return nil, 0, errors.New("reviewed assignment drift")
	}
	changed := append([]byte{}, source[:start]...)
	changed = append(changed, replacement...)
	changed = append(changed, source[end:]...)
	b, err := parser.ParseFile(token.NewFileSet(), target, changed, 0)
	if err != nil {
		return nil, 0, err
	}
	bf, err := method(b)
	if err != nil {
		return nil, 0, err
	}
	if len(bf.Body.List) != len(fn.Body.List) {
		return nil, 0, errors.New("statement count drift")
	}
	d, ok := bf.Body.List[index].(*ast.DeclStmt)
	if !ok {
		return nil, 0, errors.New("nil declaration shape")
	}
	db, err := normalized(d)
	if err != nil || string(db) != replacement {
		return nil, 0, errors.New("nil declaration drift")
	}
	// Undo exactly one declaration. Every other AST node and source byte is unchanged.
	bf.Body.List[index] = fn.Body.List[index]
	aa, ae := normalized(f)
	ba, be := normalized(b)
	if ae != nil || be != nil || !bytes.Equal(aa, ba) {
		return nil, 0, errors.New("whole-file AST parity refused")
	}
	return changed, 1 + bytes.Count(source[:start], []byte{'\n'}), nil
}
func confinedRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || real != abs {
		return "", errors.New("source root alias refused")
	}
	for p := abs; ; p = filepath.Dir(p) {
		if _, err := os.Lstat(filepath.Join(p, ".git")); !os.IsNotExist(err) {
			return "", errors.New("checkout/worktree refused")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return abs, nil
}

func overlaps(a, b string) bool {
	inside := func(root, child string) bool {
		rel, err := filepath.Rel(root, child)
		return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
	}
	return inside(a, b) || inside(b, a)
}

func evidenceRoot(output, candidate, baseline string) (string, error) {
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return "", errors.New("canonical absolute evidence path required")
	}
	parent := filepath.Dir(output)
	real, err := filepath.EvalSymlinks(parent)
	if err != nil || real != parent {
		return "", errors.New("existing nonaliased evidence parent required")
	}
	if overlaps(output, candidate) || overlaps(output, baseline) {
		return "", errors.New("evidence must be disjoint from source trees")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return "", errors.New("new evidence directory required")
	}
	return output, nil
}
func prepare(candidate, baseline, output, revision string) error {
	if len(revision) != 40 {
		return errors.New("exact revision required")
	}
	if _, err := hex.DecodeString(revision); err != nil || revision != strings.ToLower(revision) {
		return errors.New("revision syntax")
	}
	candidate, err := confinedRoot(candidate)
	if err != nil {
		return err
	}
	baseline, err = confinedRoot(baseline)
	if err != nil {
		return err
	}
	if overlaps(candidate, baseline) {
		return errors.New("overlapping source roots")
	}
	output, err = evidenceRoot(output, candidate, baseline)
	if err != nil {
		return err
	}
	a, err := tree(candidate)
	if err != nil {
		return err
	}
	b, err := tree(baseline)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a, b) {
		return errors.New("initial complete source manifests differ")
	}
	for p, digest := range reviewed {
		if a[p].SHA256 != digest {
			return fmt.Errorf("reviewed image/fallback source drift: %s", p)
		}
	}
	if a["scripts/domain-image-variant/main.go"].SHA256 == "" {
		return errors.New("helper provenance missing")
	}
	source, err := os.ReadFile(filepath.Join(candidate, filepath.FromSlash(target)))
	if err != nil {
		return err
	}
	changed, line, err := variant(source)
	if err != nil {
		return err
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(baseline, filepath.FromSlash(target)), changed, fs.FileMode(a[target].Mode)); err != nil {
		return err
	}
	afterA, err := tree(candidate)
	if err != nil {
		return err
	}
	afterB, err := tree(baseline)
	if err != nil {
		return err
	}
	want := make(manifest, len(a))
	for p, e := range a {
		want[p] = e
	}
	e := want[target]
	e.SHA256 = hash(changed)
	e.Bytes = int64(len(changed))
	want[target] = e
	if !reflect.DeepEqual(a, afterA) || !reflect.DeepEqual(want, afterB) {
		return errors.New("complete source parity refused after patch")
	}
	patch := fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d +%d @@\n-\t%s\n+\t%s\n", target, target, line, line, original, replacement)
	if err := os.WriteFile(filepath.Join(output, "variant.patch"), []byte(patch), 0600); err != nil {
		return err
	}
	report := map[string]any{"schema": 1, "source_commit": revision, "baseline": "synthetic-current-source-full-SHA-fallback", "candidate": "unmodified-current-source-image-feature", "changed_path": target, "changed_statements": 1, "whole_file_ast_parity": true, "whole_tree_parity": true, "patch_sha256": hash([]byte(patch)), "helper_sha256": a["scripts/domain-image-variant/main.go"].SHA256, "reviewed_fallbacks": reviewed, "limits": []string{"Image feature includes dependent pre-Add/Guard sharing; not memcmp-only measurement", "Synthetic variant is not historical344912c or a production release", "No harness, dependency, budget or cleanup changes between sides"}}
	for name, value := range map[string]any{"candidate-source.json": afterA, "baseline-source.json": afterB, "variant.json": report} {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(output, name), append(data, '\n'), 0600); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "candidate baseline new-output exact-commit required")
		os.Exit(2)
	}
	if err := prepare(os.Args[1], os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println("DOMAIN_IMAGE_SOURCE_PARITY: same commit, one reviewed nil-image statement, complete tree and AST parity")
}
