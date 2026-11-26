package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestImageBorrowCallersHaveReviewedFallbacks(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "dataplane")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("borrowFileObservationImage")) {
			continue
		}
		path := "internal/dataplane/" + entry.Name()
		file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if ok && method.Sel.Name == "borrowFileObservationImage" {
				if _, reviewedFallback := reviewed[path]; !reviewedFallback {
					t.Errorf("image borrower has no reviewed fallback pin: %s", path)
				}
			}
			return true
		})
	}
}

func fixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	candidate, baseline := filepath.Join(root, "candidate"), filepath.Join(root, "baseline")
	for _, side := range []string{candidate, baseline} {
		for p := range reviewed {
			b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(p)))
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(side, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, b, 0600); err != nil {
				t.Fatal(err)
			}
		}
		name := filepath.Join(side, "scripts", "domain-image-variant", "main.go")
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile("main.go")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, b, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(side, "identical-harness"), []byte("12s publication / 4s client / unchanged cleanup\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return candidate, baseline, filepath.Join(root, "evidence")
}

func TestCurrentSourceVariantExactParity(t *testing.T) {
	a, b, out := fixture(t)
	before, err := tree(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepare(a, b, out, strings.Repeat("a", 40)); err != nil {
		t.Fatal(err)
	}
	after, err := tree(a)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("candidate modified", err)
	}
	base, err := tree(b)
	if err != nil {
		t.Fatal(err)
	}
	differences := 0
	for p, e := range before {
		if e != base[p] {
			differences++
			if p != target {
				t.Fatal("non-target changed", p)
			}
		}
	}
	if differences != 1 {
		t.Fatal(differences)
	}
	got, err := os.ReadFile(filepath.Join(b, filepath.FromSlash(target)))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(a, filepath.FromSlash(target)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.Replace(got, []byte(replacement), []byte(original), 1), source) {
		t.Fatal("non-target bytes changed")
	}
	data, err := os.ReadFile(filepath.Join(out, "variant.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if json.Unmarshal(data, &report) != nil || report["whole_file_ast_parity"] != true || report["whole_tree_parity"] != true {
		t.Fatal("missing parity proof")
	}
	patch, err := os.ReadFile(filepath.Join(out, "variant.patch"))
	if err != nil || report["patch_sha256"] != hash(patch) {
		t.Fatal("patch custody", err)
	}
	if err := prepare(a, b, filepath.Join(filepath.Dir(out), "second"), strings.Repeat("a", 40)); err == nil {
		t.Fatal("already modified source accepted")
	}
}

func TestCurrentSourceVariantRefusesDriftBeforeMutation(t *testing.T) {
	for _, cut := range []string{"other-file", "target-drift", "fallback-drift", "mode-drift", "checkout", "bad-revision", "existing-output", "overlap", "output-in-candidate", "output-in-baseline", "output-ancestor", "relative-output"} {
		t.Run(cut, func(t *testing.T) {
			a, b, out := fixture(t)
			revision := strings.Repeat("a", 40)
			switch cut {
			case "other-file":
				if err := os.WriteFile(filepath.Join(b, "extra"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "target-drift", "fallback-drift":
				p := target
				if cut == "fallback-drift" {
					p = "internal/dataplane/xray_domain_tcp_file_observation.go"
				}
				for _, side := range []string{a, b} {
					f, err := os.OpenFile(filepath.Join(side, filepath.FromSlash(p)), os.O_APPEND|os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = f.WriteString("\n// unreviewed\n")
					closeErr := f.Close()
					if err != nil || closeErr != nil {
						t.Fatal(err, closeErr)
					}
				}
			case "mode-drift":
				if err := os.Chmod(filepath.Join(b, "identical-harness"), 0400); err != nil {
					t.Fatal(err)
				}
			case "checkout":
				if err := os.Mkdir(filepath.Join(b, ".git"), 0700); err != nil {
					t.Fatal(err)
				}
			case "bad-revision":
				revision = "HEAD"
			case "existing-output":
				if err := os.Mkdir(out, 0700); err != nil {
					t.Fatal(err)
				}
			case "output-in-candidate":
				out = filepath.Join(a, "evidence")
			case "output-in-baseline":
				out = filepath.Join(b, "evidence")
			case "output-ancestor":
				out = filepath.Dir(a)
			case "relative-output":
				out = "relative-evidence"
			case "overlap":
				b = a
			}
			before, err := os.ReadFile(filepath.Join(b, filepath.FromSlash(target)))
			if err != nil {
				t.Fatal(err)
			}
			if err := prepare(a, b, out, revision); err == nil {
				t.Fatal("drift admitted")
			}
			after, err := os.ReadFile(filepath.Join(b, filepath.FromSlash(target)))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal mutated source", err)
			}
		})
	}
}

func TestVariantASTSelectionRefusesMissingOrDuplicate(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(target)))
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{bytes.Replace(source, []byte(original), []byte("lease := other.borrow(1)"), 1), bytes.Replace(source, []byte(original), []byte(original+"\n\t"+original), 1)} {
		if _, _, err := variant(changed); err == nil {
			t.Fatal("unexpected producer accepted")
		}
	}
}
