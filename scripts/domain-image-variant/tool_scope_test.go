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

func toolFixture(t *testing.T) (string, string, string) {
	t.Helper()
	a, b, out := fixture(t)
	for _, side := range []string{a, b} {
		for _, p := range []string{toolTarget, "scripts/domain-image-variant/tool_scope.go"} {
			data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(p)))
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(side, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return a, b, out
}

func TestToolSourceVariantExactParity(t *testing.T) {
	a, b, out := toolFixture(t)
	before, err := tree(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareTool(a, b, out, strings.Repeat("a", 40)); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(a, filepath.FromSlash(toolTarget)))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(filepath.Join(b, filepath.FromSlash(toolTarget)))
	if err != nil {
		t.Fatal(err)
	}
	// Independent byte boundaries include the complete initializer, but leave
	// both association bookends, all file loans and every other byte intact.
	start := bytes.Index(source, []byte("\tresult := domainTCPBaselineToolComparison("))
	end := bytes.Index(source, []byte("\n\tresult = errors.Join(result, association(ctx))"))
	if start < 0 || end <= start {
		t.Fatal("reviewed initializer boundaries changed")
	}
	want := append([]byte{}, source[:start]...)
	want = append(want, "\tresult := errors.Join(read(ctx), association(ctx))"...)
	want = append(want, source[end:]...)
	if !bytes.Equal(baseline, want) {
		t.Fatal("variant changed bytes outside the single initializer")
	}
	afterA, err := tree(a)
	if err != nil || !reflect.DeepEqual(before, afterA) {
		t.Fatal("candidate changed", err)
	}
	afterB, err := tree(b)
	if err != nil {
		t.Fatal(err)
	}
	difference := 0
	for path, row := range before {
		if row != afterB[path] {
			difference++
			if path != toolTarget || afterB[path].SHA256 != hash(baseline) || afterB[path].Mode != row.Mode {
				t.Fatal("unreviewed difference", path)
			}
		}
	}
	if difference != 1 || len(afterB) != len(before) {
		t.Fatal("source parity", difference)
	}
	data, err := os.ReadFile(filepath.Join(out, "variant.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if json.Unmarshal(data, &report) != nil || report["whole_file_ast_parity"] != true || report["whole_file_byte_parity"] != true || report["whole_tree_parity"] != true || report["changed_expressions"] != float64(1) {
		t.Fatal("missing expression/file/tree parity proof")
	}
	if report["baseline"] != "synthetic-current-source-without-standalone-tool-bracket" || report["source_commit"] != strings.Repeat("a", 40) || report["baseline_file_sha256"] != hash(baseline) || report["candidate_file_sha256"] != hash(source) || report["baseline_file_revision"] != nil {
		t.Fatal("synthetic baseline provenance misrepresented", report)
	}
	for name, want := range map[string][]byte{"before.go.txt": baseline, "after.go.txt": source} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("replay source mismatch", name, err)
		}
	}
	if err := prepareTool(a, b, filepath.Join(filepath.Dir(out), "repeat"), strings.Repeat("a", 40)); err == nil {
		t.Fatal("modified source adopted")
	}
}

func TestToolSourceVariantDoesNotExecuteHistoricalFixture(t *testing.T) {
	a, b, out := toolFixture(t)
	for _, side := range []string{a, b} {
		name := filepath.Join(side, "scripts", "domain-image-variant", "testdata", "tool-scope-before.txt")
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("historical evidence; deliberately not Go source\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareTool(a, b, out, strings.Repeat("a", 40)); err != nil {
		t.Fatal("historical fixture participated in executable baseline", err)
	}
}

func TestToolSourceVariantRefusesDriftBeforeMutation(t *testing.T) {
	for _, cut := range []string{"source-pin", "baseline-source", "harness", "mode-drift", "helper-missing", "output", "overlap", "revision"} {
		t.Run(cut, func(t *testing.T) {
			a, b, out := toolFixture(t)
			revision := strings.Repeat("a", 40)
			switch cut {
			case "source-pin":
				for _, side := range []string{a, b} {
					name := filepath.Join(side, filepath.FromSlash(toolTarget))
					data, err := os.ReadFile(name)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(name, append(data, "\n// unreviewed source drift\n"...), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "baseline-source":
				if err := os.WriteFile(filepath.Join(b, filepath.FromSlash(toolTarget)), []byte("unreviewed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "harness":
				if err := os.WriteFile(filepath.Join(b, "identical-harness"), []byte("longer deadline"), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode-drift":
				if err := os.Chmod(filepath.Join(b, filepath.FromSlash(toolTarget)), 0400); err != nil {
					t.Fatal(err)
				}
			case "helper-missing":
				for _, side := range []string{a, b} {
					if err := os.Remove(filepath.Join(side, "scripts", "domain-image-variant", "tool_scope.go")); err != nil {
						t.Fatal(err)
					}
				}
			case "output":
				out = filepath.Join(a, "evidence")
			case "overlap":
				b = a
			case "revision":
				revision = "HEAD"
			}
			beforeA, err := tree(a)
			if err != nil {
				t.Fatal(err)
			}
			beforeB, err := tree(b)
			if err != nil {
				t.Fatal(err)
			}
			if err := prepareTool(a, b, out, revision); err == nil {
				t.Fatal("unsafe comparison accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("refusal created evidence output", err)
			}
			afterA, err := tree(a)
			if err != nil || !reflect.DeepEqual(beforeA, afterA) {
				t.Fatal("candidate changed before refusal", err)
			}
			afterB, err := tree(b)
			if err != nil || !reflect.DeepEqual(beforeB, afterB) {
				t.Fatal("baseline changed before refusal", err)
			}
		})
	}
}

func TestToolVariantASTSelectionRefusesDrift(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(toolTarget)))
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []struct{ name, from, to string }{
		{"method", "compareInOriginalFileObservation(ctx context.Context, compare", "otherComparison(ctx context.Context, compare"},
		{"receiver", "func (r *syntheticBaselineExecutionResource) compareInOriginalFileObservation", "func (r *foreignResource) compareInOriginalFileObservation"},
		{"assignment", "result := domainTCPBaselineToolComparison(", "result = domainTCPBaselineToolComparison("},
		{"callee", "result := domainTCPBaselineToolComparison(", "result := otherComparison("},
		{"context", "result := domainTCPBaselineToolComparison(ctx,", "result := domainTCPBaselineToolComparison(other, "},
		{"duplicate-result", "\n\tresult = errors.Join(result, association(ctx))", "\n\tresult := errors.New(\"duplicate\")\n\tresult = errors.Join(result, association(ctx))"},
		{"duplicate-call", "\n\tresult = errors.Join(result, association(ctx))", "\n\t_ = domainTCPBaselineToolComparison(ctx, nil, nil)\n\tresult = errors.Join(result, association(ctx))"},
	} {
		t.Run(cut.name, func(t *testing.T) {
			changed := bytes.Replace(source, []byte(cut.from), []byte(cut.to), 1)
			if bytes.Equal(changed, source) {
				t.Fatal("test did not modify source")
			}
			if _, _, err := toolVariant(changed); err == nil {
				t.Fatal("unreviewed comparison shape accepted")
			}
		})
	}
	baseline, _, err := toolVariant(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := toolVariant(baseline); err == nil {
		t.Fatal("already modified initializer accepted")
	}
}

func TestToolVariantRetainsCurrentFileObservationContracts(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(toolTarget)))
	if err != nil {
		t.Fatal(err)
	}
	baseline, _, err := toolVariant(source)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"candidate": source, "baseline": baseline} {
		file, err := parser.ParseFile(token.NewFileSet(), toolTarget, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		callbacks, loans := 0, map[string]int{}
		ast.Inspect(file, func(node ast.Node) bool {
			if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == "observeOriginalFiles" {
				if len(fn.Type.Params.List) != 2 {
					t.Fatal(name, "file-observation parameters drifted")
				}
				typ, err := normalized(fn.Type.Params.List[1].Type)
				if err != nil || string(typ) != "func(context.Context, *xrayDomainTCPFileObservation) error" {
					t.Fatal(name, "lost current context-bearing callback", string(typ), err)
				}
				callbacks++
			}
			if call, ok := node.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "observeOriginalPriorFiles" {
					text, err := normalized(call)
					if err != nil {
						t.Fatal(err)
					}
					loans[string(text)]++
				}
			}
			return true
		})
		wantLoans := map[string]int{"process.observeOriginalPriorFiles(ctx, true, use)": 1, "process.observeOriginalPriorFiles(observed, false, compare)": 1}
		if callbacks != 1 || !reflect.DeepEqual(loans, wantLoans) {
			t.Fatal(name, "current file-observation loans were not preserved", callbacks, loans)
		}
	}
}
