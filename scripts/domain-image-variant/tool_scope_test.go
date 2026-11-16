package main

import (
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
		for _, p := range []string{toolTarget, toolBaselineFile, "scripts/domain-image-variant/tool_scope.go"} {
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
			if path != toolTarget || afterB[path].SHA256 != toolBaselineSHA || afterB[path].Mode != row.Mode {
				t.Fatal("unreviewed difference", path)
			}
		}
	}
	if difference != 1 || len(afterB) != len(before) {
		t.Fatal("source parity", difference)
	}
	if err := prepareTool(a, b, filepath.Join(filepath.Dir(out), "repeat"), strings.Repeat("a", 40)); err == nil {
		t.Fatal("modified source adopted")
	}
}

func TestToolSourceVariantRefusesDriftBeforeMutation(t *testing.T) {
	for _, cut := range []string{"candidate-pin", "baseline-pin", "harness", "output", "overlap", "revision"} {
		t.Run(cut, func(t *testing.T) {
			a, b, out := toolFixture(t)
			revision := strings.Repeat("a", 40)
			switch cut {
			case "candidate-pin", "baseline-pin":
				p := toolTarget
				if cut == "baseline-pin" {
					p = toolBaselineFile
				}
				for _, side := range []string{a, b} {
					if err := os.WriteFile(filepath.Join(side, filepath.FromSlash(p)), []byte("unreviewed\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "harness":
				if err := os.WriteFile(filepath.Join(b, "identical-harness"), []byte("longer deadline"), 0600); err != nil {
					t.Fatal(err)
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
