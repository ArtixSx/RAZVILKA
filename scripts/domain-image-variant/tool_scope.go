package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const toolTarget = "internal/dataplane/domain_tcp_tool_observation.go"
const toolComparisonMethodName = "compareInOriginalFileObservation"
const toolReplacement = "errors.Join(read(ctx), association(ctx))"

// Updated only after independent review of the exact complete candidate file.
const toolCandidateSHA = "04d182ba66ab541e2caeff8d223944dc1495102e7f3defa4a0e1a98856e6fa90"

func toolComparisonMethod(file *ast.File) (*ast.FuncDecl, error) {
	var found *ast.FuncDecl
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != toolComparisonMethodName {
			continue
		}
		if found != nil {
			return nil, errors.New("duplicate standalone tool comparison")
		}
		found = fn
	}
	if found == nil || found.Body == nil || found.Recv == nil || len(found.Recv.List) != 1 {
		return nil, errors.New("missing standalone tool comparison")
	}
	pointer, ok := found.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return nil, errors.New("standalone tool comparison receiver drift")
	}
	receiver, ok := pointer.X.(*ast.Ident)
	if !ok || receiver.Name != "syntheticBaselineExecutionResource" {
		return nil, errors.New("standalone tool comparison receiver drift")
	}
	return found, nil
}

func toolResultInitializer(fn *ast.FuncDecl) (*ast.AssignStmt, int, error) {
	var found *ast.AssignStmt
	index := -1
	for i, statement := range fn.Body.List {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			continue
		}
		name, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok || name.Name != "result" {
			continue
		}
		if found != nil {
			return nil, -1, errors.New("duplicate standalone result initializer")
		}
		found, index = assignment, i
	}
	if found == nil {
		return nil, -1, errors.New("missing standalone result initializer")
	}
	return found, index, nil
}

// Disable only the standalone tool bracket in current source. In particular,
// never restore the historical file: its file-observation callback and loan
// contracts predate the current readers. All other source bytes are retained.
func toolVariant(source []byte) ([]byte, int, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, toolTarget, source, 0)
	if err != nil {
		return nil, 0, err
	}
	fn, err := toolComparisonMethod(file)
	if err != nil {
		return nil, 0, err
	}
	assignment, index, err := toolResultInitializer(fn)
	if err != nil {
		return nil, 0, err
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 3 || call.Ellipsis.IsValid() {
		return nil, 0, errors.New("standalone tool comparison call drift")
	}
	callee, named := call.Fun.(*ast.Ident)
	parent, parentNamed := call.Args[0].(*ast.Ident)
	_, observer := call.Args[1].(*ast.FuncLit)
	_, reader := call.Args[2].(*ast.FuncLit)
	if !named || callee.Name != "domainTCPBaselineToolComparison" || !parentNamed || parent.Name != "ctx" || !observer || !reader {
		return nil, 0, errors.New("standalone tool comparison arguments drift")
	}
	calls := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "domainTCPBaselineToolComparison" {
				calls++
			}
		}
		return true
	})
	if calls != 1 {
		return nil, 0, errors.New("standalone tool comparison call count drift")
	}
	start, end := set.Position(call.Pos()).Offset, set.Position(call.End()).Offset
	changed := append([]byte{}, source[:start]...)
	changed = append(changed, toolReplacement...)
	changed = append(changed, source[end:]...)
	changedSet := token.NewFileSet()
	changedFile, err := parser.ParseFile(changedSet, toolTarget, changed, 0)
	if err != nil {
		return nil, 0, err
	}
	changedMethod, err := toolComparisonMethod(changedFile)
	if err != nil {
		return nil, 0, err
	}
	changedAssignment, changedIndex, err := toolResultInitializer(changedMethod)
	if err != nil || changedIndex != index || len(changedMethod.Body.List) != len(fn.Body.List) {
		return nil, 0, errors.New("standalone tool comparison statement drift")
	}
	changedExpression := changedAssignment.Rhs[0]
	expression, err := normalized(changedExpression)
	if err != nil || string(expression) != toolReplacement {
		return nil, 0, errors.New("standalone tool replacement drift")
	}
	changedStart, changedEnd := changedSet.Position(changedExpression.Pos()).Offset, changedSet.Position(changedExpression.End()).Offset
	// Undo the sole expression in both representations. The AST check protects
	// structure; whole-file byte parity also preserves comments and whitespace.
	changedAssignment.Rhs[0] = assignment.Rhs[0]
	originalAST, originalErr := normalized(file)
	restoredAST, restoredErr := normalized(changedFile)
	if originalErr != nil || restoredErr != nil || !bytes.Equal(originalAST, restoredAST) {
		return nil, 0, errors.New("whole-file tool AST parity refused")
	}
	restored := append([]byte{}, changed[:changedStart]...)
	restored = append(restored, source[start:end]...)
	restored = append(restored, changed[changedEnd:]...)
	if !bytes.Equal(restored, source) {
		return nil, 0, errors.New("whole-file tool byte parity refused")
	}
	return changed, 1 + bytes.Count(source[:start], []byte{'\n'}), nil
}

// Both archives come from the same candidate. The baseline is a synthetic
// single-expression variant, not a historical revision or a production knob.
func prepareTool(candidate, baseline, output, revision string) error {
	if len(revision) != 40 || revision != strings.ToLower(revision) {
		return errors.New("exact revision required")
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return err
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
	if a[toolTarget].SHA256 != toolCandidateSHA {
		return errors.New("reviewed tool comparison source drift")
	}
	after, err := os.ReadFile(filepath.Join(candidate, filepath.FromSlash(toolTarget)))
	if err != nil || hash(after) != toolCandidateSHA {
		return errors.New("candidate changed while reading")
	}
	before, line, err := toolVariant(after)
	if err != nil {
		return err
	}
	baselineSHA := hash(before)
	helpers := map[string]string{}
	for _, name := range []string{"scripts/domain-image-variant/main.go", "scripts/domain-image-variant/tool_scope.go"} {
		if a[name].SHA256 == "" {
			return errors.New("helper provenance missing")
		}
		helpers[name] = a[name].SHA256
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(baseline, filepath.FromSlash(toolTarget)), before, 0600); err != nil {
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
	for p, row := range a {
		want[p] = row
	}
	row := want[toolTarget]
	row.Bytes, row.SHA256 = int64(len(before)), baselineSHA
	want[toolTarget] = row
	if !reflect.DeepEqual(a, afterA) || !reflect.DeepEqual(want, afterB) {
		return errors.New("complete tree parity refused after tool comparison patch")
	}
	report := map[string]any{"schema": 2, "source_commit": revision, "comparison": "baseline-tools", "baseline": "synthetic-current-source-without-standalone-tool-bracket", "candidate": "unmodified-current-source-bounded-tool-comparison", "changed_path": toolTarget, "changed_method": toolComparisonMethodName, "changed_expressions": 1, "changed_line": line, "replacement_expression": toolReplacement, "baseline_file_sha256": baselineSHA, "candidate_file_sha256": toolCandidateSHA, "whole_file_ast_parity": true, "whole_file_byte_parity": true, "whole_tree_parity": true, "limits": []string{"Only one result initializer expression differs; all other source bytes and file modes are identical", "The standalone tool bracket is disabled; before/after associations and current file-observation loans remain", "Executable image feature, callback signatures, metadata reads and actual version children remain unchanged", "Original deadlines, native harness, dependencies and cleanup remain unchanged", "This generated baseline is not a historical file, whole-commit comparison or production release"}}
	report["helpers_sha256"] = helpers
	report["replay_sources"] = map[string]string{"before.go.txt": baselineSHA, "after.go.txt": toolCandidateSHA}
	report["baseline_build_scope"] = "Both sides compile the same native app.test harness against production dataplane; dataplane package tests are not compiled into that harness"
	for name, data := range map[string][]byte{"before.go.txt": before, "after.go.txt": after} {
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			return err
		}
	}
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
