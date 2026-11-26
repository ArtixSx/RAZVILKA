package engineconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGuidedShellReadsCompleteQuotedStrategies(t *testing.T) {
	content := "# header\nexport NFQWS_ARGS=\"--first=$MODE_LIST\n\n  --new\n  --payload=\\\"quoted\\\" --path=C:\\\\fixture\n\" # keep me\nNFQWS_ARGS_QUIC='--literal=$NAME\n# part of the value\n--udp'\nIPV6_ENABLED=1\n"
	got, err := parseShellAssignments(content)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"NFQWS_ARGS":      "--first=$MODE_LIST\n\n  --new\n  --payload=\"quoted\" --path=C:\\fixture\n",
		"NFQWS_ARGS_QUIC": "--literal=$NAME\n# part of the value\n--udp",
		"IPV6_ENABLED":    "1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("quoted strategy was truncated, escaped incorrectly or interpreted")
	}
	updated, err := updateShellAssignments(content, got)
	if err != nil || updated != content {
		t.Fatalf("no-op did not preserve exact bytes: %v", err)
	}
}

func TestGuidedShellReplacesWholeValueAndPreservesOtherBytes(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(map[string]string{"\n": "LF", "\r\n": "CRLF"}[newline], func(t *testing.T) {
			prefix := "# unchanged header\n\n  export\tNFQWS_ARGS="
			suffix := "  # keep inline comment\nOTHER='private fixture literal'\n# unchanged footer\n\n"
			old := "\"--old\n--new\n--old-tail\""
			content := strings.ReplaceAll(prefix+old+suffix, "\n", newline)
			updated, err := updateShellAssignments(content, map[string]string{"NFQWS_ARGS": "--replacement\n--new\n--end"})
			if err != nil {
				t.Fatal(err)
			}
			want := strings.ReplaceAll(prefix+"\"--replacement\n--new\n--end\""+suffix, "\n", newline)
			if updated != want || strings.Contains(updated, "--old-tail") {
				t.Fatal("multiline tail, comments, export prefix or unrelated bytes changed incorrectly")
			}
			parsed, err := parseShellAssignments(updated)
			if err != nil || parsed["NFQWS_ARGS"] != "--replacement\n--new\n--end" {
				t.Fatalf("saved strategy did not round-trip: %v", err)
			}
		})
	}
}

func TestGuidedShellPreservesLiteralSingleQuotesAndContinuationSemantics(t *testing.T) {
	content := "NFQWS_ARGS='--literal=$NAME\n--old'\nCONT=first\\\nsecond\nDOUBLE=\"first\\\nsecond\"\nESCAPED=one\\ two\n"
	parsed, err := parseShellAssignments(content)
	if err != nil {
		t.Fatal(err)
	}
	if parsed["CONT"] != "firstsecond" || parsed["DOUBLE"] != "firstsecond" || parsed["ESCAPED"] != "one two" {
		t.Fatal("backslash continuation or escaped space has incorrect value")
	}
	parsed["NFQWS_ARGS"] = "--literal=$NAME\n--new"
	updated, err := updateShellAssignments(content, parsed)
	if err != nil || !strings.HasPrefix(updated, "NFQWS_ARGS='--literal=$NAME\n--new'\n") {
		t.Fatalf("single-quoted literal reference became an expansion: %v", err)
	}
	if !strings.HasSuffix(updated, content[strings.Index(content, "CONT="):]) {
		t.Fatal("unchanged continuation spelling was rewritten")
	}
}

func TestGuidedShellRejectsUnsupportedSyntaxWithoutProducingContent(t *testing.T) {
	for name, content := range map[string]string{
		"unterminated":       "NFQWS_ARGS=\"--first\n--tail\n",
		"duplicate":          "NFQWS_ARGS=old\nNFQWS_ARGS=new\n",
		"command tail":       "NFQWS_ARGS=\"--first\"; echo fixture\n",
		"command expansion":  "NFQWS_ARGS=\"$(echo fixture)\"\n",
		"backtick expansion": "NFQWS_ARGS=\"`echo fixture`\"\n",
		"parameter operator": "NFQWS_ARGS=\"${VALUE:-fixture}\"\n",
		"special parameter":  "NFQWS_ARGS=\"$?\"\n",
		"escaped dollar":     "NFQWS_ARGS=\"\\$NAME\"\n",
		"concatenation":      "NFQWS_ARGS=\"first\"'second'\n",
		"hash concatenation": "NFQWS_ARGS=\"first\"#literal\n",
		"conditional":        "if true; then\nNFQWS_ARGS=fixture\nfi\n",
		"command prefix":     "NFQWS_ARGS=fixture echo x\n",
		"multiple values":    "NFQWS_ARGS=fixture OTHER=value\n",
		"here document":      "cat <<END\nNFQWS_ARGS=fixture\nEND\n",
		"escaped nul":        "NFQWS_ARGS=one\\\x00two\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseShellAssignments(content); err == nil {
				t.Fatal("unsupported shell syntax was accepted")
			}
			updated, err := updateShellAssignments(content, map[string]string{"NFQWS_ARGS": "--safe"})
			if err == nil || updated != "" {
				t.Fatal("unsupported source produced replacement content")
			}
		})
	}
}

func TestGuidedShellNewMultilineArgumentsRemainOneQuotedValue(t *testing.T) {
	value := "\n--filter-tcp=443 $MODE_LIST\n--new\n--payload=\"fixture\"\n"
	field := GuidedField{ID: "NFQWS_ARGS", Type: "arguments"}
	if err := validateGuidedValue(field, value); err != nil {
		t.Fatal(err)
	}
	updated, err := updateShellAssignments("# fixture without final newline", map[string]string{"NFQWS_ARGS": value, "LOG_LEVEL": "0"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseShellAssignments(updated)
	if err != nil || parsed["NFQWS_ARGS"] != value || parsed["LOG_LEVEL"] != "0" || len(parsed) != 2 {
		t.Fatalf("newlines escaped the assigned value: %v", err)
	}
	if !strings.HasPrefix(updated, "# fixture without final newline\nLOG_LEVEL=") {
		t.Fatal("new fields were not appended deterministically")
	}
	for _, unsafe := range []string{"--one\n$(echo fixture)", "--one\n`echo fixture`", "--one\n; echo fixture", "$?", "$1", "$@", "\\$NAME", "${NAME}", "--one\r--two", "--one\x00--two"} {
		if err := validateGuidedValue(field, unsafe); err == nil {
			t.Fatal("unsafe new multiline argument accepted")
		}
	}
	if err := validateGuidedValue(GuidedField{ID: "ISP_INTERFACE", Type: "interfaces"}, "eth0\neth1"); err == nil {
		t.Fatal("multiline allowance escaped arguments fields")
	}
}

func TestStageGuidedShellRoundTripAndFailurePreservesStage(t *testing.T) {
	content := "# full fixture\nISP_INTERFACE=eth0\nNFQWS_EXTRA_ARGS=\"$MODE_AUTO\"\nMODE_AUTO=\"--hostlist-auto=/fixture\"\nNFQWS_ARGS=\"--first=$MODE_AUTO\n--new\n--end\" # strategy\nLOG_LEVEL=0\n"
	checkGuidedShellUnrelatedEdit(t, []byte(content))
	for name, invalid := range map[string]string{
		"unclosed existing quote": "NFQWS_ARGS=\"--unterminated\n",
		"existing command":        "NFQWS_ARGS=\"$(echo fixture)\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			m := New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
			if _, err := m.Stage("nfqws2", "main", invalid); err != nil {
				t.Fatal(err)
			}
			before, err := m.readStageImage(t.Context(), "nfqws2", "main")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.StageGuided("nfqws2", "main", map[string]string{"LOG_LEVEL": "1"}); err == nil {
				t.Fatal("invalid existing source was staged")
			}
			after, err := m.readStageImage(t.Context(), "nfqws2", "main")
			if err != nil || !bytes.Equal(before.Data, after.Data) {
				t.Fatal("failed guided update changed the existing stage")
			}
		})
	}
}

func TestStageGuidedShellEditsMultilineStrategyAsOneAssignment(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
	prefix := "# retained header\nexport NFQWS_ARGS="
	suffix := " # retained comment\nOTHER=fixture\n"
	if _, err := m.Stage("nfqws2", "main", prefix+"\"--old\n--old-tail\""+suffix); err != nil {
		t.Fatal(err)
	}
	view, err := m.Guided("nfqws2", "main")
	if err != nil {
		t.Fatal(err)
	}
	strategy := "\n--first=$MODE_LIST\n--new\n--payload=\"fixture\"\n"
	view.Values["NFQWS_ARGS"] = strategy
	if _, err := m.StageGuided("nfqws2", "main", view.Values); err != nil {
		t.Fatal(err)
	}
	after, err := m.Guided("nfqws2", "main")
	if err != nil || after.Values["NFQWS_ARGS"] != strategy {
		t.Fatalf("edited multiline strategy did not round-trip: %v", err)
	}
	image, err := m.readStageImage(t.Context(), "nfqws2", "main")
	encoded, encodeErr := shellValue(strategy, '"')
	if err != nil || encodeErr != nil || string(image.Data) != prefix+encoded+suffix {
		t.Fatal("stage retained a stale tail or changed surrounding source")
	}
}

func TestGuidedShellFullFormNoOpPreservesAbsentAndExplicitEmptyDefaults(t *testing.T) {
	for name, content := range map[string]string{
		"existing empty":  "",
		"absent defaults": "# untouched\nNFQWS_ARGS=\"--first\n--last\" # keep\n",
		"empty defaults":  "# untouched\nNFQWS_EXTRA_ARGS=''\nTCP_PORTS=\"\"\nLOG_LEVEL=0\n",
	} {
		t.Run(name, func(t *testing.T) {
			m := New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
			if _, err := m.Stage("nfqws2", "main", content); err != nil {
				t.Fatal(err)
			}
			view, err := m.Guided("nfqws2", "main")
			if err != nil {
				t.Fatal(err)
			}
			if name == "empty defaults" && (view.Values["NFQWS_EXTRA_ARGS"] != "" || view.Values["TCP_PORTS"] != "") {
				t.Fatal("explicit empty source was displayed as an active default")
			}
			if _, err := m.StageGuided("nfqws2", "main", view.Values); err != nil {
				t.Fatal(err)
			}
			image, err := m.readStageImage(t.Context(), "nfqws2", "main")
			if err != nil || string(image.Data) != content {
				t.Fatal("full no-op form materialized missing defaults or replaced explicit empty values")
			}
		})
	}
}

func TestGuidedShellMissingFileCreatesSubmittedDefaults(t *testing.T) {
	values := map[string]string{}
	fields := guidedFields("nfqws2", "main")
	for _, field := range fields {
		values[field.ID] = field.Default
	}
	changed, err := shellGuidedChanges("", fields, values, true)
	if err != nil || len(changed) != len(values) {
		t.Fatal("missing source lost defaults needed for initial setup")
	}
	content, err := encodeGuided("shell", nil, fields, changed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseShellAssignments(string(content))
	if err != nil || parsed["TCP_PORTS"] != "80,443" || parsed["NFQWS_EXTRA_ARGS"] != "$MODE_AUTO" || len(parsed) != len(values) {
		t.Fatal("new setup did not materialize the submitted assignments")
	}
}

// Optional local HIL fixture: read only the explicitly provided file, never
// execute it or include its content in failures. No router writes are made.
func TestGuidedShellPrivateFixtureUnrelatedEdit(t *testing.T) {
	path := os.Getenv("RAZVILKA_TEST_NFQWS_FIXTURE")
	if path == "" {
		t.Skip("private fixture path not provided")
	}
	content, err := os.ReadFile(path)
	if err != nil || len(content) > maxConfigBytes {
		t.Fatal("private fixture unavailable or too large")
	}
	checkGuidedShellUnrelatedEdit(t, content)
}

func checkGuidedShellUnrelatedEdit(t *testing.T, content []byte) {
	t.Helper()
	m := New(filepath.Join(t.TempDir(), "stage"), t.TempDir())
	if _, err := m.Stage("nfqws2", "main", string(content)); err != nil {
		t.Fatal("could not create isolated fixture stage")
	}
	view, err := m.Guided("nfqws2", "main")
	if err != nil {
		t.Fatalf("guided fixture read failed: %v", err)
	}
	original, err := scanShellAssignments(string(content))
	if err != nil {
		t.Fatal("fixture scan failed")
	}
	if _, err := m.StageGuided("nfqws2", "main", view.Values); err != nil {
		t.Fatalf("full no-op form failed: %v", err)
	}
	noOp, err := m.readStageImage(t.Context(), "nfqws2", "main")
	if err != nil || !bytes.Equal(noOp.Data, content) {
		t.Fatal("full no-op form changed fixture bytes")
	}
	values := view.Values
	if values["LOG_LEVEL"] == "1" {
		values["LOG_LEVEL"] = "0"
	} else {
		values["LOG_LEVEL"] = "1"
	}
	// The whole form, including all unchanged strategy references, is submitted.
	if _, err := m.StageGuided("nfqws2", "main", values); err != nil {
		t.Fatalf("unrelated guided edit failed: %v", err)
	}
	image, err := m.readStageImage(t.Context(), "nfqws2", "main")
	if err != nil {
		t.Fatal("could not read isolated staged result")
	}
	updated, err := scanShellAssignments(string(image.Data))
	if err != nil {
		t.Fatal("updated fixture is not a simple assignment document")
	}
	byKey := map[string]shellAssignment{}
	for _, a := range updated {
		byKey[a.key] = a
	}
	for _, before := range original {
		after, ok := byKey[before.key]
		if !ok {
			t.Fatal("unrelated assignment was removed")
		}
		if before.key == "LOG_LEVEL" {
			if after.value != values["LOG_LEVEL"] {
				t.Fatal("requested harmless edit was not saved")
			}
			continue
		}
		if before.value != after.value || !bytes.Equal(content[before.start:before.end], image.Data[after.start:after.end]) {
			t.Fatal("unrelated assignment bytes or multiline value changed")
		}
	}
	beforeFailure := append([]byte(nil), image.Data...)
	if _, err := m.StageGuided("nfqws2", "main", map[string]string{"NFQWS_ARGS": "--first\n$(echo fixture)"}); err == nil {
		t.Fatal("command substitution was accepted")
	}
	image, err = m.readStageImage(t.Context(), "nfqws2", "main")
	if err != nil || !bytes.Equal(image.Data, beforeFailure) {
		t.Fatal("refused edit changed the prior stage")
	}
}
