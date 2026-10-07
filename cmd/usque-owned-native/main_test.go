package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
)

func TestCommandHasNoIssuerAndNeverLoadsMissingAccount(t *testing.T) {
	base := t.TempDir()
	args := []string{"--run-existing-account", "--mode", "h2", "--binary", filepath.Join(base, "usque"),
		"--binary-sha256", "a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10",
		"--account", filepath.Join(base, "PRIVATE-MISSING-ACCOUNT"), "--account-sha256", strings.Repeat("a", 64), "--work-parent", filepath.Join(base, "PRIVATE-MISSING-PARENT")}
	var output bytes.Buffer
	if code := execute(context.Background(), args, &output); code != 3 {
		t.Fatalf("exit %d: %s", code, output.String())
	}
	var result nativeaccept.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "blocked" || result.Settlement != "not-acquired" || result.SecretCleanup != "not-staged" || result.Observation != nil ||
		(result.Code != "core-retained-issuer-unavailable" && result.Code != "native-linux-required") || strings.Contains(output.String(), "PRIVATE-") {
		t.Fatalf("unsafe command result: %s", output.String())
	}
	if retainedCOREIssuer() != nil {
		t.Fatal("unreviewed authority added to command")
	}
}

func TestCommandRedactsParseFailuresAndStaticHelp(t *testing.T) {
	var output bytes.Buffer
	if execute(context.Background(), []string{"--register=PRIVATE-TOKEN"}, &output) != 2 || strings.Contains(output.String(), "PRIVATE-TOKEN") {
		t.Fatal("parse input echoed")
	}
	output.Reset()
	if execute(context.Background(), []string{"--help"}, &output) != 0 || output.String() != nativeaccept.Usage {
		t.Fatal("static help failed")
	}
}
