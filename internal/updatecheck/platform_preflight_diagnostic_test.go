package updatecheck

import (
	"strings"
	"testing"
)

func TestInstallerPreflightFailureHasClosedCodesWithoutPrivateOutput(t *testing.T) {
	for _, test := range []struct{ output, wanted string }{
		{"Target binary has an incompatible self update schema; installation unchanged\n", "installer-preflight-self-update-schema-refused"},
		{"Target binary cannot preserve self update recovery; installation unchanged\n", "installer-preflight-self-update-schema-refused"},
		{"Self update metadata is unknown or incompatible; installation unchanged\n", "installer-preflight-self-update-metadata-refused"},
		{"Target binary cannot read all retained node history; installation unchanged\n", "installer-preflight-node-history-refused"},
		{"Target version cannot read the current autonomy state; installation unchanged\n", "installer-preflight-autonomy-refused"},
		{"private-token=DO-NOT-PUBLISH endpoint secret stderr path /private/user\n", "installer-preflight-refused"},
		{"prefix Target binary has an incompatible self update schema; installation unchanged secret\n", "installer-preflight-refused"},
	} {
		if got := installerPreflightFailureCode(test.output); got != test.wanted || strings.Contains(got, "DO-NOT-PUBLISH") {
			t.Fatalf("unexpected public code %q", got)
		}
	}
	output := &cappedOutput{maximum: 8192}
	private := strings.Repeat("private", 10000)
	if n, err := output.Write([]byte(private)); err != nil || n != len(private) || output.Len() != 8192 {
		t.Fatal("diagnostic did not drain bounded output")
	}
	if got := installerPreflightFailureCode(output.String()); got != "installer-preflight-refused" {
		t.Fatal("unknown bounded stderr became a public diagnostic")
	}
}
