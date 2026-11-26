package main

import (
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
	"testing"
)

func TestExecutionReaderStandaloneMetadata(t *testing.T) {
	if dataplane.ExecutionReadVersion != updatecheck.ExecutionHistoryReadVersion {
		t.Fatal("format reader contract diverged")
	}
	for _, tc := range []struct {
		args    []string
		handled bool
		code    int
	}{
		{[]string{"-dataplane-execution-read-version"}, true, 0},
		{[]string{"--dataplane-execution-read-version"}, true, 2},
		{[]string{"-dataplane-execution-read-version=true"}, true, 2},
		{[]string{"-dataplane-execution-read-version", "-config=/other"}, true, 2},
		{[]string{"-version"}, false, 0},
	} {
		if handled, code := runExecutionReadCommand(tc.args); handled != tc.handled || code != tc.code {
			t.Fatal(tc.args, handled, code)
		}
	}
}
