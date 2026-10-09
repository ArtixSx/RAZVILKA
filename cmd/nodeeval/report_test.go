package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestEarlyCheckerFailureReportsClosedReasonAndStops(t *testing.T) {
	for _, row := range []struct {
		err  error
		code string
	}{
		{dataplane.ErrExactNodeNetworkChanged, "node-network-changed"},
		{dataplane.ErrExactNodeBusy, "node-checker-busy"},
		{dataplane.ErrExactNodeUnavailable, "node-checker-unavailable"},
		{dataplane.ErrExactNodeRuntime, "node-runtime-unavailable"},
		{context.Canceled, "node-check-canceled"},
		{context.DeadlineExceeded, "node-check-deadline"},
		{errors.New("private-endpoint"), "node-check-failed"},
	} {
		t.Run(row.code, func(t *testing.T) {
			store := privateStoreFixture(t, 2)
			checker := &checkerFixture{engine: "xray", check: func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				return dataplane.NodeCheckResult{}, fmt.Errorf("private-profile: %w", row.err)
			}}
			var out bytes.Buffer
			code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) { return "wan-0123456789ab", nil }, 2, json.NewEncoder(&out))
			reports := decodeReports(t, out.Bytes())
			if code != 1 || len(reports) != 2 || reports[0].Code != row.code || reports[0].HTTPSPass || reports[1].Finished || reports[1].Code != "checker-error" || checker.checks != 1 || checker.recovers != 1 || strings.Contains(out.String(), "private-") {
				t.Fatal("early error lost classification, leaked data or continued", code, reports)
			}
		})
	}
}
