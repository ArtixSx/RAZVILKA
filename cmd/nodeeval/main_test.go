package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Explicit CLI orchestration fixtures: no executable, DNS, network, proxy or
// kernel operation occurs. Store/history assertions use the real private API.
type checkerFixture struct {
	engine           string
	checks, recovers int
	check            func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error)
	recoverErr       error
}

func (c *checkerFixture) EngineID() string { return c.engine }
func (c *checkerFixture) Check(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
	c.checks++
	return c.check(ctx, r)
}
func (c *checkerFixture) Recover(ctx context.Context) error {
	c.recovers++
	if end, ok := ctx.Deadline(); !ok || time.Until(end) > 8*time.Second {
		return errors.New("unbounded recovery")
	}
	return c.recoverErr
}

func positiveFixture(r dataplane.NodeCheckRequest, engine string) dataplane.NodeCheckResult {
	now := time.Now()
	return dataplane.NodeCheckResult{NodeID: r.NodeID, ServiceID: r.Service.ID, NetworkProfile: r.NetworkProfile, RoutePathID: engine + ":" + r.NodeID,
		StartedAt: now, FinishedAt: now, ExpiresAt: now.Add(time.Minute), TestLevel: "service", Stage: "service", Verdict: evidence.VerdictPass, Available: true, HTTPStatus: 200}
}

func privateStoreFixture(t *testing.T, count int) *nodestore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := nodestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var lines []string
	for i := range count {
		lines = append(lines, fmt.Sprintf("vless://11111111-1111-4111-8111-%012d@private-node-%d.example:443?security=tls&sni=private-sni.example&type=tcp", i+1, i))
	}
	if _, err := s.Import(context.Background(), nodestore.Source{ID: "test-private", Kind: "manual"}, strings.Join(lines, "\n"), time.Now(), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	return s
}

func decodeReports(t *testing.T, data []byte) []report {
	t.Helper()
	var result []report
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var r report
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		result = append(result, r)
	}
	return result
}

func TestEvaluateFreshEngineChecksLimitAndDoesNotWriteLiveHistory(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			store := privateStoreFixture(t, 3)
			before, err := store.ExportPrivate(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			checker := &checkerFixture{engine: engine, check: func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				return positiveFixture(r, engine), nil
			}}
			profiles := 0
			var output bytes.Buffer
			code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) {
				profiles++
				return fmt.Sprintf("wan-%012x", profiles), nil
			}, 2, json.NewEncoder(&output))
			after, err := store.ExportPrivate(context.Background())
			if err != nil || !bytes.Equal(before.Content, after.Content) || code != 0 || profiles != 2 || checker.checks != 2 || checker.recovers != 1 {
				t.Fatal("wrong limit, cached profile, history mutation or cleanup", code, profiles, checker.checks, checker.recovers, err)
			}
			rows := decodeReports(t, output.Bytes())
			if len(rows) != 3 || !rows[0].Fresh || !rows[0].HTTPSPass || rows[2].Passed != 2 || !rows[2].Finished || rows[0].Engine != engine || rows[0].NodeID == "" {
				t.Fatal("fresh result lost identity or summary", rows)
			}
			for _, secret := range []string{"private-node", "private-sni", "11111111", "egress_ip", "outbound"} {
				if strings.Contains(output.String(), secret) {
					t.Fatal("private material entered report")
				}
			}
		})
	}
}

func TestEvaluateRejectsStaleWrongPathAndUnconfirmedCleanup(t *testing.T) {
	for _, cut := range []string{"stale", "wrong-engine", "wrong-profile", "direct-leak", "protocol-only", "cleanup-nil-error", "cleanup-code-only", "cleanup-stage-only", "error-and-cleanup-failure", "unsupported", "private-error"} {
		t.Run(cut, func(t *testing.T) {
			store := privateStoreFixture(t, 2)
			checker := &checkerFixture{engine: "sing-box"}
			checker.check = func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				result := positiveFixture(r, checker.engine)
				switch cut {
				case "stale":
					result.StartedAt = result.StartedAt.Add(-time.Hour)
				case "wrong-engine":
					result.RoutePathID = "xray:" + r.NodeID
				case "wrong-profile":
					result.NetworkProfile = "wan-other"
				case "direct-leak":
					result.DirectLeak = true
				case "protocol-only":
					result.TestLevel = "protocol"
				case "cleanup-nil-error":
					result.Stage, result.ErrorCode = "cleanup", "node-cleanup-failed"
				case "cleanup-code-only":
					result.ErrorCode = "node-cleanup-failed"
				case "cleanup-stage-only":
					result.Stage = "cleanup"
				case "error-and-cleanup-failure":
					checker.recoverErr = errors.New("private-node password")
					return result, errors.New("private-node password")
				case "unsupported":
					return dataplane.NodeCheckResult{}, dataplane.ErrExactNodeUnsupported
				case "private-error":
					result.Stage, result.ErrorCode = "secret-stage-uuid", "https://private-node/password"
					result.Message, result.EgressIP = "private-node password", "198.51.100.55"
					return result, errors.New("private-node password")
				}
				return result, nil
			}
			var output bytes.Buffer
			code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) { return "wan-0123456789ab", nil }, 2, json.NewEncoder(&output))
			rows := decodeReports(t, output.Bytes())
			last := rows[len(rows)-1]
			if code == 0 || rows[0].HTTPSPass || last.Passed != 0 || checker.recovers != 1 {
				t.Fatal("bad evidence or cleanup was accepted", code, rows, checker.recovers)
			}
			if strings.HasPrefix(cut, "cleanup-") || cut == "error-and-cleanup-failure" {
				if checker.checks != 1 || last.Code != "cleanup-unconfirmed" || last.Finished {
					t.Fatal("cleanup gap continued to next node", rows, checker.checks)
				}
			}
			if cut == "unsupported" && (code != 2 || checker.checks != 2 || rows[0].Code != "node-profile-unsupported") {
				t.Fatal("unsupported transport was converted or falsely scored", code, rows)
			}
			for _, secret := range []string{"private-node", "password", "198.51.100.55", "secret-stage-uuid"} {
				if strings.Contains(output.String(), secret) {
					t.Fatal("error or result leaked private values")
				}
			}
		})
	}
}

func TestEvaluateDeadlineStopsWithoutSecondCandidateOrCachedProfile(t *testing.T) {
	store := privateStoreFixture(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	checker := &checkerFixture{engine: "xray", check: func(c context.Context, _ dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		<-c.Done()
		return dataplane.NodeCheckResult{}, c.Err()
	}}
	var output bytes.Buffer
	started := time.Now()
	code := evaluate(ctx, context.Background(), store, checker, func(context.Context) (string, error) { return "wan-0123456789ab", nil }, 2, json.NewEncoder(&output))
	if code != 1 || checker.checks != 1 || checker.recovers != 1 || time.Since(started) > time.Second {
		t.Fatal("deadline widened or retried", code, checker.checks, checker.recovers)
	}
	checker.checks = 0
	output.Reset()
	code = evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) { return "", errors.New("private profile") }, 2, json.NewEncoder(&output))
	if code != 1 || checker.checks != 0 || strings.Contains(output.String(), "private profile") {
		t.Fatal("fresh profile failure reused old profile")
	}
}

func TestFinalCleanupFailureLeavesEarlierPassIncompleteWithoutRetry(t *testing.T) {
	store := privateStoreFixture(t, 1)
	checker := &checkerFixture{engine: "xray", recoverErr: errors.New("private cleanup error"), check: func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return positiveFixture(r, "xray"), nil
	}}
	var output bytes.Buffer
	code := evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) { return "wan-0123456789ab", nil }, 1, json.NewEncoder(&output))
	rows := decodeReports(t, output.Bytes())
	if code != 1 || checker.checks != 1 || checker.recovers != 1 || !rows[0].HTTPSPass || rows[1].Finished || rows[1].Code != "cleanup-unconfirmed" || strings.Contains(output.String(), "private cleanup error") {
		t.Fatal("final cleanup failure became overall acceptance or retried", code, rows)
	}
}

func TestOptionsAndWorkspaceFailClosedBeforeEffects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new-workspace")
	store := filepath.Join(t.TempDir(), "read-store")
	valid := []string{"-root", root, "-store", store}
	if _, err := parseOptions(valid); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{"-limit", "0"}, {"-limit", "129"}, {"-duration", "0"}, {"-duration", "2h"}, {"-check-timeout", "90s"}, {"-engine", "other"}, {"-preset", "igareck-black-vless"}, {"-port", "80"}, {"-port", "65535"}, {"-unknown-secret", "password"}} {
		var output bytes.Buffer
		if run(context.Background(), append(append([]string{}, valid...), extra...), &output) != 1 || strings.Contains(output.String(), "password") {
			t.Fatal("bad option accepted or leaked", extra)
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid invocation created workspace")
		}
	}
	if _, err := parseOptions([]string{"-root", root, "-store", filepath.Dir(root)}); err == nil {
		t.Fatal("read store/workspace overlap accepted")
	}
	short, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var output bytes.Buffer
	if run(short, valid, &output) != 1 || !strings.Contains(output.String(), "deadline-or-canceled") {
		t.Fatal("short parent deadline discarded cleanup reserve")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("already exhausted work budget created a workspace")
	}
	w, err := newWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := newWorkspace(root); err == nil {
		t.Fatal("existing workspace could be reused as fresh authority")
	}
	if _, err := w.historyAdmission(context.Background()); err == nil {
		t.Fatal("existing-store workspace manufactured history authority")
	}
}
