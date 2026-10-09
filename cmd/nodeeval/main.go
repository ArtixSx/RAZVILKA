// Command nodeeval is a bounded development probe, never a production route or
// history writer. HTTPS checks use the actual isolated exact-node checker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

const cleanupReserve = 20 * time.Second

type options struct {
	root, store, preset, engine, binary string
	port, limit                         int
	duration, checkTimeout              time.Duration
}

func parseOptions(args []string) (options, error) {
	var o options
	f := flag.NewFlagSet("nodeeval", flag.ContinueOnError)
	f.SetOutput(io.Discard) // An invalid argument may itself contain a secret.
	f.StringVar(&o.root, "root", "", "new private working directory; must not exist")
	f.StringVar(&o.store, "store", "", "existing private NodeStore, read only")
	f.StringVar(&o.preset, "preset", "", "approved feed ID imported only into the new isolated store")
	f.StringVar(&o.engine, "engine", "sing-box", "sing-box or xray")
	f.StringVar(&o.binary, "binary", "", "absolute checker runtime path; empty uses discovery")
	f.IntVar(&o.port, "port", 19291, "one temporary loopback SOCKS port")
	f.IntVar(&o.limit, "limit", 12, "total VLESS candidates, 1..128")
	f.DurationVar(&o.duration, "duration", 8*time.Minute, "overall budget, 30s..1h, including cleanup reserve")
	f.DurationVar(&o.checkTimeout, "check-timeout", 45*time.Second, "per-node budget, 1s..60s")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if len(f.Args()) != 0 || o.duration < 30*time.Second || o.duration > time.Hour || o.checkTimeout < time.Second || o.checkTimeout > time.Minute || o.limit < 1 || o.limit > 128 ||
		!absoluteClean(o.root) || (o.store == "") == (o.preset == "") || (o.engine != "sing-box" && o.engine != "xray") || o.port < 1024 || o.port > 65535-dataplane.MaxExactNodeSlots+1 || o.binary != "" && !absoluteClean(o.binary) {
		return o, errors.New("arguments")
	}
	if o.store != "" && (!absoluteClean(o.store) || pathsOverlap(o.root, o.store)) {
		return o, errors.New("arguments")
	}
	if o.preset != "" {
		approved := false
		for _, p := range providerfeed.Builtins() {
			approved = approved || p.ID == o.preset
		}
		if !approved {
			return o, errors.New("arguments")
		}
	}
	return o, nil
}

func absoluteClean(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

type report struct {
	Kind       string `json:"kind"`
	Code       string `json:"code,omitempty"`
	Engine     string `json:"engine,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	Candidate  int    `json:"candidate,omitempty"`
	Stage      string `json:"stage,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
	HTTPSPass  bool   `json:"https_pass"`
	Fresh      bool   `json:"fresh"`
	DirectLeak bool   `json:"direct_leak"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Checked    int    `json:"checked,omitempty"`
	Passed     int    `json:"https_passed,omitempty"`
	Imported   int    `json:"imported,omitempty"`
	Total      int    `json:"feed_entries,omitempty"`
	Rejected   int    `json:"rejected,omitempty"`
	Finished   bool   `json:"finished"`
	Scope      string `json:"scope,omitempty"`
}

const httpsScope = "fresh exact-node Telegram HTTPS by name/IP; no MTProto, account, media, voice, LAN/TUN or Selectable claim"

type checkStore interface {
	Snapshot(context.Context, time.Time) (nodestore.Snapshot, error)
	WithSecret(context.Context, string, func([]byte) error) error
}

type exactChecker interface {
	dataplane.NodeChecker
	EngineID() string
}

func recoverOnce(ctx context.Context, checker exactChecker) error {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return checker.Recover(bounded)
}

func telegramService() catalog.Service {
	return catalog.Service{ID: "custom-telegram-https", Name: "Telegram HTTPS", Domains: []string{"telegram.org"},
		Strategy: []string{"auto"}, ProbeURL: "https://telegram.org/"}
}

// No RecordCheck, Import, restore, history admission or route API exists on this
// existing-store evaluation interface. Cached health chooses order only.
func evaluate(ctx, cleanupCtx context.Context, store checkStore, checker exactChecker, freshProfile func(context.Context) (string, error), limit int, out *json.Encoder) int {
	finish := func(checked, passed int, code string) int {
		if out.Encode(report{Kind: "summary", Engine: checker.EngineID(), Checked: checked, Passed: passed, Finished: code == "", Code: code, Scope: httpsScope}) != nil {
			return 1
		}
		if code != "" {
			return 1
		}
		if passed == 0 {
			return 2
		}
		return 0
	}
	snapshot, err := store.Snapshot(ctx, time.Now())
	if err != nil {
		return finish(0, 0, "store-unavailable")
	}
	sort.SliceStable(snapshot.Nodes, func(i, j int) bool {
		return snapshot.Nodes[i].Health.CheckedAt.After(snapshot.Nodes[j].Health.CheckedAt)
	})
	checked, passed := 0, 0
	service := telegramService()
	for _, node := range snapshot.Nodes {
		if checked == limit {
			break
		}
		if ctx.Err() != nil {
			return finish(checked, passed, "deadline-or-canceled")
		}
		if node.Disabled || node.Protocol != "VLESS" {
			continue
		}
		profile, err := freshProfile(ctx)
		if err != nil || ctx.Err() != nil {
			return finish(checked, passed, "fresh-profile-unavailable")
		}
		started := time.Now()
		var result dataplane.NodeCheckResult
		called := false
		err = store.WithSecret(ctx, node.ID, func(material []byte) error {
			called = true
			var checkErr error
			result, checkErr = checker.Check(ctx, dataplane.NodeCheckRequest{NodeID: node.ID, Outbound: material, Service: service, NetworkProfile: profile})
			return checkErr
		})
		if !called {
			return finish(checked, passed, "secret-unavailable")
		}
		checked++
		finished := time.Now()
		fresh := result.NodeID == node.ID && result.ServiceID == service.ID && result.NetworkProfile == profile && result.RoutePathID == checker.EngineID()+":"+node.ID &&
			!result.StartedAt.Before(started) && !result.FinishedAt.Before(result.StartedAt) && !result.FinishedAt.After(finished) && finished.Before(result.ExpiresAt)
		ok := err == nil && ctx.Err() == nil && fresh && result.Available && result.Verdict == evidence.VerdictPass && result.TestLevel == "service" && result.ErrorCode == "" &&
			!result.DirectLeak && result.HTTPStatus >= 200 && result.HTTPStatus < 300 && result.Stage != "cleanup"
		entry := report{Kind: "candidate", Engine: checker.EngineID(), NodeID: safeNodeID(node.ID), Candidate: checked, Stage: safeStage(result.Stage), Verdict: safeVerdict(result.Verdict),
			Code: safeCheckCode(result.ErrorCode), HTTPSPass: ok, Fresh: fresh, DirectLeak: result.DirectLeak, HTTPStatus: min(max(result.HTTPStatus, 0), 599)}
		if errors.Is(err, dataplane.ErrExactNodeUnsupported) {
			entry.Stage, entry.Code, entry.Verdict = "unsupported", "node-profile-unsupported", "INCONCLUSIVE"
		} else if err != nil && result.ErrorCode == "" {
			entry.Code = safeCheckerError(err)
		}
		if out.Encode(entry) != nil {
			_ = recoverOnce(cleanupCtx, checker)
			return 1
		}
		// Cleanup failure can be a result with nil error. Never check another
		// candidate or count a positive response after this acknowledgement gap.
		if result.Stage == "cleanup" || result.ErrorCode == "node-cleanup-failed" {
			_ = recoverOnce(cleanupCtx, checker)
			return finish(checked, passed, "cleanup-unconfirmed")
		}
		if err != nil && !errors.Is(err, dataplane.ErrExactNodeUnsupported) {
			if recoverOnce(cleanupCtx, checker) != nil {
				return finish(checked, passed, "cleanup-unconfirmed")
			}
			return finish(checked, passed, "checker-error")
		}
		if ok {
			passed++
		}
	}
	if recoverOnce(cleanupCtx, checker) != nil {
		return finish(checked, passed, "cleanup-unconfirmed")
	}
	if ctx.Err() != nil {
		return finish(checked, passed, "deadline-or-canceled")
	}
	return finish(checked, passed, "")
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout)
	cancel()
	os.Exit(code)
}

func run(parent context.Context, args []string, output io.Writer) int {
	encoder := json.NewEncoder(output)
	fail := func(code string) int { _ = encoder.Encode(report{Kind: "fatal", Code: code}); return 1 }
	o, err := parseOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.WriteString(output, "nodeeval -root NEW_PRIVATE_DIR (-store EXISTING_PRIVATE_STORE | -preset APPROVED_ID) [-engine sing-box|xray] [-binary ABS_PATH] [-limit 12] [-duration 8m]\n")
		return 0
	}
	if err != nil || parent == nil || parent.Err() != nil {
		return fail("arguments-or-canceled")
	}
	end := time.Now().Add(o.duration)
	if parentEnd, ok := parent.Deadline(); ok && parentEnd.Before(end) {
		end = parentEnd
	}
	workCtx, cancel := context.WithDeadline(parent, end.Add(-cleanupReserve))
	defer cancel()
	// Cleanup may detach cancellation, but retains the same finite overall end.
	cleanupCtx, cleanupCancel := context.WithDeadline(context.WithoutCancel(parent), end)
	defer cleanupCancel()
	if workCtx.Err() != nil {
		return fail("deadline-or-canceled")
	}
	if o.store != "" && !separatedExistingStore(o.root, o.store) {
		return fail("store-workspace-overlap-or-unavailable")
	}
	w, err := newWorkspace(o.root)
	if err != nil {
		return fail("workspace-unavailable")
	}
	defer w.Close()
	file, err := w.reportFile()
	if err != nil {
		return fail("report-unavailable")
	}
	defer file.Close()
	encoder = json.NewEncoder(io.MultiWriter(output, file))
	var store *nodestore.Store
	if o.preset != "" {
		store, err = w.createStore()
	} else {
		store, err = nodestore.Open(o.store)
	}
	if err != nil {
		return fail("store-unavailable-or-busy")
	}
	defer store.Close()
	if o.preset != "" {
		admit, err := w.historyAdmission(workCtx)
		if err != nil {
			return fail("isolated-history-admission")
		}
		feed := providerfeed.New(store)
		feed.HistoryWriteAdmission = admit
		result, err := feed.Sync(workCtx, providerfeed.Request{PresetID: o.preset, Limit: o.limit, AcceptPartial: true})
		if encoder.Encode(report{Kind: "feed", Imported: result.Imported, Total: result.TotalEntries, Rejected: result.Rejected, Code: providerfeed.ErrorCode(err)}) != nil {
			return 1
		}
		if err != nil {
			return fail("feed-sync-refused")
		}
	}
	checkerRoot := filepath.Join(o.root, "checker")
	checker := dataplane.NewExactNodeChecker(checkerRoot)
	if o.engine == "xray" {
		checker = dataplane.NewExactXrayNodeCheckerSlots(checkerRoot, 1)
	}
	checker.Port, checker.Timeout = o.port, o.checkTimeout
	checker.Binary = o.binary
	return evaluate(workCtx, cleanupCtx, store, checker, checker.FreshProfile, o.limit, encoder)
}
