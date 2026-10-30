package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestOfflineNFQWS2StopCLIChild(t *testing.T) {
	base := os.Getenv("RAZVILKA_OFFLINE_STOP_CLI_TEST")
	if base == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("RAZVILKA_OFFLINE_STOP_CLI_ARGS")), &args); err != nil {
		t.Fatal("CLI fixture arguments unavailable")
	}
	os.Args = append([]string{"razvilka"}, args...)
	flag.CommandLine = flag.NewFlagSet("razvilka", flag.ExitOnError)
	os.Exit(mainWithSelfUpdateJournalRoots(selfUpdateReadRoots(filepath.Join(base, "reader"))))
}

func offlineStopTestPaths(base string) offlineNFQWS2StopPaths {
	return offlineNFQWS2StopPaths{
		config: filepath.Join(base, "config.json"), customServices: filepath.Join(base, "custom.json"), devices: filepath.Join(base, "devices.json"),
		stage: filepath.Join(base, "staging"), backups: filepath.Join(base, "backups"), cloudflare: filepath.Join(base, "cloudflare"), nodes: filepath.Join(base, "nodes"),
		warp: filepath.Join(base, "warp"), dataplane: filepath.Join(base, "dataplane"), dns: filepath.Join(base, "dns.json"),
		componentState: filepath.Join(base, "components"), componentBin: filepath.Join(base, "bin"), componentInit: filepath.Join(base, "init"),
		componentRepo: filepath.Join(base, "repo"), componentInfo: filepath.Join(base, "info"),
	}
}

func offlineStopTestCLI(t *testing.T, base string, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOfflineNFQWS2StopCLIChild$")
	paths := offlineStopTestPaths(base)
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	command.Env = append(os.Environ(), "RAZVILKA_OFFLINE_STOP_CLI_TEST="+base, "RAZVILKA_OFFLINE_STOP_CLI_ARGS="+string(rawArgs))
	for key, value := range map[string]string{
		"CONFIG": paths.config, "CUSTOM_SERVICES": paths.customServices, "DEVICES": paths.devices, "STAGE": paths.stage, "BACKUPS": paths.backups,
		"CLOUDFLARE_STATE": paths.cloudflare, "NODE_STATE": paths.nodes, "WARP_STATE": paths.warp, "DATAPLANE_STATE": paths.dataplane, "DNS_STATE": paths.dns,
		"COMPONENT_STATE": paths.componentState, "COMPONENT_BIN": paths.componentBin, "COMPONENT_INIT": paths.componentInit, "COMPONENT_REPO": paths.componentRepo, "COMPONENT_INFO": paths.componentInfo,
		"SELF_UPDATE_INSTALLATION": filepath.Join(base, "installation"), "SELF_UPDATE_FILE_STATE": filepath.Join(base, "files"), "SELF_UPDATE_HELPER_STATE": filepath.Join(base, "helper"), "SELF_UPDATE_CONTROL_STATE": filepath.Join(base, "control"),
		"CATALOG": filepath.Join(base, "catalog.json"), "SOURCES": filepath.Join(base, "sources.json"), "COMMUNITY_CATALOG": filepath.Join(base, "community.json"),
		"CACHE": filepath.Join(base, "cache"), "TOKEN_FILE": filepath.Join(base, "token"), "CREDENTIALS_FILE": filepath.Join(base, "credentials"),
		"SMART_ROUTE_STATE": filepath.Join(base, "smart.json"), "METRICS_HISTORY": filepath.Join(base, "metrics.jsonl"), "STRATEGY_LAB_STATE": filepath.Join(base, "lab.json"), "AUDIT_LOG": filepath.Join(base, "audit.jsonl"),
	} {
		command.Env = append(command.Env, "RAZVILKA_"+key+"="+value)
	}
	var output, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	err = command.Run()
	if ctx.Err() != nil {
		t.Fatal("offline CLI did not finish within its bound")
	}
	code := 0
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatal(err)
		}
		code = exited.ExitCode()
	}
	return output.String(), diagnostic.String(), code
}

type offlineStopTestFile struct {
	mode os.FileMode
	raw  string
}

func offlineStopTestTree(t *testing.T, base string) map[string]offlineStopTestFile {
	t.Helper()
	image := map[string]offlineStopTestFile{}
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var raw []byte
		if !entry.IsDir() {
			raw, err = os.ReadFile(path)
		}
		image[path] = offlineStopTestFile{mode: info.Mode(), raw: string(raw)}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func offlineStopTestWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// Canonical comparison metadata for refusal tests only. No modeled native
// observation is injected into a production source or used to authorize Stop.
func offlineStopTestPending(t *testing.T, base string) {
	t.Helper()
	paths := offlineStopTestPaths(base)
	store, err := config.Load(paths.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService("video", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	at := time.Date(2026, 10, 1, 2, 3, 4, 0, time.UTC)
	plan, err := dataplane.BuildAt(dataplane.Input{Revision: before.AppliedRevision,
		Routes:  []dataplane.Route{{ServiceID: "video", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"video.example"}}},
		Engines: []dataplane.Engine{{ID: "nfqws2", Installed: true, Configured: true, Running: true, Activatable: true}},
		Host:    dataplane.HostState{IPTables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true}}, at)
	if err != nil {
		t.Fatal(err)
	}
	plan.State, plan.Ready = "committed", true
	target, err := dataplane.BuildAt(dataplane.Input{Revision: before.Revision + 1}, at)
	if err != nil {
		t.Fatal(err)
	}
	resolved := map[string]string{"video": "nfqws2"}
	after, err := config.ReviewedNFQWS2StopImage(before, resolved, at)
	if err != nil {
		t.Fatal(err)
	}
	marshalImage := func(value any) restorejournal.Image {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return restorejournal.Image{Exists: true, Data: raw}
	}
	execution := dataplane.Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "committed", StartedAt: at.Format(time.RFC3339Nano), FinishedAt: at.Format(time.RFC3339Nano), Steps: []dataplane.ExecutionStep{}}
	original := map[string]restorejournal.Image{"latest-plan.json": marshalImage(plan), "latest-committed-plan.json": marshalImage(plan), "latest-execution.json": marshalImage(execution),
		filepath.Join("transactions", plan.PlanID, "execution.json"): marshalImage(execution), "latest-recovery.json": {}, "nfqws2-hooks-recovery.json": {}, "nfqws2-boot-hooks.json": {}}
	source := dataplane.NFQWS2OfflineStopEvidence{Binding: strings.Repeat("a", 64), RuntimeRoot: filepath.Join(paths.dataplane, "runtime", "nfqws2"), RuntimeOwner: "modeled-directory", Instance: strings.Repeat("b", 24),
		Network: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 12},
		Lease:   []byte("modeled-running"), StoppedLease: []byte("modeled-stopped"), Files: make([]restorejournal.Image, 11), FileOwners: make([]string, 11)}
	source.Files[0], source.FileOwners[0] = restorejournal.Image{Exists: true, Data: source.Lease}, "modeled-lease"
	intent := dataplane.NFQWS2OfflineStopIntent{Version: 1, State: "pending", StateRoot: paths.dataplane, StateOwner: "modeled-directory", ConfigPath: paths.config, ConfigOwner: "modeled-config-directory", DNSPath: paths.dns,
		AppliedAt: at, Plan: plan, Target: target, ConfigBefore: before, ConfigAfter: after, BeforeImage: marshalImage(before), AfterImage: marshalImage(after), Resolved: resolved, Original: original,
		HooksAfter: map[string]restorejournal.Image{"nfqws2-hooks-recovery.json": {}, "nfqws2-boot-hooks.json": {}}, Source: source}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dataplane.DecodeNFQWS2OfflineStopIntent(raw); err != nil {
		t.Fatal("pending refusal fixture must pass the actual closed codec", err)
	}
	offlineStopTestWrite(t, filepath.Join(paths.dataplane, dataplane.NFQWS2OfflineStopJournalName), raw)
}

func TestOfflineNFQWS2StopPendingFencesEveryMutatingCLI(t *testing.T) {
	for _, journal := range []string{"canonical-pending", "malformed"} {
		t.Run(journal, func(t *testing.T) {
			base := t.TempDir()
			paths := offlineStopTestPaths(base)
			if journal == "canonical-pending" {
				offlineStopTestPending(t, base)
			} else {
				offlineStopTestWrite(t, filepath.Join(paths.dataplane, dataplane.NFQWS2OfflineStopJournalName), []byte("private-stop-marker-must-not-be-logged"))
			}
			if err := os.Mkdir(paths.stage, 0755); err != nil {
				t.Fatal(err)
			}
			// Secondary refusal prevents actual package/install effects if the
			// outer gate regresses. The required diagnostic must still be Stop.
			offlineStopTestWrite(t, filepath.Join(base, "files", "current.json"), []byte("unresolved-update"))
			offlineStopTestWrite(t, filepath.Join(paths.dataplane, "runtime", "nfqws2", "ownership.json"), []byte("invalid-managed-intent"))
			before := offlineStopTestTree(t, base)
			for _, args := range [][]string{
				nil, {"-migrate-config"}, {"-recover-private-restore"}, {"-install-components"}, {"-deactivate-dataplane"}, {"-deactivate-dataplane", "-retire-dataplane-for-removal"},
				{"-adopt-nfqws2-init"}, {"-retry-rollback-plan", "reviewed-plan", "-retry-rollback-digest", "reviewed-digest"}, {"-close-rollback-plan", "reviewed-plan", "-close-rollback-digest", "reviewed-digest"},
				{"-retire-rollback-after-boot-plan", "reviewed-plan", "-retire-rollback-after-boot-digest", "reviewed-digest"},
				{"install-control-initialize", "invalid"}, {"self-update-bootstrap-old193", "invalid"}, {"self-update-paired-restore", "invalid"},
				{"nfqws-compatibility-supervisor", "invalid"}, {"nfqws-managed-process-supervisor", strings.Repeat("a", 32)}, {"component-package-supervisor", "invalid"}, {"component-package-supervision-probe", "invalid"},
				{"self-update-helper", "invalid"}, {"self-update-command-helper", "invalid"}, {"self-update-runtime-quiesce", "invalid"}, {"self-update-files", "restore", "invalid", "0"},
				{"components", "--refresh"}, {"bypasses", "--refresh"}, {"component", "plan", "nfqws2", "install", "--refresh"},
			} {
				name := strings.Join(args, " ")
				if name == "" {
					name = "ordinary-startup"
				}
				t.Run(name, func(t *testing.T) {
					out, diagnostic, code := offlineStopTestCLI(t, base, args...)
					if code == 0 || out != "" || !strings.Contains(diagnostic, app.ErrOfflineNFQWS2Stop.Error()) || strings.Contains(diagnostic, base) || strings.Contains(diagnostic, "private-stop-marker") {
						t.Fatal("mutation missed the early sanitized Stop fence", out, diagnostic, code)
					}
					if !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
						t.Fatal("refused mutation changed bytes, directories or staging permissions")
					}
				})
			}
		})
	}
}

func TestOfflineNFQWS2StopPendingKeepsReadersUsable(t *testing.T) {
	base := t.TempDir()
	offlineStopTestPending(t, base)
	for name, source := range map[string]string{"config.json": "config.example.json", "catalog.json": "service-catalog.json", "sources.json": "sources.json", "community.json": "community-catalog.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "configs", source))
		if err != nil {
			t.Fatal(err)
		}
		offlineStopTestWrite(t, filepath.Join(base, name), raw)
	}
	before := offlineStopTestTree(t, base)
	for _, args := range [][]string{{"-version"}, {"version"}, {"help"}, {"-h"}, {"-check"}, {"-check-dns-state"}, {"-check-autonomy-state"}, {"-self-update-read-version"}, {"-check-self-update-state"}, {"-component-update-schema"}, {"-native-enrollment-schema"}, {"-subscription-schema"}, {"-node-history-read-version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, diagnostic, code := offlineStopTestCLI(t, base, args...)
			if code != 0 || out == "" && diagnostic == "" || strings.Contains(diagnostic, app.ErrOfflineNFQWS2Stop.Error()) {
				t.Fatal("Stop disabled read-only diagnostics", out, diagnostic, code)
			}
			if !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
				t.Fatal("reader changed retained Stop/configuration or opened recovery leases")
			}
		})
	}
	// Inventory may report unavailable local tooling; it still must be able
	// to return its own observation without acquiring a mutation lease.
	for _, args := range [][]string{{"status"}, {"doctor"}, {"components"}, {"bypasses"}, {"component", "plan", "nfqws2", "install"}, {"self-update-files", "current"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, diagnostic, _ := offlineStopTestCLI(t, base, args...)
			if out == "" && diagnostic == "" || strings.Contains(diagnostic, app.ErrOfflineNFQWS2Stop.Error()) || !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
				t.Fatal("pending Stop blocked or changed a read-only inventory", out, diagnostic)
			}
		})
	}
}

func TestOfflineNFQWS2StopExplicitModeIsExclusiveAndHonoursUpdaterFence(t *testing.T) {
	base := t.TempDir()
	offlineStopTestPending(t, base)
	before := offlineStopTestTree(t, base)
	for _, mode := range []string{"-check", "-deactivate-dataplane", "-recover-private-restore", "-migrate-config", "-install-components", "-adopt-nfqws2-init"} {
		out, diagnostic, code := offlineStopTestCLI(t, base, "-stop-owned-routes", mode)
		if code == 0 || out != "" || !strings.Contains(diagnostic, "mutually exclusive") || !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
			t.Fatal("explicit Stop combined with another mode", mode, out, diagnostic, code)
		}
	}
	offlineStopTestWrite(t, filepath.Join(base, "files", "current.json"), []byte("unresolved-update"))
	before = offlineStopTestTree(t, base)
	out, diagnostic, code := offlineStopTestCLI(t, base, "-stop-owned-routes")
	if code == 0 || out != "" || !strings.Contains(diagnostic, "self update recovery required") || !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
		t.Fatal("explicit Stop bypassed independent updater recovery", out, diagnostic, code)
	}
}

func TestOfflineNFQWS2StopRequiresExistingConfigAndReleasesAllLeases(t *testing.T) {
	for _, content := range []string{"missing", "private-malformed-config"} {
		t.Run(content, func(t *testing.T) {
			base := t.TempDir()
			paths := offlineStopTestPaths(base)
			if content != "missing" {
				offlineStopTestWrite(t, paths.config, []byte(content))
			}
			if err := os.Mkdir(paths.stage, 0755); err != nil {
				t.Fatal(err)
			}
			out, diagnostic, code := offlineStopTestCLI(t, base, "-stop-owned-routes")
			if code == 0 || out != "" || !strings.Contains(diagnostic, "existing-config") || strings.Contains(diagnostic, base) || strings.Contains(diagnostic, "private-malformed-config") {
				t.Fatal("missing/invalid configuration did not safely refuse", out, diagnostic, code)
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			allowed := map[string]bool{"staging": true, "private-restore": true, "private-restore-nodes-v1": true, "private-restore-native-v1": true, "private-restore-feeds-v1": true}
			if content != "missing" {
				allowed["config.json"] = true
			}
			for _, entry := range entries {
				if !allowed[entry.Name()] {
					t.Fatal("Stop created unrelated defaults, credentials or runtime state", entry.Name())
				}
			}
			stage, err := os.Stat(paths.stage)
			if err != nil || stage.Mode().Perm() != 0755 {
				t.Fatal("explicit Stop normalized staging before native review", err)
			}
			legacy, current, _, _, err := preparePrivateRecoveries(paths.config, paths.customServices, paths.devices, paths.stage, paths.cloudflare, paths.nodes, paths.warp)
			if err != nil {
				t.Fatal("refused command leaked a private recovery lifetime lease", err)
			}
			if err := errors.Join(current.Close(), legacy.Close()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOfflineNFQWS2StopCannotRunBesideAnyPrivateGeneration(t *testing.T) {
	for _, generation := range []string{"legacy", "nodes", "native", "feeds"} {
		t.Run(generation, func(t *testing.T) {
			base := t.TempDir()
			p := offlineStopTestPaths(base)
			offlineStopTestWrite(t, p.config, []byte("private-config-must-not-be-read"))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var lease *privaterestore.Coordinator
			var err error
			switch generation {
			case "legacy":
				lease, _, err = preparePrivateRecoveryContext(ctx, p.config, p.customServices, p.devices, p.stage, p.cloudflare)
			case "nodes":
				lease, _, err = prepareNodePrivateRecoveryContext(ctx, p.config, p.customServices, p.devices, p.stage, p.cloudflare, p.nodes)
			case "native":
				lease, _, err = prepareNativePrivateRecovery(ctx, p.config, p.customServices, p.devices, p.stage, p.cloudflare, p.nodes, p.warp)
			case "feeds":
				lease, _, err = prepareFeedPrivateRecovery(ctx, p.config, p.customServices, p.devices, p.stage, p.cloudflare, p.nodes, p.warp)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			if err := lease.StartRuntime(); err != nil {
				t.Fatal(err)
			}
			out, diagnostic, code := offlineStopTestCLI(t, base, "-stop-owned-routes")
			if code == 0 || out != "" || !strings.Contains(diagnostic, "private-recovery") || strings.Contains(diagnostic, "existing-config") || strings.Contains(diagnostic, "private-config") {
				t.Fatal("Stop bypassed a running private recovery generation", out, diagnostic, code)
			}
			if raw, err := os.ReadFile(p.config); err != nil || string(raw) != "private-config-must-not-be-read" {
				t.Fatal("Stop modified settings beside another instance", err)
			}
			if _, err := os.Lstat(p.dataplane); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Stop initialized runtime before lifetime admission", err)
			}
		})
	}
}

func TestOfflineNFQWS2StopDoesNotReplayPreparedPrivateRestore(t *testing.T) {
	for generation, directory := range []string{"private-restore", "private-restore-nodes-v1", "private-restore-native-v1", "private-restore-feeds-v1"} {
		t.Run(directory, func(t *testing.T) {
			base := t.TempDir()
			p := offlineStopTestPaths(base)
			if _, err := config.Load(p.config); err != nil {
				t.Fatal(err)
			}
			if _, err := customservices.Load(p.customServices); err != nil {
				t.Fatal(err)
			}
			if _, err := devices.Load(p.devices); err != nil {
				t.Fatal(err)
			}
			if _, err := engineconfig.New(p.stage, p.backups).Stage("nfqws2", "user-list", "retained.example\n"); err != nil {
				t.Fatal(err)
			}
			legacy, current, _, _, err := preparePrivateRecoveries(p.config, p.customServices, p.devices, p.stage, p.cloudflare, p.nodes, p.warp)
			if err != nil {
				t.Fatal(err)
			}
			all := append(append([]*privaterestore.Coordinator(nil), legacy.coordinators...), current)
			payload := privatebackup.NewPayload(app.Version)
			payload.Services = map[string]config.ServiceState{"video": {Enabled: true, Route: "nfqws2"}}
			if err := privatebackup.Seal(&payload); err != nil {
				t.Fatal(err)
			}
			outcome, restoreErr := all[generation].RestoreOffline(context.Background(), payload, map[string]bool{"video": true})
			closeErr := errors.Join(current.Close(), legacy.Close())
			if restoreErr != nil || closeErr != nil || outcome != restorejournal.Applied {
				t.Fatal("real private writer did not create an idle scope fixture", outcome, restoreErr, closeErr)
			}
			// Retain the actual writer's scope and checksum encoding. Model a
			// crash after these typed targets reached their recorded after images.
			offlineStopTestPending(t, base)
			journalPath := filepath.Join(base, directory, "restore.private.json")
			raw, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			type record struct {
				Target string               `json:"target"`
				Before restorejournal.Image `json:"before"`
				After  restorejournal.Image `json:"after"`
			}
			var journal struct {
				Kind    string   `json:"kind"`
				Schema  int      `json:"schema"`
				Scope   string   `json:"scope"`
				ID      string   `json:"id"`
				State   string   `json:"state"`
				Records []record `json:"records"`
				Digest  string   `json:"digest"`
			}
			if err := json.Unmarshal(raw, &journal); err != nil || journal.State != "idle" || journal.Scope == "" {
				t.Fatal("original idle scope missing", err)
			}
			for _, target := range []struct{ id, path string }{{"config", p.config}, {"custom_services", p.customServices}, {"draft_nfqws2_user-list", filepath.Join(p.stage, "nfqws2", "user-list.draft")}} {
				after, err := os.ReadFile(target.path)
				if err != nil {
					t.Fatal(err)
				}
				before := append(append([]byte(nil), after...), '\n')
				journal.Records = append(journal.Records, record{Target: target.id, Before: restorejournal.Image{Exists: true, Data: before}, After: restorejournal.Image{Exists: true, Data: after}})
			}
			journal.State, journal.ID, journal.Digest = "prepared", strings.Repeat("d", 32), ""
			unsigned, err := json.Marshal(journal)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(unsigned)
			journal.Digest = hex.EncodeToString(digest[:])
			raw, err = json.Marshal(journal)
			if err != nil {
				t.Fatal(err)
			}
			offlineStopTestWrite(t, journalPath, raw)
			before := offlineStopTestTree(t, base)
			output, diagnostic, code := offlineStopTestCLI(t, base, "-stop-owned-routes")
			if code == 0 || output != "" || !strings.Contains(diagnostic, "private-recovery") || !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
				t.Fatal("Stop replayed another journal before its original comparison guard", output, diagnostic, code)
			}
			// This is a recoverable real typed scope, not corrupt metadata which
			// happened to refuse: the old ordinary Open path demonstrably writes.
			legacy, current, older, newest, err := preparePrivateRecoveries(p.config, p.customServices, p.devices, p.stage, p.cloudflare, p.nodes, p.warp)
			if err != nil || older != restorejournal.RolledBack && newest != restorejournal.RolledBack {
				t.Fatal("control did not reproduce ordinary recovery's target writes", older, newest, err)
			}
			if err := errors.Join(current.Close(), legacy.Close()); err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
				t.Fatal("ordinary recovery control did not change its targets")
			}
		})
	}
}

func TestOfflineNFQWS2StopStateOverrideCannotHideFixedStop(t *testing.T) {
	base := t.TempDir()
	fixed, selected := filepath.Join(base, "fixed"), filepath.Join(base, "selected")
	offlineStopTestWrite(t, filepath.Join(fixed, dataplane.NFQWS2OfflineStopJournalName), []byte("private-fixed-pending"))
	before := offlineStopTestTree(t, base)
	for _, explicit := range []bool{false, true} {
		if err := checkOfflineNFQWS2StopMutationAt(fixed, selected, explicit); !errors.Is(err, app.ErrOfflineNFQWS2Stop) {
			t.Fatal("state override concealed the fixed package Stop", explicit, err)
		}
	}
	if err := checkOfflineNFQWS2StopMutationAt(fixed, fixed, true); err != nil {
		t.Fatal("explicit retry could not reach its own original journal", err)
	}
	if !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
		t.Fatal("fence changed a retained path")
	}
}

func TestOfflineNFQWS2StopFencesIndependentUpdaterAndEachEffect(t *testing.T) {
	base := t.TempDir()
	offlineStopTestPending(t, base)
	paths := offlineStopTestPaths(base)
	control := filepath.Join(base, "control")
	r, err := operationgate.InitializeSelfUpdateControl(context.Background(), control)
	if err != nil {
		t.Fatal(err)
	}
	before := offlineStopTestTree(t, base)
	if err := independentSelfUpdateFences(context.Background(), paths.config, paths.dataplane); !errors.Is(err, app.ErrOfflineNFQWS2Stop) {
		t.Fatal("independent helper passed pending outer Stop", err)
	}
	for _, action := range []string{"start/live", "stop-owned", "replace-to-rollback", "bootstrap-offline"} {
		called := false
		err := selfUpdateEffectAdmissionWithRoots(context.Background(), control, paths.config, paths.dataplane, strings.Repeat("c", 32), r.InstallationID, r.Sequence,
			action, "command-worker-stop-old-panel", func() error { called = true; return nil })
		if !errors.Is(err, app.ErrOfflineNFQWS2Stop) || called {
			t.Fatal("updater effect crossed the pending Stop fence", action, err)
		}
	}
	if !reflect.DeepEqual(before, offlineStopTestTree(t, base)) {
		t.Fatal("independent refusal changed control/config/runtime files")
	}
}

func TestOfflineNFQWS2StopRequiresFiniteOriginalContextBeforeOpening(t *testing.T) {
	base := t.TempDir()
	paths := offlineStopTestPaths(base)
	canceled, cancel := context.WithTimeout(context.Background(), time.Minute)
	cancel()
	for i, ctx := range []context.Context{nil, context.Background(), canceled} {
		result, err := runOfflineNFQWS2StopCLI(ctx, paths)
		if err == nil || result.Stopped {
			t.Fatal("invalid command context admitted Stop", i, err)
		}
	}
	if entries, err := os.ReadDir(base); err != nil || len(entries) != 0 {
		t.Fatal("invalid context opened private recovery or created settings", fmt.Sprint(entries), err)
	}
}
