//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/sources"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

const wgListNativeQAID = "custom-qa-wg-list"
const wgListNativeProfileID = "qa-native-wg"

type wgListNativeInput struct {
	Root, Profile, Catalog, Sources, Scope, Probe string
	Target, Client                                netip.Addr
	Apply                                         bool
	Hold                                          time.Duration
}

func wgListNativeParse(getenv func(string) string) (in wgListNativeInput, err error) {
	switch getenv("RAZVILKA_NATIVE_WG_LIST_APPLY") {
	case "":
	case "APPLY_WG_LIST":
		in.Apply = true
	default:
		return in, errors.New("explicit apply opt-in required")
	}
	for key, target := range map[string]*string{"ROOT": &in.Root, "PROFILE": &in.Profile, "CATALOG": &in.Catalog, "SOURCES": &in.Sources, "SCOPE": &in.Scope} {
		*target = getenv("RAZVILKA_NATIVE_WG_LIST_" + key)
		if !filepath.IsAbs(*target) || filepath.Clean(*target) != *target || strings.TrimSpace(*target) != *target || filepath.Dir(*target) == *target {
			return in, errors.New("canonical existing private QA inputs required")
		}
	}
	in.Target, err = netip.ParseAddr(getenv("RAZVILKA_NATIVE_WG_LIST_TARGET_IPV4"))
	if err != nil || !in.Target.Is4() || !publicfetch.PublicAddress(in.Target) {
		return in, errors.New("public finite IPv4 target required")
	}
	in.Client, err = netip.ParseAddr(getenv("RAZVILKA_NATIVE_WG_LIST_CLIENT_IPV4"))
	if err != nil || !in.Client.Is4() || !in.Client.IsGlobalUnicast() || in.Client.IsLoopback() || in.Client == in.Target {
		return in, errors.New("selected LAN client required")
	}
	in.Probe = getenv("RAZVILKA_NATIVE_WG_LIST_PROBE_URL")
	u, err := url.Parse(in.Probe)
	if err != nil || u.Scheme != "https" || u.Hostname() != in.Target.String() || u.Port() != "" && u.Port() != "443" || u.User != nil || u.Fragment != "" || len(in.Probe) > 2048 {
		return in, errors.New("normal HTTPS probe on exact target required")
	}
	seconds, err := strconv.Atoi(getenv("RAZVILKA_NATIVE_WG_LIST_HOLD_SECONDS"))
	if in.Apply && (err != nil || seconds < 30 || seconds > 300) || !in.Apply && getenv("RAZVILKA_NATIVE_WG_LIST_HOLD_SECONDS") != "" {
		return in, errors.New("explicit bounded apply hold required")
	}
	in.Hold = time.Duration(seconds) * time.Second
	return in, nil
}

func wgListNativeService(in wgListNativeInput) catalog.Service {
	return catalog.Service{ID: wgListNativeQAID, Name: "QA Generic WireGuard list", Category: "QA", Icon: "+", Description: "Separate finite WG acceptance definition",
		Domains: []string{}, CIDRs: []string{in.Target.String() + "/32"}, Strategy: []string{"wireguard"}, ProbeURL: in.Probe,
		Probes: []catalog.Probe{{ID: "qa-https", Label: "Exact public HTTPS", URL: in.Probe, Required: true, Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectPolicy: "none"}}}}
}

type wgListNativeProgress struct {
	Schema             int       `json:"schema"`
	RunID              string    `json:"run_id"`
	OwnerPID           int       `json:"owner_pid"`
	Stage              string    `json:"stage"`
	LastBoundary       string    `json:"last_boundary"`
	BodyFailed         bool      `json:"body_failed"`
	Cleanup            string    `json:"cleanup"`
	UpdatedAt          time.Time `json:"updated_at_utc"`
	ActiveAt           time.Time `json:"active_at_utc"`
	OwnerObservedUntil time.Time `json:"owner_observed_until_utc"`
}

func wgListNativeForeignLink() (*net.Interface, error) {
	links, err := net.Interfaces()
	if err != nil || len(links) > 1024 {
		return nil, errors.New("bounded foreign interface inventory unavailable")
	}
	for _, link := range links {
		if link.Name == "nwg0" {
			return &link, nil
		}
	}
	return nil, nil
}

func wgListNativeRefusal(data []byte) string {
	var body struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(data, &body) == nil {
		switch body.Code {
		case "WG_LIST_REVIEW_REFUSED", "WG_LIST_REVIEW_REQUIRED", "WG_LIST_RUNTIME_REFUSED", "WG_LIST_RESPONSE_UNAVAILABLE":
			return body.Code
		}
	}
	return xraySelectedRefusal(data)
}

// Command files are Root's test intent, never proof, a lease or permission.
func wgListNativeCommand(root *ownedfs.Root, id string) (string, error) {
	info, err := root.Stat("command")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 96 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return "", errors.New("invalid test command")
	}
	f, err := openWGListNativeCommand(root)
	if err != nil {
		return "", err
	}
	held, statErr := f.Stat()
	if statErr != nil || !os.SameFile(info, held) || held.Mode() != info.Mode() || held.Size() != info.Size() {
		return "", errors.Join(errors.New("test command replaced"), f.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 97))
	closeErr := f.Close()
	current, pathErr := root.Stat("command")
	if readErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(info, current) || current.Mode() != info.Mode() || current.Size() != info.Size() || int64(len(data)) != info.Size() || len(data) > 96 {
		return "", errors.New("test command changed")
	}
	for _, command := range []string{"STOP", "ABORT"} {
		if string(data) == command+" "+id+"\n" {
			return command, nil
		}
	}
	return "", errors.New("test command does not match run")
}

func openWGListNativeCommand(root *ownedfs.Root) (*os.File, error) {
	return root.OpenFile("command", os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}

// ROOT ONLY, fresh private mount namespace and CURRENT actual network namespace.
// Build linux/arm64 cmd tests, run only TestWGListAppNativeHTTP -test.timeout=0.
// Opt-in RAZVILKA_NATIVE_WG_LIST=1 plus _ROOT/_PROFILE/_CATALOG/_SOURCES/_SCOPE,
// _CLIENT_IPV4/_TARGET_IPV4/_PROBE_URL. PROFILE is a private single-peer plain WG
// profile with public numeric endpoint; ordinary authenticated import issues
// the named catalog owner. SCOPE is intent for one selected device/segment.
// Default is actual /plan only, with Safe Mode disabled only in the NEW private
// config as required by the existing Ready review. _APPLY=APPLY_WG_LIST and
// _HOLD_SECONDS=30..300 explicitly enable live Apply. Root observes progress.json then sends real
// traffic from the agreed PC during active_at_utc..owner_observed_until_utc. After at
// least HOLD_SECONDS atomically write 0600 command "STOP <run_id>\n" (or ABORT).
// STOP by HOLD_SECONDS+120 is required. Neither a command nor this test's PASS
// certifies external LAN traffic: Root must retain its independent PC evidence.
// No native process alarm/kill: an unsuccessful original Close stays in the
// production retirement keeper. Use an external finite observer without signal.
func TestWGListAppNativeHTTP(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_WG_LIST") != "1" {
		t.Skip("Root-only genuine GenericWG App acceptance requires explicit opt-in")
	}
	if _, finite := t.Deadline(); finite {
		t.Fatal("stage=inputs code=test_timeout_zero_required")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("stage=inputs code=root_arm64_required")
	}
	in, err := wgListNativeParse(os.Getenv)
	if err != nil {
		t.Fatal("stage=inputs code=invalid_contract")
	}
	rootInfo, err := os.Lstat(in.Root)
	if err != nil || !xraySelectedSoakPrivate(rootInfo, true) || rootInfo.Mode().Perm() != 0700 || rootInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("stage=inputs code=empty_private_root_required")
	}
	entries, err := os.ReadDir(in.Root)
	if err != nil || len(entries) != 0 {
		t.Fatal("stage=inputs code=empty_private_root_required")
	}
	progressRoot, err := ownedfs.Open(in.Root)
	if err != nil {
		t.Fatal("stage=inputs code=held_private_root_required")
	}
	defer progressRoot.Close()
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal("stage=inputs code=entropy_required")
	}
	progress := wgListNativeProgress{Schema: 1, RunID: hex.EncodeToString(entropy[:]), OwnerPID: os.Getpid(), Stage: "inputs", Cleanup: "not_started"}
	publish := func() {
		progress.UpdatedAt, progress.BodyFailed = time.Now().UTC(), t.Failed()
		image, err := json.Marshal(progress)
		if err != nil || progressRoot.WriteAtomic("progress.json", image, 0600) != nil || progressRoot.Sync() != nil {
			t.Error("stage=progress code=private_progress_unconfirmed")
		}
	}
	defer publish() // Capture failures in the later closing/foreign comparisons.
	stage := func(value string) {
		progress.Stage = value
		if value != "original_retirement" && value != "retired" {
			progress.LastBoundary = value
		}
		publish()
		t.Logf("stage=%s", value)
	}
	stage("inputs")
	foreignBefore, foreignErr := wgListNativeForeignLink()
	if foreignErr != nil {
		t.Fatal("stage=foreign_inventory code=read_unconfirmed")
	}
	defer func() {
		after, err := wgListNativeForeignLink()
		if err != nil || !reflect.DeepEqual(foreignBefore, after) {
			t.Error("stage=foreign_inventory code=foreign_link_changed")
		}
	}()
	profile := xraySelectedReadFile(t, "profile", in.Profile, awgprofile.MaxBytes, true)
	defer clear(profile)
	parsed, err := awgprofile.ParsePlainWireGuard(string(profile))
	if err != nil {
		t.Fatal("stage=profile code=single_plain_wg_profile_required")
	}
	host, _, err := net.SplitHostPort(parsed.Public().Endpoint)
	endpoint, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || !publicfetch.PublicAddress(endpoint) {
		t.Fatal("stage=profile code=public_numeric_endpoint_required")
	}
	policy := xraySelectedReadFile(t, "scope", in.Scope, 64<<10, true)
	intent, err := xraySelectedScope(policy)
	clear(policy)
	if err != nil || intent.Clients.NewDevices != "base" {
		t.Fatal("stage=scope code=one_selected_device_list_only_required")
	}
	cat, err := catalog.Load(in.Catalog)
	if err != nil {
		t.Fatal("stage=catalog code=genuine_catalog_required")
	}
	for _, service := range cat.Services {
		if service.ID == wgListNativeQAID {
			t.Fatal("stage=catalog code=qa_identity_must_be_new")
		}
	}
	registry, err := sources.LoadRegistry(in.Sources)
	if err != nil {
		t.Fatal("stage=sources code=genuine_registry_required")
	}
	runLife, stopRunLife := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRunLife()
	// One fixed body deadline covers setup, the production eight-minute Apply,
	// current checks and the finite external hold. Cleanup may outlive it while
	// the SAME original owners remain in the production retirement keeper.
	bodyLife, stopBodyLife := context.WithTimeout(runLife, 30*time.Minute)
	defer stopBodyLife()
	ctx, cancel := context.WithCancel(bodyLife)
	defer cancel()
	configPath := filepath.Join(in.Root, "config.json")
	store, err := config.Load(configPath)
	if err != nil {
		t.Fatal("stage=constructor code=private_store_required")
	}
	configs := engineconfig.New(filepath.Join(in.Root, "stage"), filepath.Join(in.Root, "backup"))
	fresh := func(c context.Context) (string, error) { p, err := systemprobe.FreshWANProfile(c); return p.ID, err }
	manager, err := newDataplaneManagerWithNodes(filepath.Join(in.Root, "dataplane"), configs, nil, fresh)
	if err != nil {
		t.Fatal("stage=constructor code=main_manager_refused")
	}
	dns, err := dnscontrol.New(filepath.Join(in.Root, "dns"))
	if err != nil || registerScopedDNS(manager, dns) != nil {
		t.Fatal("stage=constructor code=original_dns_required")
	}
	custom, err := customservices.Load(filepath.Join(in.Root, "custom-services.json"))
	if err != nil {
		t.Fatal("stage=constructor code=private_custom_store_required")
	}
	known, err := devices.Load(filepath.Join(in.Root, "devices.json"))
	if err != nil {
		t.Fatal("stage=constructor code=private_devices_required")
	}
	components, err := componentsFromEnv()
	if err != nil {
		t.Fatal("stage=constructor code=actual_components_required")
	}
	lab, err := strategylab.New(filepath.Join(in.Root, "strategy-lab.json"))
	if err != nil {
		t.Fatal("stage=constructor code=private_strategy_store_required")
	}
	files, err := configuredSelfUpdateFiles("/opt", filepath.Join(in.Root, "self-update-files"), filepath.Join(in.Root, "self-update"), filepath.Join(in.Root, "control"))
	if err != nil {
		t.Fatal("stage=constructor code=main_control_required")
	}
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, files.ControlRoot); err != nil {
		t.Fatal("stage=constructor code=original_control_refused")
	}
	var tokenBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		t.Fatal("stage=auth code=entropy_required")
	}
	token := hex.EncodeToString(tokenBytes[:])
	clear(tokenBytes[:])
	securityGate, err := security.NewGate(token)
	if err != nil {
		t.Fatal("stage=auth code=ordinary_gate_required")
	}
	a := &app.App{Store: store, Catalog: cat, Dataplane: manager, EngineConfigs: configs, DNS: dns, Devices: known, CustomServices: custom,
		Sources:    sources.NewManager(registry, filepath.Join(in.Root, "source-cache"), filepath.Join(in.Root, "sources-selection.json")),
		Components: components, StrategyLab: lab, Security: securityGate, SelfUpdate: files.Helper, SelfUpdateFiles: files, FreshProfile: fresh,
		ComponentHistory: updatecheck.NewComponentHistoryAdmission(app.ManagedComponentReadVersion)}
	if a.InitializeComponentRecoveryGate() != nil || a.ConfigureDefaultConsent(configPath, "") != nil {
		t.Fatal("stage=constructor code=ordinary_recovery_scope_refused")
	}
	defer a.CloseDefaultConsent()
	managedLife, stopManagedLife := context.WithCancel(context.Background())
	var nfq *app.ManagedNFQWSListRuntime
	var xray *app.ManagedXraySelectedTCPListRuntime
	var wg *app.ManagedWGListRuntime
	joined := false
	closeManaged := func(cleanup context.Context) error {
		if joined {
			return nil
		}
		progress.Cleanup = "pending"
		stage("original_retirement")
		if err := a.WaitManagedStrategyCompatibility(cleanup); err != nil {
			return err
		}
		if wg != nil {
			if err := wg.Close(cleanup); err != nil {
				return err
			}
		}
		if xray != nil {
			if err := xray.Close(cleanup); err != nil {
				return err
			}
		}
		if nfq != nil {
			if err := nfq.Close(cleanup); err != nil {
				return err
			}
		}
		if err := a.CloseManagedListStartup(cleanup); err != nil {
			return err
		}
		if err := manager.CloseScopedDNS(cleanup); err != nil {
			return err
		}
		if err := a.CloseManagedNFQControl(); err != nil {
			return err
		}
		joined = true
		progress.Cleanup = "joined"
		stage("retired")
		stopManagedLife()
		return nil
	}
	defer retainManagedListRetirement(closeManaged)
	stage("managed_startup")
	nfq, err = configureManagedNFQList(managedLife, a)
	if err != nil || nfq == nil {
		t.Fatal("stage=managed_startup code=nfq_source_unconfirmed")
	}
	xray, err = configureManagedXraySelectedTCPList(managedLife, a)
	if err != nil || xray == nil {
		t.Fatal("stage=managed_startup code=xray_source_unconfirmed")
	}
	wg, err = configureManagedWGList(managedLife, a)
	if err != nil || wg == nil {
		t.Fatal("stage=managed_startup code=wg_source_unconfirmed")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("stage=http code=local_listener_required")
	}
	serverLife, stopServerLife := context.WithCancel(context.Background())
	defer stopServerLife()
	server := newPanelHTTPServer(serverLife, listener.Addr().String(), a.Handler(http.NotFoundHandler()))
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + listener.Addr().String()
	call := func(label, method, route string, value any, target any) {
		t.Helper()
		stage(label)
		status, data, err := xraySelectedCall(ctx, client, base, token, method, route, value)
		defer clear(data)
		if err != nil || status != 200 && status != 201 || target != nil && json.Unmarshal(data, target) != nil {
			t.Fatalf("stage=%s status=%d code=%s", label, status, wgListNativeRefusal(data))
		}
	}
	call("manual_mode", "PUT", "/api/v1/service-control", map[string]any{"expected_revision": store.Get().Revision, "mode": "manual", "confirm": "SAVE_SERVICE_CONTROL"}, nil)
	var imported struct {
		Saved   bool `json:"saved"`
		Live    bool `json:"live_applied"`
		Profile struct {
			Profile wireguardprofile.Metadata `json:"profile"`
			Route   string                    `json:"route"`
		} `json:"profile"`
	}
	call("ordinary_profile_import", "POST", "/api/v1/wireguard/profiles", map[string]any{"id": wgListNativeProfileID, "name": "QA GenericWG", "content": string(profile)}, &imported)
	clear(profile)
	route := "wireguard:" + wgListNativeProfileID
	if !imported.Saved || imported.Live || imported.Profile.Profile.ID != wgListNativeProfileID || len(imported.Profile.Profile.Revision) != 64 || imported.Profile.Route != route {
		t.Fatal("stage=ordinary_profile_import code=actual_import_revision_required")
	}
	var service catalog.Service
	call("ordinary_custom_service", "POST", "/api/v1/custom-services", wgListNativeService(in), &service)
	if service.ID != wgListNativeQAID || len(service.Domains) != 0 || !slices.Equal(service.CIDRs, []string{in.Target.String() + "/32"}) || !reflect.DeepEqual(a.Catalog, cat) {
		t.Fatal("stage=ordinary_custom_service code=finite_new_definition_required")
	}
	call("named_profile_assignment", "PUT", "/api/v1/services/"+service.ID, map[string]any{"enabled": true, "route": route, "sources": []string{in.Client.String() + "/32"}, "expected_revision": store.Get().Revision, "expected_profile_revision": imported.Profile.Profile.Revision}, nil)
	call("ordinary_device_discovery", "GET", "/api/v1/devices?view=status", nil, nil)
	grant := config.DefaultRouteGrant{Resolved: route, ProviderClass: "private_profile", ProviderID: wgListNativeProfileID}
	call("original_scope_consent", "POST", "/api/v1/networkpolicy/review", map[string]any{"expected_revision": store.Get().Revision, "expected_policy_revision": 0, "policy": intent, "grants": []config.DefaultRouteGrant{grant}, "confirm": "APPROVE_NETWORK_POLICY"}, nil)
	// Only the NEW private QA config changes here. Existing WG review requires
	// Ready, including Safe Mode admission; /apply remains separately opt-in.
	call("private_write_permission", "PUT", "/api/v1/settings/safe-mode", map[string]any{"enabled": false}, nil)
	var plan struct {
		Transaction dataplane.Plan `json:"transaction"`
		Review      struct {
			Revision *uint64 `json:"expected_revision"`
			Digest   string  `json:"reviewed_digest"`
		} `json:"review"`
	}
	call("original_plan", "GET", "/api/v1/plan?scope=all", nil, &plan)
	if plan.Review.Revision == nil || *plan.Review.Revision != store.Get().Revision || len(plan.Review.Digest) != 64 || !plan.Transaction.Ready || plan.Transaction.Noop || plan.Transaction.LAN == nil || len(plan.Transaction.Routes) != 1 {
		t.Fatal("stage=original_plan code=actual_nonempty_ready_review_required")
	}
	planned := plan.Transaction.Routes[0]
	if planned.Selected != route || planned.WireGuardProfileRevision != imported.Profile.Profile.Revision || len(planned.Domains) != 0 || !slices.Equal(planned.CIDRs, service.CIDRs) || !slices.Equal(planned.Sources, []string{in.Client.String() + "/32"}) {
		t.Fatal("stage=original_plan code=finite_original_scope_required")
	}
	if !in.Apply {
		stage("plan_only_complete")
		return
	}
	// Obtain the exact fresh review again immediately before actual Apply.
	call("original_apply_review", "GET", "/api/v1/plan?scope=all", nil, &plan)
	if plan.Review.Revision == nil || *plan.Review.Revision != store.Get().Revision || !plan.Transaction.Ready || plan.Transaction.Noop || plan.Transaction.LAN == nil || len(plan.Transaction.Routes) != 1 {
		t.Fatal("stage=original_apply_review code=fresh_review_required")
	}
	planned = plan.Transaction.Routes[0]
	if planned.Selected != route || planned.WireGuardProfileRevision != imported.Profile.Profile.Revision || len(planned.Domains) != 0 || !slices.Equal(planned.CIDRs, service.CIDRs) || !slices.Equal(planned.Sources, []string{in.Client.String() + "/32"}) {
		t.Fatal("stage=original_apply_review code=finite_original_scope_required")
	}
	stopConfirmed := false
	stopRuntime := func() bool {
		ok := true
		var stoppedConfig *config.Config
		for attempt := 1; attempt <= 2; attempt++ {
			stage("ordinary_stop")
			cleanup, end := context.WithTimeout(context.Background(), 2*time.Minute)
			status, data, err := xraySelectedCall(cleanup, client, base, token, "POST", "/api/v1/service-control/runtime", map[string]any{"expected_revision": store.Get().Revision, "action": "stop", "confirm": "STOP_OWNED_ROUTES"})
			end()
			var result struct {
				OK bool `json:"ok"`
			}
			if err != nil || status != 200 || json.Unmarshal(data, &result) != nil || !result.OK || !store.Get().ServiceControl.Stopped {
				t.Errorf("stage=ordinary_stop attempt=%d status=%d code=%s", attempt, status, wgListNativeRefusal(data))
				ok = false
			}
			current := store.Get()
			if stoppedConfig == nil {
				stoppedConfig = &current
			} else if !reflect.DeepEqual(*stoppedConfig, current) {
				t.Error("stage=ordinary_stop code=repeated_stop_changed_config")
				ok = false
			}
			clear(data)
		}
		stopped, exists, err := manager.Committed()
		// BOTH public Stops open the SAME terminal's fresh WG+LAN observer.
		// A standalone unbound Manager observer is not a replacement grant.
		if err != nil || !exists || len(stopped.Routes) != 0 || stopped.State != "committed" {
			t.Error("stage=absence code=same_original_absence_unconfirmed")
			ok = false
		}
		return ok
	}
	defer func() {
		if !stopConfirmed {
			stopConfirmed = stopRuntime()
		}
		if !stopConfirmed {
			progress.Cleanup = "unconfirmed"
			publish()
		}
	}()
	var applied struct {
		OK      bool `json:"ok"`
		Live    bool `json:"live_applied"`
		Pending bool `json:"scope_pending_changes"`
	}
	call("ordinary_apply", "POST", "/api/v1/apply?scope=all", map[string]any{"expected_revision": *plan.Review.Revision, "reviewed_digest": plan.Review.Digest}, &applied)
	committed, exists, err := manager.Committed()
	if err != nil || !exists || committed.State != "committed" || !applied.OK || !applied.Live || applied.Pending || len(committed.Routes) != 1 || committed.Routes[0].Selected != route || wg.Current(ctx) != nil {
		t.Fatal("stage=active code=original_handshake_health_owner_unconfirmed")
	}
	activeConfig, activeCustom := store.Get(), custom.List()
	progress.ActiveAt = time.Now().UTC()
	progress.OwnerObservedUntil = progress.ActiveAt
	stage("active_observed")
	cancel() // Request lifetime never becomes retained runtime permission.
	deadline := time.Now().Add(in.Hold + 120*time.Second)
	for {
		if bodyLife.Err() != nil || time.Now().After(deadline) {
			t.Fatal("stage=hold code=stop_intent_missing_or_canceled")
		}
		observe, end := context.WithTimeout(bodyLife, 15*time.Second)
		err := wg.Current(observe)
		end()
		current, exists, journalErr := manager.Committed()
		if err != nil || journalErr != nil || !exists || !reflect.DeepEqual(current, committed) || !reflect.DeepEqual(store.Get(), activeConfig) || !reflect.DeepEqual(custom.List(), activeCustom) || !reflect.DeepEqual(a.Catalog, cat) {
			t.Fatal("stage=hold code=original_owner_or_config_changed")
		}
		progress.OwnerObservedUntil = time.Now().UTC()
		publish()
		command, err := wgListNativeCommand(progressRoot, progress.RunID)
		if err != nil || command == "ABORT" {
			t.Fatal("stage=hold code=external_intent_aborted_or_invalid")
		}
		if command == "STOP" {
			if time.Since(progress.ActiveAt) < in.Hold {
				t.Fatal("stage=hold code=stop_before_minimum_interval")
			}
			break
		}
		select {
		case <-bodyLife.Done():
			t.Fatal("stage=hold code=canceled")
		case <-time.After(5 * time.Second):
		}
	}
	stopConfirmed = stopRuntime()
	if !stopConfirmed {
		t.Fatal("stage=stop code=ordinary_stop_or_absence_unconfirmed")
	}
	stage("body_complete_external_traffic_requires_root_evidence")
}

func TestWGListNativeContractBoundsAndExplicitApply(t *testing.T) {
	base := map[string]string{"ROOT": "/tmp/wg-qa", "PROFILE": "/tmp/profile", "CATALOG": "/tmp/catalog", "SOURCES": "/tmp/sources", "SCOPE": "/tmp/scope", "TARGET_IPV4": "1.1.1.1", "CLIENT_IPV4": "192.168.1.2", "PROBE_URL": "https://1.1.1.1/"}
	get := func(key string) string { return base[strings.TrimPrefix(key, "RAZVILKA_NATIVE_WG_LIST_")] }
	in, err := wgListNativeParse(get)
	if err != nil || in.Apply || in.Hold != 0 || len(wgListNativeService(in).CIDRs) != 1 {
		t.Fatal("plan-only finite contract", err)
	}
	for key, value := range map[string]string{"APPLY": "1", "TARGET_IPV4": "127.0.0.1", "PROBE_URL": "https://example.com/", "CLIENT_IPV4": "::1", "ROOT": "relative"} {
		old := base[key]
		base[key] = value
		if _, err := wgListNativeParse(get); err == nil {
			t.Fatal("unsafe input accepted", key)
		}
		base[key] = old
	}
	base["APPLY"] = "APPLY_WG_LIST"
	for _, seconds := range []string{"", "0", "29", "301", "-1", "30s"} {
		base["HOLD_SECONDS"] = seconds
		if _, err := wgListNativeParse(get); err == nil {
			t.Fatal("unbounded hold", seconds)
		}
	}
	base["HOLD_SECONDS"] = "30"
	in, err = wgListNativeParse(get)
	if err != nil || !in.Apply || in.Hold != 30*time.Second {
		t.Fatal("explicit bounded apply refused", err)
	}
}

func TestWGListNativePrivateCommandIsExactBoundedIntent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root-owned private command contract")
	}
	path := t.TempDir()
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	id := strings.Repeat("a", 32)
	if command, err := wgListNativeCommand(root, id); err != nil || command != "" {
		t.Fatal("absent command is no intent", err)
	}
	for _, command := range []string{"STOP", "ABORT"} {
		if err := root.WriteAtomic("command", []byte(command+" "+id+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := wgListNativeCommand(root, id); err != nil || got != command {
			t.Fatal("exact intent refused", err)
		}
	}
	for _, data := range []string{"STOP\n", "STOP " + strings.Repeat("b", 32) + "\n", "STOP " + id, "STOP " + id + "\nextra", strings.Repeat("x", 97)} {
		if err := root.WriteAtomic("command", []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := wgListNativeCommand(root, id); err == nil {
			t.Fatal("unknown command accepted")
		}
	}
	if err := root.Remove("command"); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(path, "command"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := wgListNativeCommand(root, id); err == nil {
		t.Fatal("FIFO command accepted")
	}
	if err := root.Remove("command"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("progress.json", filepath.Join(path, "command")); err != nil {
		t.Fatal(err)
	}
	if _, err := wgListNativeCommand(root, id); err == nil {
		t.Fatal("symlink command accepted")
	}
	if got := wgListNativeRefusal([]byte(`{"code":"WG_LIST_RUNTIME_REFUSED","error":"private-data"}`)); got != "WG_LIST_RUNTIME_REFUSED" {
		t.Fatal("fixed refusal lost")
	}
	if got := wgListNativeRefusal([]byte(`{"code":"private-data","error":"private-data"}`)); got != "production_refused" {
		t.Fatal("unrecognized diagnostic disclosed")
	}
}
