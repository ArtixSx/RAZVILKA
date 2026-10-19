package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

type siteExclusionFixture struct {
	adapter                                          *NFQWS2Adapter
	runner                                           *nfqwsFakeRunner
	config, user, ipset, exclude, ipsetExclude, root string
}

// The stock nfqws2-keenetic layout: every list in one directory, the AUTO
// mode reading exclude.list and the ipset arguments reading ipset_exclude.list.
func newSiteExclusionFixture(t *testing.T, mode string) siteExclusionFixture {
	t.Helper()
	root := t.TempDir()
	// Laid out as the engine catalog's /opt paths relocated beneath root/live.
	base := filepath.Join(root, "live", "opt", "etc", "nfqws2")
	lists := filepath.Join(base, "lists")
	if err := os.MkdirAll(lists, 0o700); err != nil {
		t.Fatal(err)
	}
	f := siteExclusionFixture{runner: &nfqwsFakeRunner{}, root: root, config: filepath.Join(base, "nfqws2.conf"),
		user: filepath.Join(lists, "user.list"), ipset: filepath.Join(lists, "ipset.list"),
		exclude: filepath.Join(lists, "exclude.list"), ipsetExclude: filepath.Join(lists, "ipset_exclude.list")}
	conf := "ISP_INTERFACE=eth3\n" +
		"MODE_LIST=\"--hostlist=" + f.user + "\"\n" +
		"MODE_ALL=\"--hostlist-exclude=" + f.exclude + "\"\n" +
		"MODE_AUTO=\"$MODE_LIST $MODE_ALL\"\n" +
		"NFQWS_EXTRA_ARGS=\"" + mode + "\"\n" +
		"NFQWS_ARGS_IPSET=\"--ipset=" + f.ipset + " --ipset-exclude=" + f.ipsetExclude + "\"\n" +
		"NFQWS_ARGS_UDP=\"--filter-udp=50000-50099 --filter-l7=discord,stun --lua-desync=fake\"\n" +
		"NFQWS_ARGS_CUSTOM=\"\"\n" +
		"NFQUEUE_NUM=300\n"
	initPath, iptablesSave := filepath.Join(root, "S51nfqws2"), filepath.Join(root, "iptables-save")
	for path, content := range map[string]string{
		f.config: conf, initPath: "#!/bin/sh\n", iptablesSave: "#!/bin/sh\n", f.user: "manual.example\n", f.ipset: "",
		f.exclude: "stock.example\n", f.ipsetExclude: "10.0.0.0/8\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.adapter = &NFQWS2Adapter{ConfigPath: f.config, InitPath: initPath, UserListPath: f.user, IPSetListPath: f.ipset, IPTablesSave: iptablesSave, Runner: f.runner, HealthProbe: func(context.Context, string) error { return nil }}
	if err := f.adapter.bindStateRoot(filepath.Join(root, "state")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f siteExclusionFixture) transaction(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(f.root, name)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f siteExclusionFixture) activate(t *testing.T, plan Plan, transaction string) error {
	t.Helper()
	for _, call := range []func(context.Context, Plan, string) error{f.adapter.Snapshot, f.adapter.Stage, f.adapter.Validate, f.adapter.Activate} {
		if err := call(context.Background(), plan, transaction); err != nil {
			return err
		}
	}
	return nil
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func siteExclusionPlan() Plan {
	return Plan{
		Routes:         []Route{{ServiceName: "YouTube", Resolved: "nfqws2", Domains: []string{"youtube.com"}, ProbeURL: "https://example.com"}},
		SiteExclusions: &SiteExclusions{Domains: []string{"bank.example"}, CIDRs: []string{"198.51.100.7"}},
	}
}

// Excluded names and addresses land in managed blocks of the stock exclude
// lists beside the owner's own entries; rollback and Stop restore the lists.
func TestNFQWS2SiteExclusionListsLifecycle(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_AUTO")
	original := readText(t, f.config)
	plan := siteExclusionPlan()
	transaction := f.transaction(t, "first")
	if err := f.activate(t, plan, transaction); err != nil {
		t.Fatal(err)
	}
	exclude, ipsetExclude := readText(t, f.exclude), readText(t, f.ipsetExclude)
	if !strings.HasPrefix(exclude, "stock.example\n"+managedBegin) || !strings.Contains(exclude, "\nbank.example\n"+managedEnd) {
		t.Fatalf("exclude.list=%q", exclude)
	}
	if !strings.HasPrefix(ipsetExclude, "10.0.0.0/8\n"+managedBegin) || !strings.Contains(ipsetExclude, "\n198.51.100.7\n"+managedEnd) {
		t.Fatalf("ipset_exclude.list=%q", ipsetExclude)
	}
	if strings.Contains(readText(t, f.user), "bank.example") {
		t.Fatal("an excluded site was selected for bypass")
	}
	if config := readText(t, f.config); !strings.HasPrefix(config, original) || !strings.Contains(config, managedBegin) {
		t.Fatalf("configuration block missing or owner part changed: %q", config)
	}
	for _, call := range []func(context.Context, Plan, string) error{f.adapter.Health, f.adapter.Commit, f.adapter.Rollback} {
		if err := call(context.Background(), plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	if got := readText(t, f.exclude); got != "stock.example\n" {
		t.Fatalf("rollback exclude.list=%q", got)
	}
	if got := readText(t, f.ipsetExclude); got != "10.0.0.0/8\n" {
		t.Fatalf("rollback ipset_exclude.list=%q", got)
	}
	if got := readText(t, f.config); got != original {
		t.Fatalf("rollback config=%q", got)
	}

	if err := f.activate(t, plan, f.transaction(t, "second")); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readText(t, f.exclude); got != "stock.example\n" {
		t.Fatalf("stopped exclude.list=%q", got)
	}
	if got := readText(t, f.ipsetExclude); got != "10.0.0.0/8\n" {
		t.Fatalf("stopped ipset_exclude.list=%q", got)
	}
	if got := readText(t, f.config); got != original {
		t.Fatalf("stopped config=%q", got)
	}
}

// Like z2k, exclusions reach every nfqws2 profile the stock init composes: the
// configuration's managed block extends each profile variable the owner set,
// leaves empty ones empty and splits custom profiles on --new. Any mode then
// honours the lists; only a value that cannot be read without the shell is
// refused.
func TestNFQWS2ExclusionsReachEveryProfile(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_LIST")
	conf := strings.Replace(readText(t, f.config), `NFQWS_ARGS_CUSTOM=""`, `NFQWS_ARGS_CUSTOM="--filter-udp=1400 --filter-l7=discord --lua-desync=fake --new --filter-tcp=5222 --lua-desync=multisplit"`, 1)
	if err := os.WriteFile(f.config, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.activate(t, siteExclusionPlan(), f.transaction(t, "tx")); err != nil {
		t.Fatal(err)
	}
	config := readText(t, f.config)
	host := "--hostlist-exclude=" + f.exclude + " --ipset-exclude=" + f.ipsetExclude
	for _, want := range []string{
		`NFQWS_EXTRA_ARGS="$NFQWS_EXTRA_ARGS ` + host + `"`,
		`if [ -n "$NFQWS_ARGS_IPSET" ]; then NFQWS_ARGS_IPSET="$NFQWS_ARGS_IPSET ` + host + `"; fi`,
		`if [ -n "$NFQWS_ARGS_UDP" ]; then NFQWS_ARGS_UDP="$NFQWS_ARGS_UDP --ipset-exclude=` + f.ipsetExclude + `"; fi`,
		`NFQWS_ARGS_CUSTOM="` + nfqws2DoubleQuoted("--filter-udp=1400 --filter-l7=discord --lua-desync=fake "+host+" --new --filter-tcp=5222 --lua-desync=multisplit "+host) + `"`,
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("configuration lacks %q:\n%s", want, config)
		}
	}
	// What the init's shell actually sees, where a POSIX shell is available.
	if sh, err := exec.LookPath("sh"); err == nil && runtime.GOOS != "windows" {
		out, err := exec.Command(sh, "-c", `. "$1"; printf '%s\n' "$NFQWS_EXTRA_ARGS" "$NFQWS_ARGS_UDP" "$NFQWS_ARGS_CUSTOM"`, "sh", f.config).Output()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if err != nil || len(lines) != 3 || !strings.HasSuffix(lines[0], host) || !strings.HasPrefix(lines[0], "--hostlist="+f.user) ||
			!strings.HasSuffix(lines[1], "--ipset-exclude="+f.ipsetExclude) || strings.Count(lines[2], host) != 2 {
			t.Fatalf("sourced profiles: %v %q", err, lines)
		}
	}

	// Nothing to exclude: the owner's configuration stays exactly as it is.
	g := newSiteExclusionFixture(t, "$MODE_AUTO")
	original := readText(t, g.config)
	plan := siteExclusionPlan()
	plan.SiteExclusions = nil
	if err := g.activate(t, plan, g.transaction(t, "none")); err != nil {
		t.Fatal(err)
	}
	if got := readText(t, g.config); got != original {
		t.Fatalf("configuration changed without exclusions: %q", got)
	}

	for name, replace := range map[string][2]string{
		"custom-substitution": {`NFQWS_ARGS_CUSTOM=""`, `NFQWS_ARGS_CUSTOM="$OTHER_PROFILE"`},
		"braced-reference":    {`NFQWS_EXTRA_ARGS="$MODE_AUTO"`, `NFQWS_EXTRA_ARGS="${MODE_AUTO}"`},
	} {
		h := newSiteExclusionFixture(t, "$MODE_AUTO")
		conf := strings.Replace(readText(t, h.config), replace[0], replace[1], 1)
		if err := os.WriteFile(h.config, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := h.activate(t, siteExclusionPlan(), h.transaction(t, "tx")); !errors.Is(err, ErrSiteExclusionsUnread) {
			t.Fatalf("%s: unreadable configuration accepted: %v", name, err)
		}
		if got := readText(t, h.config); got != conf || readText(t, h.exclude) != "stock.example\n" {
			t.Fatalf("%s: refused Stage changed files", name)
		}
	}
}

// An interrupted cleanup that already removed only the configuration block is
// finished by Stop and restored, proven by the lease, by boot reconcile.
func TestNFQWS2ConfigurationBlockSurvivesInterruptedCleanup(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_AUTO")
	original := readText(t, f.config)
	plan := siteExclusionPlan()
	transaction := f.transaction(t, "tx")
	if err := f.activate(t, plan, transaction); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func(context.Context, Plan, string) error{f.adapter.Health, f.adapter.Commit} {
		if err := call(context.Background(), plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	installed := readText(t, f.config)
	if err := os.WriteFile(f.config, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Reconcile(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if got := readText(t, f.config); got != installed {
		t.Fatalf("reconcile did not restore the proven block: %q", got)
	}
	if err := os.WriteFile(f.config, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Deactivate(context.Background()); err != nil {
		t.Fatal("stop after a partial cleanup:", err)
	}
	if got := readText(t, f.config); got != original {
		t.Fatalf("stopped config=%q", got)
	}
}

// An excluded service keeps its route but leaves the selection lists; its
// catalog names and networks go to the exclude lists instead.
func TestNFQWS2ExcludedServiceLeavesSelectionLists(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_AUTO")
	plan := Plan{Routes: []Route{
		{ServiceID: "youtube", ServiceName: "YouTube", Resolved: "nfqws2", Domains: []string{"youtube.com"}, ProbeURL: "https://example.com"},
		{ServiceID: "video", ServiceName: "Видео", Resolved: "nfqws2", Domains: []string{"video.example"}, CIDRs: []string{"192.0.2.0/24"}, ProbeURL: "https://example.com"},
	}, SiteExclusions: &SiteExclusions{Services: []string{"video"}, ServiceDomains: []string{"video.example"}, ServiceCIDRs: []string{"192.0.2.0/24"}}}
	if err := f.activate(t, plan, f.transaction(t, "tx")); err != nil {
		t.Fatal(err)
	}
	user, ipset, exclude, ipsetExclude := readText(t, f.user), readText(t, f.ipset), readText(t, f.exclude), readText(t, f.ipsetExclude)
	if strings.Contains(user, "video.example") || strings.Contains(ipset, "192.0.2.0/24") || !strings.Contains(user, "\nyoutube.com\n") {
		t.Fatalf("excluded service stayed selected: user=%q ipset=%q", user, ipset)
	}
	if !strings.Contains(exclude, "\nvideo.example\n") || !strings.Contains(ipsetExclude, "\n192.0.2.0/24\n") {
		t.Fatalf("excluded service was not excluded: exclude=%q ipset_exclude=%q", exclude, ipsetExclude)
	}
	// Only the excluded service on NFQWS2 still writes its exclusions.
	g := newSiteExclusionFixture(t, "$MODE_AUTO")
	plan.Routes = plan.Routes[1:]
	if err := g.activate(t, plan, g.transaction(t, "tx")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readText(t, g.exclude), "\nvideo.example\n") {
		t.Fatal("exclusions were dropped when the excluded service is the adapter's only route")
	}
}

// Commit settles a list draft; a later rollback of the same transaction gives
// the owner's edit back as a draft instead of losing it.
func TestNFQWS2RollbackAfterCommitRestagesListDraft(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_AUTO")
	configs := engineconfig.New(filepath.Join(f.root, "drafts"), filepath.Join(f.root, "backups"))
	configs.LiveRoot = filepath.Join(f.root, "live")
	f.adapter.Configs = configs
	if _, err := configs.Stage("nfqws2", "exclude-list", "stock.example\nowner.example\n"); err != nil {
		t.Fatal(err)
	}
	plan := siteExclusionPlan()
	plan.EngineDrafts = []string{"nfqws2/exclude-list"}
	transaction := f.transaction(t, "draft")
	if err := f.activate(t, plan, transaction); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func(context.Context, Plan, string) error{f.adapter.Health, f.adapter.Commit, f.adapter.Rollback} {
		if err := call(context.Background(), plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	if got := readText(t, f.exclude); got != "stock.example\n" {
		t.Fatalf("rollback exclude.list=%q", got)
	}
	view, err := configs.ReadExpert("nfqws2", "exclude-list")
	if err != nil || view.Source != "staged" || !strings.Contains(view.Content, "owner.example") {
		t.Fatalf("the owner's list edit was lost on rollback: %v %q %q", err, view.Source, view.Content)
	}
}

// The owner's part of a list edited in the engine editor is applied with the
// managed block and the draft is settled on commit.
func TestNFQWS2AppliesEngineListDraftBesideManagedBlock(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_AUTO")
	configs := engineconfig.New(filepath.Join(f.root, "drafts"), filepath.Join(f.root, "backups"))
	configs.LiveRoot = filepath.Join(f.root, "live")
	f.adapter.Configs = configs
	if _, err := configs.Stage("nfqws2", "exclude-list", "stock.example\nowner.example\n"); err != nil {
		t.Fatal(err)
	}
	plan := siteExclusionPlan()
	plan.EngineDrafts = []string{"nfqws2/exclude-list"}
	transaction := f.transaction(t, "draft")
	if err := f.activate(t, plan, transaction); err != nil {
		t.Fatal(err)
	}
	if got := readText(t, f.exclude); !strings.HasPrefix(got, "stock.example\nowner.example\n"+managedBegin) || !strings.Contains(got, "\nbank.example\n"+managedEnd) {
		t.Fatalf("exclude.list=%q", got)
	}
	for _, call := range []func(context.Context, Plan, string) error{f.adapter.Health, f.adapter.Commit} {
		if err := call(context.Background(), plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	if view, err := configs.ReadExpert("nfqws2", "exclude-list"); err != nil || view.Source == "staged" {
		t.Fatalf("applied list draft was not settled: %v %+v", err, view.Source)
	}
}

// An address route cannot honour a name exclusion and must never carry an
// excluded address; NFQWS2 and direct routes are enforced or unaffected.
func TestBuildBlocksAddressRouteOverExcludedAddress(t *testing.T) {
	input := Input{Revision: 3, Routes: []Route{
		{ServiceID: "telegram", ServiceName: "Telegram", Resolved: "sing-box", CIDRs: []string{"198.51.100.0/24"}},
		{ServiceID: "video", ServiceName: "Видео", Resolved: "nfqws2", CIDRs: []string{"198.51.100.0/24"}},
	}, SiteExclusions: &SiteExclusions{CIDRs: []string{"198.51.100.7"}}}
	plan, err := BuildAt(input, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	conflicts := 0
	for _, blocker := range plan.Blockers {
		if blocker.Code == "SITE_EXCLUSION_CONFLICT" {
			conflicts++
			if !strings.Contains(blocker.Message, "Telegram") || strings.Contains(blocker.Message, "Видео") {
				t.Fatalf("wrong conflict: %+v", blocker)
			}
		}
	}
	if conflicts != 1 || plan.Ready {
		t.Fatalf("conflict not blocked: %+v", plan.Blockers)
	}
	input.SiteExclusions = &SiteExclusions{CIDRs: []string{"192.0.2.7"}, Domains: []string{"bank.example"}}
	other, err := BuildAt(input, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, blocker := range other.Blockers {
		if blocker.Code == "SITE_EXCLUSION_CONFLICT" {
			t.Fatalf("unrelated exclusion blocked: %+v", blocker)
		}
	}
	if other.Digest == plan.Digest {
		t.Fatal("exclusions are not bound to the reviewed digest")
	}
	if _, err := BuildAt(Input{SiteExclusions: &SiteExclusions{Domains: []string{"bad domain"}}}, time.Unix(100, 0).UTC()); err == nil {
		t.Fatal("invalid excluded domain accepted")
	}
}

func TestLegacySiteExclusionsFromSavedList(t *testing.T) {
	cfg := config.Default()
	if sites, err := LegacySiteExclusions(cfg); err != nil || sites != nil {
		t.Fatalf("absent list: %+v %v", sites, err)
	}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{
		{Kind: "exact", Value: "example.com"}, {Kind: "suffix", Value: "example.com"}, {Kind: "cidr", Value: "203.0.113.0/24"}, {Kind: "service", Value: "video"},
	}}
	sites, err := LegacySiteExclusions(cfg)
	if err != nil || sites == nil || strings.Join(sites.Domains, ",") != "example.com" || strings.Join(sites.CIDRs, ",") != "203.0.113.0/24" || strings.Join(sites.Services, ",") != "video" {
		t.Fatalf("saved list: %+v %v", sites, err)
	}
	// The catalog expansion is frozen per plan and not part of the comparison.
	expanded := &SiteExclusions{Domains: []string{"example.com", "example.com"}, CIDRs: []string{"203.0.113.0/24"}, Services: []string{"video"}, ServiceDomains: []string{"video.example"}}
	if !SameSiteExclusions(sites, expanded) || SameSiteExclusions(sites, nil) || SameSiteExclusions(sites, &SiteExclusions{Domains: []string{"example.com"}, CIDRs: []string{"203.0.113.0/24"}}) {
		t.Fatal("canonical comparison")
	}
	// The home-network mode keeps its own policy; this mode reads nothing.
	cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1}
	if sites, err := LegacySiteExclusions(cfg); err != nil || sites != nil {
		t.Fatalf("list mode leaked into the whole-network plan: %+v %v", sites, err)
	}
}

func TestBuildNamesExcludedServiceRoutedThroughProxy(t *testing.T) {
	plan, err := BuildAt(Input{Revision: 3, Routes: []Route{
		{ServiceID: "tg", ServiceName: "Telegram", Resolved: "sing-box:node-1", CIDRs: []string{"149.154.160.0/20"}},
		{ServiceID: "yt", ServiceName: "YouTube", Resolved: "nfqws2", Domains: []string{"youtube.com"}},
	}, SiteExclusions: &SiteExclusions{Services: []string{"tg", "yt"}, ServiceCIDRs: []string{"149.154.160.0/20"}, ServiceDomains: []string{"youtube.com"}}}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	routed, conflicts := 0, 0
	for _, blocker := range plan.Blockers {
		switch blocker.Code {
		case "SITE_EXCLUSION_SERVICE_ROUTED":
			routed++
			if !strings.Contains(blocker.Message, "Telegram") || strings.Contains(blocker.Message, "YouTube") {
				t.Fatalf("wrong service named: %+v", blocker)
			}
		case "SITE_EXCLUSION_CONFLICT":
			conflicts++
		}
	}
	if routed != 1 || conflicts != 0 || plan.Ready {
		t.Fatalf("excluded proxy service not refused once with its own reason: %+v", plan.Blockers)
	}
}

// An excluded service, or a route whose checked site is excluded, is left
// alone by NFQWS2: it is neither probed through the bypass nor credited.
func TestNFQWS2HealthSkipsExcludedRoutes(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_AUTO")
	probed := []string{}
	f.adapter.HealthProbe = func(_ context.Context, url string) error {
		probed = append(probed, url)
		if strings.Contains(url, "video.example") || strings.Contains(url, "bank.example") {
			return errors.New("blocked without the bypass")
		}
		return nil
	}
	input := Input{Revision: 3, Routes: []Route{
		{ServiceID: "youtube", ServiceName: "YouTube", Resolved: "nfqws2", Domains: []string{"youtube.com"}, ProbeURL: "https://www.youtube.com/"},
		{ServiceID: "video", ServiceName: "Видео", Resolved: "nfqws2", Domains: []string{"video.example"}, ProbeURL: "https://video.example/"},
		{ServiceID: "bank", ServiceName: "Банк", Resolved: "nfqws2", Domains: []string{"bank.example"}, ProbeURL: "https://www.bank.example/"},
	}, SiteExclusions: &SiteExclusions{Domains: []string{"bank.example"}, Services: []string{"video"}, ServiceDomains: []string{"video.example"}}}
	plan, err := BuildAt(input, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	transaction := f.transaction(t, "tx")
	if err := f.activate(t, plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Health(context.Background(), plan, transaction); err != nil || len(probed) != 1 || probed[0] != "https://www.youtube.com/" {
		t.Fatalf("excluded routes were probed: %v %v", err, probed)
	}
	for _, proof := range plan.RouteEvidence {
		excluded := proof.ServiceID == "video" || proof.ServiceID == "bank"
		if excluded != (proof.Required == evidence.None) || excluded && proof.Note != siteExclusionEvidenceNote {
			t.Fatalf("route evidence for %s: %+v", proof.ServiceID, proof)
		}
	}
}
