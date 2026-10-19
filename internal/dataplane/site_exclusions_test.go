package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
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
		"NFQWS_ARGS_IPSET=\"--ipset=" + f.ipset + " --ipset-exclude=" + f.ipsetExclude + "\"\n"
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
}

// A configuration that does not read the exclude lists would silently bypass
// an excluded site, so Stage refuses before any list is written.
func TestNFQWS2SiteExclusionsRequireExcludeLists(t *testing.T) {
	f := newSiteExclusionFixture(t, "$MODE_LIST")
	err := f.activate(t, siteExclusionPlan(), f.transaction(t, "list-mode"))
	if err == nil || !strings.Contains(err.Error(), "$MODE_LIST") {
		t.Fatalf("list-only mode accepted exclusions: %v", err)
	}
	if got := readText(t, f.exclude); got != "stock.example\n" {
		t.Fatalf("refused Stage wrote exclude.list=%q", got)
	}
	// Without exclusions the same mode stays usable.
	plan := siteExclusionPlan()
	plan.SiteExclusions = nil
	if err := f.activate(t, plan, f.transaction(t, "no-exclusions")); err != nil {
		t.Fatal(err)
	}

	g := newSiteExclusionFixture(t, "$MODE_AUTO")
	conf := strings.Replace(readText(t, g.config), " --ipset-exclude="+g.ipsetExclude, "", 1)
	if err := os.WriteFile(g.config, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.activate(t, siteExclusionPlan(), g.transaction(t, "no-ipset-exclude")); err == nil || !strings.Contains(err.Error(), "--ipset-exclude") {
		t.Fatalf("missing --ipset-exclude accepted address exclusions: %v", err)
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
	if sites, services, err := LegacySiteExclusions(cfg); err != nil || sites != nil || len(services) != 0 {
		t.Fatalf("absent list: %+v %v %v", sites, services, err)
	}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{
		{Kind: "exact", Value: "example.com"}, {Kind: "suffix", Value: "example.com"}, {Kind: "cidr", Value: "203.0.113.0/24"}, {Kind: "service", Value: "video"},
	}}
	sites, services, err := LegacySiteExclusions(cfg)
	if err != nil || sites == nil || strings.Join(sites.Domains, ",") != "example.com" || strings.Join(sites.CIDRs, ",") != "203.0.113.0/24" || !services["video"] {
		t.Fatalf("saved list: %+v %v %v", sites, services, err)
	}
	if !SameSiteExclusions(sites, &SiteExclusions{Domains: []string{"example.com", "example.com"}, CIDRs: []string{"203.0.113.0/24"}}) || SameSiteExclusions(sites, nil) {
		t.Fatal("canonical comparison")
	}
	// The home-network mode keeps its own policy; this mode reads nothing.
	cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1}
	if sites, _, err := LegacySiteExclusions(cfg); err != nil || sites != nil {
		t.Fatalf("list mode leaked into the whole-network plan: %+v %v", sites, err)
	}
}
