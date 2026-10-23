package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

const (
	managedBegin = engineconfig.ManagedListBegin
	managedEnd   = engineconfig.ManagedListEnd
)

type NFQWS2Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type nfqws2ExecRunner struct{}

func (nfqws2ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type NFQWS2Adapter struct {
	StateRoot                 string
	ConfigPath                string
	UserListPath              string
	IPSetListPath             string
	ExcludeListPath           string // Stock hostlist-exclude list: owner's sites without bypass.
	IPSetExcludeListPath      string // Stock ipset-exclude list: owner's addresses without bypass.
	InitPath                  string
	IPTablesSave              string
	Runner                    NFQWS2Runner
	Configs                   *engineconfig.Manager
	HealthProbe               func(context.Context, string) error
	Timeout                   time.Duration
	activationLeaseReady      func()             // Deterministic fault injection before the first global write.
	activeProcess             *nfqws2ActiveOwner // Only the actual separate producer can install it.
	activeExecution           *nfqws2ActiveExecution
	inactivity                *NFQWSRuntimeInactiveSource                                         // Bound once by the trusted startup owner.
	stockNativeOwner          *components.Manager                                                 // Actual startup component owner, parameter-check only.
	firstStartObservation     func(context.Context, bool) error                                   // Private deterministic observation model for lifecycle tests; never bound by startup.
	firstStartProcessRead     func(int) (components.NFQWSRuntimeProcessIdentity, error)           // Private process readback model, never bound by startup.
	firstStartStopReview      func(context.Context, components.NFQWSRuntimeProcessIdentity) error // Private full process/PIDfile model; production uses its startup source.
	firstStartRetirementReady func(string)                                                        // Private deterministic file-CAS fault model, never bound by startup.
	firstStartReview          *components.StockNFQWSNativeReview                                  // Bounded to the current real Apply, never a detached permission.
	firstStartReviewRoot      string
	firstStartScopeRead       func(context.Context) ([]byte, string, error) // Private fact-source model; production uses its original protected provider/current WAN.
	firstStartReceiptReady    func()                                        // Private deterministic fault injection after exact running receipt persistence.
}

type nfqws2Snapshot struct {
	FirstStart           bool         `json:"first_start,omitempty"`
	Init                 []byte       `json:"init,omitempty"`
	InitMode             os.FileMode  `json:"init_mode,omitempty"`
	RunningConfig        []byte       `json:"running_config,omitempty"`
	RunningConfigExisted bool         `json:"running_config_existed,omitempty"`
	Lease                *nfqws2Lease `json:"instance_lease,omitempty"`
	UserListExisted      bool         `json:"user_list_existed"`
	UserList             []byte       `json:"user_list,omitempty"`
	IPSetListExisted     bool         `json:"ipset_list_existed"`
	IPSetList            []byte       `json:"ipset_list,omitempty"`
	ExcludeExisted       bool         `json:"exclude_list_existed"`
	ExcludeList          []byte       `json:"exclude_list,omitempty"`
	IPSetExclExisted     bool         `json:"ipset_exclude_list_existed"`
	IPSetExcludeList     []byte       `json:"ipset_exclude_list,omitempty"`
	WasRunning           bool         `json:"was_running"`
	ConfigExisted        bool         `json:"config_existed"`
	Config               []byte       `json:"config,omitempty"`
	ConfigDraft          bool         `json:"config_draft"`
	StagedConfig         []byte       `json:"staged_config,omitempty"`
	// Owner's part of each managed list from the engine editor, in lease order.
	ListDraft   [4]bool   `json:"list_draft"`
	StagedLists [4][]byte `json:"staged_lists,omitempty"`
}

func NewNFQWS2Adapter() *NFQWS2Adapter {
	return &NFQWS2Adapter{
		ConfigPath: "/opt/etc/nfqws2/nfqws2.conf", UserListPath: "/opt/etc/nfqws2/lists/user.list",
		IPSetListPath: "/opt/etc/nfqws2/lists/ipset.list", InitPath: "/opt/etc/init.d/S51nfqws2",
		Runner: nfqws2ExecRunner{}, Timeout: 20 * time.Second,
	}
}

func (*NFQWS2Adapter) ID() string { return "nfqws2" }

func (a *NFQWS2Adapter) Snapshot(ctx context.Context, plan Plan, root string) error {
	if e, present, err := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		if err != nil {
			return preflightRefusalError{err}
		}
		return e.prepare(ctx)
	}
	snapshot := nfqws2Snapshot{}
	var err error
	snapshot.Lease, err = a.readLease()
	if err != nil {
		return preflightRefusalError{err}
	}
	snapshot.Config, snapshot.ConfigExisted, err = nfqws2Read(a.ConfigPath)
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 config: %w", err)
	}
	if a.Configs != nil {
		content, readErr := a.Configs.ReadExpert(a.ID(), "main")
		if readErr != nil {
			return fmt.Errorf("read NFQWS2 config draft: %w", readErr)
		}
		if planUsesEngineDraft(plan, a.ID(), "main") && content.Source == "staged" {
			snapshot.ConfigDraft = true
			snapshot.StagedConfig = []byte(content.Content)
		}
		for index, fileID := range nfqws2ListFileIDs {
			if !planUsesEngineDraft(plan, a.ID(), fileID) {
				continue
			}
			content, readErr := a.Configs.ReadExpert(a.ID(), fileID)
			if readErr != nil {
				return fmt.Errorf("read NFQWS2 list draft: %w", readErr)
			}
			if content.Source == "staged" {
				snapshot.ListDraft[index], snapshot.StagedLists[index] = true, []byte(content.Content)
			}
		}
	}
	snapshot.UserList, snapshot.UserListExisted, err = nfqws2Read(a.UserListPath)
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 user list: %w", err)
	}
	snapshot.ExcludeList, snapshot.ExcludeExisted, err = nfqws2Read(a.ownedListPaths()[2])
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 exclude list: %w", err)
	}
	snapshot.IPSetExcludeList, snapshot.IPSetExclExisted, err = nfqws2Read(a.ownedListPaths()[3])
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 ipset exclude list: %w", err)
	}
	snapshot.IPSetList, snapshot.IPSetListExisted, err = nfqws2Read(a.IPSetListPath)
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 ipset list: %w", err)
	}
	if err := a.prepareFirstStartSnapshot(ctx, plan, &snapshot); err != nil {
		return preflightRefusalError{err}
	}
	if a.Runner != nil && regularFile(a.InitPath) && !(snapshot.FirstStart && snapshot.Lease == nil) {
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		action := "status"
		if snapshot.FirstStart {
			action = "owned_status"
		}
		output, statusErr := a.Runner.Run(probeCtx, a.InitPath, action)
		cancel()
		snapshot.WasRunning = statusErr == nil && runningOutput(string(output))
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(root, "snapshot.json"), data, 0o600)
}

func (a *NFQWS2Adapter) Stage(ctx context.Context, plan Plan, root string) error {
	if e, present, err := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		if err != nil {
			return preflightRefusalError{err}
		}
		return e.prepare(ctx)
	}
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return err
	}
	config := snapshot.Config
	if snapshot.ConfigDraft {
		config = snapshot.StagedConfig
	}
	if len(config) == 0 {
		return errors.New("NFQWS2 configuration is empty")
	}
	lists := nfqws2PlanLists(plan, a.ID())
	for index, values := range lists {
		for _, value := range values {
			if index%2 == 0 && !validManagedDomain(value) {
				return fmt.Errorf("invalid NFQWS2 domain %q", value)
			}
			if index%2 == 1 {
				if _, err := netip.ParsePrefix(value); err != nil {
					if _, addrErr := netip.ParseAddr(value); addrErr != nil {
						return fmt.Errorf("invalid NFQWS2 CIDR %q", value)
					}
				}
			}
		}
	}
	var merged [4][]byte
	for index, values := range lists {
		base := []byte(nil)
		if snapshot.ListDraft[index] {
			base = snapshot.StagedLists[index]
		}
		if merged[index], err = a.mergeOwnedList(index, values, base, snapshot.ListDraft[index]); err != nil {
			return preflightRefusalError{err}
		}
	}
	// Exclusions reach every nfqws2 profile through the configuration's own
	// managed block; without that the owner's configuration is unchanged.
	staged, err := a.exclusionConfig(config, plan)
	if snapshot.FirstStart {
		staged, err = a.stageFirstStart(plan, root, snapshot)
	}
	if err != nil {
		return preflightRefusalError{err}
	}
	if err := writeAtomic(filepath.Join(root, "nfqws2.conf.staged"), staged, 0o600); err != nil {
		return err
	}
	for index := range lists {
		if err := writeAtomic(filepath.Join(root, nfqws2ListStages[index]), merged[index], 0o600); err != nil {
			return err
		}
	}
	return nil
}

// The stock lists RAZVILKA keeps one managed block in, in lease order:
// selected domains, selected addresses, excluded domains, excluded addresses.
var nfqws2ListStages = [4]string{"user.list.staged", "ipset.list.staged", "exclude.list.staged", "ipset_exclude.list.staged"}

// The engine editor's files that hold the owner's part of the same lists.
var nfqws2ListFileIDs = [4]string{"user-list", "ipset-list", "exclude-list", "ipset-exclude"}

func (a *NFQWS2Adapter) ownedListPaths() [4]string {
	// The stock package keeps every list in one directory; an adapter that
	// names only its selection lists finds the exclude lists beside them.
	exclude, ipsetExclude := a.ExcludeListPath, a.IPSetExcludeListPath
	if exclude == "" && a.UserListPath != "" {
		exclude = filepath.Join(filepath.Dir(a.UserListPath), "exclude.list")
	}
	if ipsetExclude == "" && a.IPSetListPath != "" {
		ipsetExclude = filepath.Join(filepath.Dir(a.IPSetListPath), "ipset_exclude.list")
	}
	return [4]string{a.UserListPath, a.IPSetListPath, exclude, ipsetExclude}
}

func (s nfqws2Snapshot) ownedList(index int) ([]byte, bool) {
	switch index {
	case 0:
		return s.UserList, s.UserListExisted
	case 1:
		return s.IPSetList, s.IPSetListExisted
	case 2:
		return s.ExcludeList, s.ExcludeExisted
	default:
		return s.IPSetExcludeList, s.IPSetExclExisted
	}
}

// nfqws2PlanLists returns the four managed blocks of a plan, in lease order.
// An excluded service keeps its route but leaves the selection lists, and
// exclusions are written while this adapter carries any route at all.
func nfqws2PlanLists(plan Plan, id string) [4][]string {
	domains, cidrs := []string{}, []string{}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != id {
			continue
		}
		if plan.SiteExclusions.excludesService(route.ServiceID) {
			continue
		}
		domains = append(domains, route.Domains...)
		cidrs = append(cidrs, route.CIDRs...)
	}
	// The package's exclude lists keep only an empty block: an entry there
	// would make the owner's profiles that read them require a hostname.
	// Exclusions reach nfqws2 through the configuration block instead.
	return [4][]string{sortedUnique(domains), sortedUnique(cidrs), {}, {}}
}

// nfqws2PlanExclusions are the names and addresses nfqws2 must leave alone,
// while this adapter carries any route at all.
func nfqws2PlanExclusions(plan Plan, id string) ([]string, []string) {
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == id && plan.SiteExclusions != nil {
			return plan.SiteExclusions.ExcludedDomains(), plan.SiteExclusions.ExcludedCIDRs()
		}
	}
	return nil, nil
}

// ErrSiteExclusionsUnread marks "sites without bypass" that cannot be given
// to nfqws2.
var ErrSiteExclusionsUnread = errors.New("NFQWS2_SITE_EXCLUSIONS_UNREAD")

// nfqws2ExclusionFormat names the block layout. A later release that changes
// it must still render this one: boot recovery proves a removed block by
// re-rendering it against the hash the activating release recorded.
const nfqws2ExclusionFormat = "# RAZVILKA NFQWS2 EXCLUSIONS v1"

// maxNFQWS2ExclusionArguments keeps the inline lists, and so the whole
// nfqws2 command line, well inside what RAZVILKA's process scans read.
const maxNFQWS2ExclusionArguments = 48 << 10

// exclusionConfig renders the owner's nfqws2.conf with this instance's managed
// block. nfqws2 selects the first matching profile and selects again once a
// connection's hostname is known. The block therefore puts one or two
// profiles without any action before every profile of the owner: excluded
// names (--hostlist-domains) and excluded addresses (--ipset-ip). Excluded
// traffic lands there and is passed unchanged; everything else, including
// connections without a hostname, reaches the owner's profiles exactly as
// before. The owner's profiles and the package's own lists are not changed.
// With nothing to exclude the owner's configuration is returned unchanged.
func (a *NFQWS2Adapter) exclusionConfig(config []byte, plan Plan) ([]byte, error) {
	domains, addresses := nfqws2PlanExclusions(plan, a.ID())
	owner, err := a.owner()
	if err != nil {
		return nil, err
	}
	block, err := nfqws2Block(config)
	if err != nil {
		return nil, err
	}
	if len(block) != 0 && !strings.Contains(string(block), "\n# RAZVILKA INSTANCE "+owner+"\n") {
		return nil, errors.New("NFQWS2 configuration block is not owned by this instance")
	}
	ownerPart, _, err := removeManagedBlock(string(config))
	if err != nil {
		return nil, err
	}
	if len(domains)+len(addresses) == 0 {
		return []byte(ownerPart), nil
	}
	profiles := []string{}
	if len(domains) != 0 {
		for _, name := range domains {
			if !validManagedDomain(name) {
				return nil, fmt.Errorf("invalid NFQWS2 domain %q", name)
			}
		}
		profiles = append(profiles, "--hostlist-domains="+strings.Join(sortedUnique(domains), ","))
	}
	if len(addresses) != 0 {
		subnets := make([]string, 0, len(addresses))
		for _, value := range addresses {
			prefix, err := siteExclusionPrefix(value)
			if err != nil {
				return nil, fmt.Errorf("invalid NFQWS2 CIDR %q", value)
			}
			subnets = append(subnets, prefix.String())
		}
		profiles = append(profiles, "--ipset-ip="+strings.Join(sortedUnique(subnets), ","))
	}
	leading := strings.Join(profiles, " --new ")
	if len(leading) > maxNFQWS2ExclusionArguments {
		return nil, fmt.Errorf("%w: список «Сайтов без обхода» слишком длинный для nfqws2; сократите его", ErrSiteExclusionsUnread)
	}
	// The init sources the file more than once per restart; the line adds
	// the profiles only where they are not already first.
	lines := []string{"# RAZVILKA INSTANCE " + owner, nfqws2ExclusionFormat,
		`case "$NFQWS_ARGS_CUSTOM" in "` + leading + `"|"` + leading + ` --new "*) ;; "") NFQWS_ARGS_CUSTOM="` + leading + `" ;; *) NFQWS_ARGS_CUSTOM="` + leading + ` --new $NFQWS_ARGS_CUSTOM" ;; esac`}
	merged, err := replaceManagedBlock(ownerPart, lines)
	if err != nil {
		return nil, err
	}
	return []byte(merged), nil
}

func (a *NFQWS2Adapter) Validate(ctx context.Context, plan Plan, root string) error {
	if e, present, err := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		if err != nil {
			return preflightRefusalError{err}
		}
		return e.prepare(ctx)
	}
	required := []string{a.InitPath, filepath.Join(root, "nfqws2.conf.staged")}
	for _, stage := range nfqws2ListStages {
		required = append(required, filepath.Join(root, stage))
	}
	for _, path := range required {
		if !regularFile(path) {
			return fmt.Errorf("required NFQWS2 file is missing: %s", path)
		}
	}
	if a.Configs != nil {
		if validation := a.Configs.Validate(a.ID(), "main"); !validation.OK {
			return fmt.Errorf("NFQWS2 native config validation failed: %s", validation.Output)
		}
	}
	for _, stage := range nfqws2ListStages {
		path := filepath.Join(root, stage)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Count(string(data), managedBegin) != 1 || strings.Count(string(data), managedEnd) != 1 {
			return fmt.Errorf("invalid managed block in %s", path)
		}
	}
	if err := a.validateStockNative(ctx, plan, root); err != nil {
		return preflightRefusalError{err}
	}
	return nil
}

func (a *NFQWS2Adapter) Activate(ctx context.Context, plan Plan, root string) error {
	if e, present, err := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		if err != nil {
			return err
		}
		return e.activate(ctx)
	}
	unlock, err := a.lockResources()
	if err != nil {
		return preflightRefusalError{err}
	}
	defer unlock()
	if err := a.prepareActivationLease(root, plan); err != nil {
		return preflightRefusalError{err}
	}
	if a.activationLeaseReady != nil {
		a.activationLeaseReady()
	}
	if err := a.activateFirstStartInit(ctx, root); err != nil {
		return err
	}
	installConfigErr := error(nil)
	firstSnapshot, readErr := readNFQWS2Snapshot(root)
	if readErr != nil {
		return readErr
	}
	if firstSnapshot.FirstStart {
		installConfigErr = a.installFirstStartResources(root, firstSnapshot)
	} else {
		installConfigErr = installStaged(filepath.Join(root, "nfqws2.conf.staged"), a.ConfigPath)
	}
	if err := installConfigErr; err != nil {
		return fmt.Errorf("activate NFQWS2 config: %w", err)
	}
	// nfqws2 drops privileges to `nobody` before it opens host/ipset files.
	// Keeping these generated lists at 0600 makes the init script print
	// "Started" while the daemon exits immediately with EACCES.
	for index, path := range a.ownedListPaths() {
		if firstSnapshot.FirstStart {
			break
		}
		if err := installStagedMode(filepath.Join(root, nfqws2ListStages[index]), path, 0o644); err != nil {
			return fmt.Errorf("activate NFQWS2 list %s: %w", filepath.Base(path), err)
		}
	}
	var output []byte
	if firstSnapshot.FirstStart {
		err = a.startFirstStart(ctx, root)
	} else {
		output, err = a.run(ctx, a.InitPath, "restart")
	}
	if err != nil {
		return fmt.Errorf("restart NFQWS2: %s", shortOutput(output, err))
	}
	// Some Entware init scripts return zero even when nfqws2 failed after
	// daemonising (for example, unreadable lists). Never report activation as
	// successful until the process is observable.
	status, statusErr := a.run(ctx, a.InitPath, "status")
	if statusErr != nil || !runningOutput(string(status)) {
		return fmt.Errorf("NFQWS2 did not stay running after restart: %s", shortOutput(status, statusErr))
	}
	return nil
}

func (a *NFQWS2Adapter) Commit(ctx context.Context, plan Plan, root string) error {
	if e, present, err := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		if err != nil {
			return err
		}
		return e.health(ctx)
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return err
	}
	if a.Configs == nil {
		return nil
	}
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return err
	}
	for index, used := range snapshot.ListDraft {
		if used {
			if err := a.Configs.Discard(a.ID(), nfqws2ListFileIDs[index]); err != nil {
				return err
			}
		}
	}
	if snapshot.ConfigDraft {
		return a.Configs.Discard(a.ID(), "main")
	}
	return nil
}

func (a *NFQWS2Adapter) Health(ctx context.Context, plan Plan, root string) error {
	if e, present, err := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		if err != nil {
			return err
		}
		return e.health(ctx)
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return err
	}
	if err := a.verifyFirstStartRunning(ctx); err != nil {
		return err
	}
	if lease, err := a.readLease(); err != nil {
		return err
	} else if lease != nil && lease.FirstStart != nil {
		config, _, err := nfqws2Read(a.ConfigPath)
		if err != nil {
			return err
		}
		if err := a.reviewFirstStartScope(ctx, config, true); err != nil {
			return err
		}
	}
	output, err := a.run(ctx, a.InitPath, "status")
	if err != nil || !runningOutput(string(output)) {
		return fmt.Errorf("NFQWS2 status is not running: %s", shortOutput(output, err))
	}
	iptablesSave := a.IPTablesSave
	if iptablesSave == "" {
		iptablesSave = findExecutable("/opt/sbin/iptables-save", "/opt/bin/iptables-save", "iptables-save")
	}
	if iptablesSave == "" {
		return errors.New("iptables-save is unavailable")
	}
	output, err = a.run(ctx, iptablesSave)
	if err != nil || !strings.Contains(strings.ToLower(string(output)), "nfqws") || !strings.Contains(strings.ToUpper(string(output)), "NFQUEUE") {
		return fmt.Errorf("active NFQWS2 NFQUEUE rules were not confirmed: %s", shortOutput(output, err))
	}
	probe := a.HealthProbe
	if probe == nil {
		probe = defaultNFQWS2Probe
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() || route.ProbeURL == "" || plan.SiteExclusions.coversRoute(route) {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		err := probeNFQWS2Health(probeCtx, route.ProbeURL, probe)
		cancel()
		if err != nil {
			return fmt.Errorf("%s health probe: %w", route.ServiceName, err)
		}
	}
	return nil
}

func (a *NFQWS2Adapter) Reconcile(ctx context.Context, plan Plan) error {
	nfqws2ActiveAdapterMu.Lock()
	active := a.activeExecution != nil || a.activeProcess != nil
	nfqws2ActiveAdapterMu.Unlock()
	if active {
		return ErrNFQWSScopedOwner
	}
	unlock, err := a.lockResources()
	if err != nil {
		return err
	}
	defer unlock()
	lease, err := a.readLease()
	if err != nil {
		return err
	}
	if lease != nil && lease.FirstStart != nil {
		return a.reconcileFirstStart(ctx, plan, lease)
	}
	restored, err := a.restoreDeactivatedBlocks(plan)
	if err != nil {
		return err
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return err
	}
	output, err := a.run(ctx, a.InitPath, "status")
	if restored || err != nil || !runningOutput(string(output)) {
		if output, err = a.run(ctx, a.InitPath, "restart"); err != nil {
			return fmt.Errorf("restart committed NFQWS2: %s", shortOutput(output, err))
		}
	}
	return a.Health(ctx, plan, "")
}

// leaseBlockRestoration renders a list without its managed block back with
// the block of these values, if that block hashes exactly to the lease's.
func leaseBlockRestoration(data []byte, values []string, owner, hash string) ([]byte, bool) {
	merged, err := replaceManagedBlock(string(data), append([]string{"# RAZVILKA INSTANCE " + owner}, values...))
	if err != nil {
		return nil, false
	}
	rendered, err := nfqws2Block([]byte(merged))
	if err != nil || nfqws2Hash(rendered) != hash {
		return nil, false
	}
	return []byte(merged), true
}

// restoreDeactivatedBlocks puts back the managed blocks that a controlled
// deactivation removed. The installer quiesces the dataplane before replacing
// the binary and then restores the committed journal and the ownership lease,
// but not the shared lists: boot recovery used to find no block and enter
// Recovery Safe Mode. A block is written back only if the configuration and
// init still match the lease and the block rendered from the committed plan
// hashes exactly to the block the lease recorded; anything else still fails.
func (a *NFQWS2Adapter) restoreDeactivatedBlocks(plan Plan) (bool, error) {
	lease, err := a.readLease()
	if err != nil || lease == nil {
		return false, err
	}
	owner, err := a.owner()
	if err != nil {
		return false, err
	}
	lists := nfqws2PlanLists(plan, a.ID())
	type write struct {
		path string
		data []byte
		mode os.FileMode
	}
	var writes []write
	config, configExists, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return false, err
	}
	configHash := nfqws2Hash(config)
	if configExists && lease.ConfigOwner != "" && configHash == lease.ConfigOwner {
		// An interrupted cleanup removed the block this lease records.
		rendered, err := a.exclusionConfig(config, plan)
		if lease.FirstStart != nil {
			rendered, err = a.firstStartConfig(plan, config)
		}
		if err != nil || nfqws2Hash(rendered) != lease.ConfigHash {
			return false, errors.New("the NFQWS2 configuration block of the committed plan cannot be proven; review is required")
		}
		mode := os.FileMode(0o644)
		if info, statErr := os.Stat(a.ConfigPath); statErr == nil {
			mode = info.Mode().Perm()
		}
		writes = append(writes, write{a.ConfigPath, rendered, mode})
		configHash = lease.ConfigHash
	}
	for index, values := range lists {
		path := a.ownedListPaths()[index]
		data, exists, err := nfqws2Read(path)
		if err != nil {
			return false, err
		}
		block, err := nfqws2Block(data)
		if err != nil || len(block) > 0 || !exists {
			continue // present or unreadable: the ownership check decides
		}
		merged, ok := leaseBlockRestoration(data, values, owner, lease.Lists[index].BlockHash)
		if !ok {
			return false, errors.New("the NFQWS2 managed block of the committed plan cannot be proven; review is required")
		}
		mode := os.FileMode(0o644)
		if info, statErr := os.Stat(path); statErr == nil {
			mode = info.Mode().Perm()
		}
		writes = append(writes, write{path, []byte(merged), mode})
	}
	if len(writes) == 0 {
		return false, nil
	}
	init, _, err := nfqws2Read(a.InitPath)
	if err != nil || configHash != lease.ConfigHash || nfqws2Hash(init) != lease.InitHash {
		return false, errors.New("NFQWS2 runtime changed outside its ownership manifest")
	}
	for _, w := range writes {
		if err := writeAtomic(w.path, w.data, w.mode); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (a *NFQWS2Adapter) Deactivate(ctx context.Context) error {
	nfqws2ActiveAdapterMu.Lock()
	e, active := a.activeExecution, a.activeProcess != nil
	nfqws2ActiveAdapterMu.Unlock()
	if e != nil {
		if e.self != e || e.material == nil || e.material.adapter != a {
			return ErrNFQWSScopedOwner
		}
		return e.rollback(ctx)
	}
	if active {
		return ErrNFQWSScopedOwner
	}
	lease, err := a.readLease()
	if err != nil || lease == nil {
		return err // A generic marker or an interface name grants no ownership.
	}
	unlock, err := a.lockResources()
	if err != nil {
		return err
	}
	defer unlock()
	lease, err = a.readLease()
	if err != nil || lease == nil {
		return err
	}
	if err := a.verifyOwnedRuntime(lease, true); err != nil {
		return err
	}
	if lease.FirstStart != nil {
		if isNFQWS2Removal(ctx) {
			return a.retireFirstStart(ctx, lease)
		}
		return a.deactivateFirstStart(ctx, lease)
	}
	type removal struct {
		path string
		data []byte
		mode os.FileMode
	}
	removals := []removal{}
	// Validate every shared resource before the first write. Keep the lease
	// until reload succeeds so interrupted cleanup can safely be retried.
	config, configExists, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return err
	}
	if block, blockErr := nfqws2Block(config); blockErr != nil {
		return blockErr
	} else if configExists && len(block) != 0 {
		owner, err := a.owner()
		if err != nil || !strings.Contains(string(block), "\n# RAZVILKA INSTANCE "+owner+"\n") {
			return errors.New("NFQWS2 configuration block is not owned by this instance")
		}
		cleaned, _, err := removeManagedBlock(string(config))
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if info, statErr := os.Stat(a.ConfigPath); statErr == nil {
			mode = info.Mode().Perm()
		}
		removals = append(removals, removal{a.ConfigPath, []byte(cleaned), mode})
	}
	for index, path := range a.ownedListPaths() {
		data, exists, err := nfqws2Read(path)
		if err != nil {
			return err
		}
		if err := a.checkListOwnership(lease, index, data, true); err != nil {
			return err
		}
		if !exists {
			continue
		}
		cleaned, found, err := removeManagedBlock(string(data))
		if err != nil {
			return fmt.Errorf("remove RAZVILKA block from %s: %w", path, err)
		}
		if !found {
			continue
		}
		mode := os.FileMode(0o600)
		if info, statErr := os.Stat(path); statErr == nil {
			mode = info.Mode().Perm()
		}
		removals = append(removals, removal{path, []byte(cleaned), mode})
	}
	if !regularFile(a.InitPath) {
		return errors.New("NFQWS2 owned cleanup requires its init script for reload")
	}
	for _, removal := range removals {
		if err := writeAtomic(removal.path, removal.data, removal.mode); err != nil {
			return err
		}
	}
	if output, err := a.run(ctx, a.InitPath, "restart"); err != nil {
		return fmt.Errorf("reload NFQWS2 after managed-list cleanup: %s", shortOutput(output, err))
	}
	return a.writeLease(nil)
}

func (a *NFQWS2Adapter) Rollback(ctx context.Context, plan Plan, root string) error {
	if e, present, err := nfqws2ActiveExecutionFor(ctx, a, plan, root); present {
		if err != nil {
			return err
		}
		return e.rollback(ctx)
	}
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return err
	}
	lease, err := a.readLease()
	transaction, pathErr := filepath.Abs(root)
	if err != nil || pathErr != nil || lease == nil {
		return errors.Join(err, pathErr)
	}
	if lease.Transaction != transaction {
		if nfqws2FirstStartRollbackResumeMatches(lease, snapshot) {
			return a.resumeFirstStartRollback(ctx, root, snapshot, lease)
		}
		if nfqws2RollbackLeaseEqual(lease, snapshot.Lease) {
			// Already rolled back: a retry after a rollback that could not put
			// back the block its lease records (0.19.2).
			return a.restoreRolledBackBlocks(ctx, plan, snapshot)
		}
		return nil
	}
	unlock, err := a.lockResources()
	if err != nil {
		return err
	}
	defer unlock()
	owned, err := a.mayRollback(root, snapshot)
	if err != nil || !owned {
		return err
	}
	if snapshot.FirstStart {
		return a.rollbackFirstStart(ctx, root, snapshot, lease)
	}
	if err := restoreOptional(a.ConfigPath, snapshot.Config, snapshot.ConfigExisted); err != nil {
		return err
	}
	for index, path := range a.ownedListPaths() {
		data, existed := snapshot.ownedList(index)
		if err := restoreOptionalMode(path, data, existed, 0o644); err != nil {
			return err
		}
	}
	action := "stop"
	if snapshot.WasRunning {
		action = "restart"
	}
	output, err := a.run(ctx, a.InitPath, action)
	// Entware's S51nfqws2 returns 1 for an already stopped service. That is the
	// desired rollback state when the snapshot was not running, so keep rollback
	// idempotent instead of surfacing a second, misleading failure.
	if err != nil && !(action == "stop" && !runningOutput(string(output)) && strings.Contains(strings.ToLower(string(output)), "not running")) {
		return fmt.Errorf("restore NFQWS2 process state: %w", err)
	}
	if snapshot.ConfigDraft && a.Configs != nil {
		if _, err := a.Configs.Stage(a.ID(), "main", string(snapshot.StagedConfig)); err != nil {
			return fmt.Errorf("restore NFQWS2 config draft: %w", err)
		}
	}
	// Commit settles the list drafts; a later rollback gives them back.
	for index, used := range snapshot.ListDraft {
		if used && a.Configs != nil {
			if _, err := a.Configs.Stage(a.ID(), nfqws2ListFileIDs[index], string(snapshot.StagedLists[index])); err != nil {
				return fmt.Errorf("restore NFQWS2 list draft: %w", err)
			}
		}
	}
	if err := a.writeLease(snapshot.Lease); err != nil {
		return err
	}
	// A transaction started after the installer removed the blocks and before
	// boot recovery put them back snapshots lists without the block its lease
	// records. Restoring that literally leaves the runtime incomplete and the
	// rollback unverifiable; put back exactly the block the lease proves.
	return a.restartWithRestoredBlocks(ctx, plan, snapshot)
}

// restartWithRestoredBlocks puts back the block the restored lease proves
// for the plan, if the lists lack it, and restarts a running service. An
// unproven block is left to rollback verification, which reports it.
func (a *NFQWS2Adapter) restartWithRestoredBlocks(ctx context.Context, plan Plan, snapshot nfqws2Snapshot) error {
	if restored, err := a.restoreDeactivatedBlocks(plan); err == nil && restored && snapshot.WasRunning {
		if output, err := a.run(ctx, a.InitPath, "restart"); err != nil {
			return fmt.Errorf("restart NFQWS2 with restored lists: %s", shortOutput(output, err))
		}
	}
	return nil
}

func (a *NFQWS2Adapter) restoreRolledBackBlocks(ctx context.Context, plan Plan, snapshot nfqws2Snapshot) error {
	unlock, err := a.lockResources()
	if err != nil {
		return err
	}
	defer unlock()
	if lease, err := a.readLease(); err != nil || !nfqws2RollbackLeaseEqual(lease, snapshot.Lease) {
		return err
	}
	return a.restartWithRestoredBlocks(ctx, plan, snapshot)
}

func readNFQWS2Snapshot(root string) (nfqws2Snapshot, error) {
	data, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
	if err != nil {
		return nfqws2Snapshot{}, fmt.Errorf("read NFQWS2 snapshot: %w", err)
	}
	var snapshot nfqws2Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nfqws2Snapshot{}, fmt.Errorf("decode NFQWS2 snapshot: %w", err)
	}
	return snapshot, nil
}

func (a *NFQWS2Adapter) run(parent context.Context, name string, args ...string) ([]byte, error) {
	if name == a.InitPath && len(args) == 1 {
		lease, err := a.readLease()
		if err != nil {
			return nil, err
		}
		if lease != nil && lease.FirstStart != nil {
			switch args[0] {
			case "status":
				args = []string{"owned_status"}
			case "start":
				args = []string{"owned_start"}
			case "stop":
				args = []string{"owned_stop"}
			case "restart":
				return nil, errors.New("owned NFQWS2 requires controlled stop/start receipts")
			}
		}
		if err := a.firstStartScriptSafe(args[0]); err != nil {
			return nil, err
		}
	}
	if a.Runner == nil {
		return nil, errors.New("NFQWS2 command runner is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, a.timeout())
	defer cancel()
	output, err := a.Runner.Run(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("command timed out after %s", a.timeout())
	}
	return output, err
}

func (a *NFQWS2Adapter) timeout() time.Duration {
	if a.Timeout <= 0 {
		return 20 * time.Second
	}
	return a.Timeout
}

func optionalFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(data) > 8<<20 {
		return nil, false, errors.New("managed list exceeds 8 MiB")
	}
	return data, true, nil
}

func stageManagedFile(livePath, stagePath string, values []string) error {
	current, _, err := optionalFile(livePath)
	if err != nil {
		return err
	}
	merged, err := replaceManagedBlock(string(current), values)
	if err != nil {
		return err
	}
	return writeAtomic(stagePath, []byte(merged), 0o600)
}

func replaceManagedBlock(current string, values []string) (string, error) {
	start := strings.Index(current, managedBegin)
	end := strings.Index(current, managedEnd)
	if (start >= 0) != (end >= 0) || (start >= 0 && end < start) || strings.Count(current, managedBegin) > 1 || strings.Count(current, managedEnd) > 1 {
		return "", errors.New("existing RAZVILKA managed block is malformed")
	}
	if start >= 0 {
		end += len(managedEnd)
		for end < len(current) && (current[end] == '\r' || current[end] == '\n') {
			end++
		}
		current = current[:start] + current[end:]
	}
	current = strings.TrimRight(current, "\r\n")
	block := managedBegin + "\n"
	if len(values) > 0 {
		block += strings.Join(values, "\n") + "\n"
	}
	block += managedEnd + "\n"
	if current == "" {
		return block, nil
	}
	return current + "\n" + block, nil
}

func removeManagedBlock(current string) (string, bool, error) {
	start := strings.Index(current, managedBegin)
	end := strings.Index(current, managedEnd)
	if (start >= 0) != (end >= 0) || (start >= 0 && end < start) || strings.Count(current, managedBegin) > 1 || strings.Count(current, managedEnd) > 1 {
		return "", false, errors.New("existing RAZVILKA managed block is malformed")
	}
	if start < 0 {
		return current, false, nil
	}
	end += len(managedEnd)
	for end < len(current) && (current[end] == '\r' || current[end] == '\n') {
		end++
	}
	cleaned := strings.TrimRight(current[:start]+current[end:], "\r\n")
	if cleaned != "" {
		cleaned += "\n"
	}
	return cleaned, true, nil
}

func validManagedDomain(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@ \\") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

func installStaged(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(destination); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return writeAtomic(destination, data, mode)
}

func installStagedMode(source, destination string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return writeAtomic(destination, data, mode)
}

func restoreOptional(path string, data []byte, existed bool) error {
	return restoreOptionalMode(path, data, existed, 0o600)
}

func restoreOptionalMode(path string, data []byte, existed bool, mode os.FileMode) error {
	if !existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomic(path, data, mode)
}

func runningOutput(output string) bool {
	value := strings.ToLower(strings.TrimSpace(output))
	for _, negative := range []string{"not running", "not started", "stopped", "inactive", "dead", "failed"} {
		if strings.Contains(value, negative) {
			return false
		}
	}
	for _, positive := range []string{"running", "started", "active"} {
		if strings.Contains(value, positive) {
			return true
		}
	}
	return false
}

func findExecutable(candidates ...string) string {
	for _, candidate := range candidates {
		if strings.Contains(candidate, "/") {
			if regularFile(candidate) {
				return candidate
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

func shortOutput(output []byte, err error) string {
	value := strings.TrimSpace(string(output))
	if len(value) > 500 {
		value = value[:500]
	}
	if err != nil {
		if value != "" {
			value += "; "
		}
		value += err.Error()
	}
	return value
}

func defaultNFQWS2Probe(ctx context.Context, rawURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "RAZVILKA-NFQWS2-Health/1")
	request.Header.Set("Range", "bytes=0-2047")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) > 4 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	response, err := serviceProbeClient(client, rawURL).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = strictServiceResponse(rawURL, response)
	return err
}

// Some router resolvers allow only one second and one DNS attempt. A single
// transient lookup failure after activation should get one retry within the
// original health budget. No retry for HTTP, TLS, ownership or NXDOMAIN errors.
func probeNFQWS2Health(ctx context.Context, rawURL string, probe func(context.Context, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := probe(ctx, rawURL)
	var dnsErr *net.DNSError
	if err == nil || !errors.As(err, &dnsErr) || dnsErr.IsNotFound || (!dnsErr.IsTimeout && !dnsErr.IsTemporary) {
		return err
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return probe(ctx, rawURL)
}

func sortedCopy(values []string) []string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	return values
}
