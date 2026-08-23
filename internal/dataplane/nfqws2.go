package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

const (
	managedBegin = "# BEGIN RAZVILKA MANAGED"
	managedEnd   = "# END RAZVILKA MANAGED"
)

type NFQWS2Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type nfqws2ExecRunner struct{}

func (nfqws2ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type NFQWS2Adapter struct {
	ConfigPath    string
	UserListPath  string
	IPSetListPath string
	InitPath      string
	IPTablesSave  string
	Runner        NFQWS2Runner
	Configs       *engineconfig.Manager
	HealthProbe   func(context.Context, string) error
	Timeout       time.Duration
}

type nfqws2Snapshot struct {
	UserListExisted  bool   `json:"user_list_existed"`
	UserList         []byte `json:"user_list,omitempty"`
	IPSetListExisted bool   `json:"ipset_list_existed"`
	IPSetList        []byte `json:"ipset_list,omitempty"`
	WasRunning       bool   `json:"was_running"`
	ConfigExisted    bool   `json:"config_existed"`
	Config           []byte `json:"config,omitempty"`
	ConfigDraft      bool   `json:"config_draft"`
	StagedConfig     []byte `json:"staged_config,omitempty"`
}

func NewNFQWS2Adapter() *NFQWS2Adapter {
	return &NFQWS2Adapter{
		ConfigPath: "/opt/etc/nfqws2/nfqws2.conf", UserListPath: "/opt/etc/nfqws2/lists/user.list",
		IPSetListPath: "/opt/etc/nfqws2/lists/ipset.list", InitPath: "/opt/etc/init.d/S51nfqws2",
		Runner: nfqws2ExecRunner{}, Timeout: 20 * time.Second,
	}
}

func (*NFQWS2Adapter) ID() string { return "nfqws2" }

func (a *NFQWS2Adapter) Snapshot(ctx context.Context, _ Plan, root string) error {
	snapshot := nfqws2Snapshot{}
	var err error
	snapshot.Config, snapshot.ConfigExisted, err = optionalFile(a.ConfigPath)
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 config: %w", err)
	}
	if a.Configs != nil {
		content, readErr := a.Configs.ReadExpert(a.ID(), "main")
		if readErr != nil {
			return fmt.Errorf("read NFQWS2 config draft: %w", readErr)
		}
		if content.Source == "staged" {
			snapshot.ConfigDraft = true
			snapshot.StagedConfig = []byte(content.Content)
		}
	}
	snapshot.UserList, snapshot.UserListExisted, err = optionalFile(a.UserListPath)
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 user list: %w", err)
	}
	snapshot.IPSetList, snapshot.IPSetListExisted, err = optionalFile(a.IPSetListPath)
	if err != nil {
		return fmt.Errorf("snapshot NFQWS2 ipset list: %w", err)
	}
	if a.Runner != nil && regularFile(a.InitPath) {
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		output, statusErr := a.Runner.Run(probeCtx, a.InitPath, "status")
		cancel()
		snapshot.WasRunning = statusErr == nil && runningOutput(string(output))
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(root, "snapshot.json"), data, 0o600)
}

func (a *NFQWS2Adapter) Stage(_ context.Context, plan Plan, root string) error {
	config := []byte(nil)
	if a.Configs != nil {
		content, err := a.Configs.ReadExpert(a.ID(), "main")
		if err != nil {
			return err
		}
		if content.Content != "" {
			config = []byte(content.Content)
		}
	}
	if len(config) == 0 {
		var err error
		config, err = os.ReadFile(a.ConfigPath)
		if err != nil {
			return fmt.Errorf("stage NFQWS2 config: %w", err)
		}
	}
	if err := writeAtomic(filepath.Join(root, "nfqws2.conf.staged"), config, 0o600); err != nil {
		return err
	}
	domains := []string{}
	cidrs := []string{}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() {
			continue
		}
		domains = append(domains, route.Domains...)
		cidrs = append(cidrs, route.CIDRs...)
	}
	domains = sortedUnique(domains)
	cidrs = sortedUnique(cidrs)
	for _, domain := range domains {
		if !validManagedDomain(domain) {
			return fmt.Errorf("invalid NFQWS2 domain %q", domain)
		}
	}
	for _, cidr := range cidrs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			if _, addrErr := netip.ParseAddr(cidr); addrErr != nil {
				return fmt.Errorf("invalid NFQWS2 CIDR %q", cidr)
			}
		}
	}
	if err := stageManagedFile(a.UserListPath, filepath.Join(root, "user.list.staged"), domains); err != nil {
		return err
	}
	return stageManagedFile(a.IPSetListPath, filepath.Join(root, "ipset.list.staged"), cidrs)
}

func (a *NFQWS2Adapter) Validate(_ context.Context, _ Plan, root string) error {
	for _, path := range []string{a.InitPath, filepath.Join(root, "nfqws2.conf.staged"), filepath.Join(root, "user.list.staged"), filepath.Join(root, "ipset.list.staged")} {
		if !regularFile(path) {
			return fmt.Errorf("required NFQWS2 file is missing: %s", path)
		}
	}
	if a.Configs != nil {
		if validation := a.Configs.Validate(a.ID(), "main"); !validation.OK {
			return fmt.Errorf("NFQWS2 native config validation failed: %s", validation.Output)
		}
	}
	for _, path := range []string{filepath.Join(root, "user.list.staged"), filepath.Join(root, "ipset.list.staged")} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Count(string(data), managedBegin) != 1 || strings.Count(string(data), managedEnd) != 1 {
			return fmt.Errorf("invalid managed block in %s", path)
		}
	}
	return nil
}

func (a *NFQWS2Adapter) Activate(ctx context.Context, _ Plan, root string) error {
	if err := installStaged(filepath.Join(root, "nfqws2.conf.staged"), a.ConfigPath); err != nil {
		return fmt.Errorf("activate NFQWS2 config: %w", err)
	}
	if err := installStaged(filepath.Join(root, "user.list.staged"), a.UserListPath); err != nil {
		return fmt.Errorf("activate NFQWS2 user list: %w", err)
	}
	if err := installStaged(filepath.Join(root, "ipset.list.staged"), a.IPSetListPath); err != nil {
		return fmt.Errorf("activate NFQWS2 ipset list: %w", err)
	}
	_, err := a.run(ctx, a.InitPath, "restart")
	if err != nil {
		return fmt.Errorf("restart NFQWS2: %w", err)
	}
	return nil
}

func (a *NFQWS2Adapter) Commit(_ context.Context, _ Plan, root string) error {
	if a.Configs == nil {
		return nil
	}
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return err
	}
	if snapshot.ConfigDraft {
		return a.Configs.Discard(a.ID(), "main")
	}
	return nil
}

func (a *NFQWS2Adapter) Health(ctx context.Context, plan Plan, _ string) error {
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
		if adapterID(route.Resolved) != a.ID() || route.ProbeURL == "" {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, a.timeout())
		err := probe(probeCtx, route.ProbeURL)
		cancel()
		if err != nil {
			return fmt.Errorf("%s health probe: %w", route.ServiceName, err)
		}
	}
	return nil
}

func (a *NFQWS2Adapter) Reconcile(ctx context.Context, plan Plan) error {
	output, err := a.run(ctx, a.InitPath, "status")
	if err != nil || !runningOutput(string(output)) {
		if output, err = a.run(ctx, a.InitPath, "restart"); err != nil {
			return fmt.Errorf("restart committed NFQWS2: %s", shortOutput(output, err))
		}
	}
	return a.Health(ctx, plan, "")
}

func (a *NFQWS2Adapter) Deactivate(ctx context.Context) error {
	changed := false
	for _, path := range []string{a.UserListPath, a.IPSetListPath} {
		data, exists, err := optionalFile(path)
		if err != nil {
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
		if err := writeAtomic(path, []byte(cleaned), mode); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	if !regularFile(a.InitPath) {
		return errors.New("NFQWS2 managed lists were cleaned but init script is unavailable for reload")
	}
	if output, err := a.run(ctx, a.InitPath, "restart"); err != nil {
		return fmt.Errorf("reload NFQWS2 after managed-list cleanup: %s", shortOutput(output, err))
	}
	return nil
}

func (a *NFQWS2Adapter) Rollback(ctx context.Context, _ Plan, root string) error {
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return err
	}
	if err := restoreOptional(a.ConfigPath, snapshot.Config, snapshot.ConfigExisted); err != nil {
		return err
	}
	if err := restoreOptional(a.UserListPath, snapshot.UserList, snapshot.UserListExisted); err != nil {
		return err
	}
	if err := restoreOptional(a.IPSetListPath, snapshot.IPSetList, snapshot.IPSetListExisted); err != nil {
		return err
	}
	action := "stop"
	if snapshot.WasRunning {
		action = "restart"
	}
	if _, err := a.run(ctx, a.InitPath, action); err != nil {
		return fmt.Errorf("restore NFQWS2 process state: %w", err)
	}
	if snapshot.ConfigDraft && a.Configs != nil {
		if _, err := a.Configs.Stage(a.ID(), "main", string(snapshot.StagedConfig)); err != nil {
			return fmt.Errorf("restore NFQWS2 config draft: %w", err)
		}
	}
	return nil
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

func restoreOptional(path string, data []byte, existed bool) error {
	if !existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomic(path, data, 0o600)
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
	request.Header.Set("User-Agent", "RAZVILKA-NFQWS2-Health/0.6")
	request.Header.Set("Range", "bytes=0-2047")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) > 4 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
	if response.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}

func sortedCopy(values []string) []string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	return values
}
