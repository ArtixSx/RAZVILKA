package devices

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxDevices = 512

var (
	deviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,95}$`)
	macPattern      = regexp.MustCompile(`(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type Device struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	Group      string   `json:"group,omitempty"`
	Hostname   string   `json:"hostname,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	IPs        []string `json:"ips"`
	Interface  string   `json:"interface,omitempty"`
	State      string   `json:"state"`
	Discovered bool     `json:"discovered"`
	LastSeenAt string   `json:"last_seen_at,omitempty"`
}

type document struct {
	Schema  int               `json:"schema"`
	Devices map[string]Device `json:"devices"`
}

type Manager struct {
	Path       string
	Runner     Runner
	IPCommand  string
	ARPPaths   []string
	LeasePaths []string

	mu      sync.Mutex
	devices map[string]Device
}

func Load(path string) (*Manager, error) {
	m := &Manager{
		Path: path, Runner: execRunner{}, devices: map[string]Device{},
		ARPPaths:   []string{"/proc/net/arp"},
		LeasePaths: []string{"/opt/var/lib/misc/dnsmasq.leases", "/var/lib/misc/dnsmasq.leases", "/tmp/dhcp.leases", "/tmp/ndm/dhcp.leases"},
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := m.saveLocked(); err != nil {
			return nil, err
		}
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var stored document
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("decode device registry: %w", err)
	}
	if stored.Schema != 1 || len(stored.Devices) > maxDevices {
		return nil, errors.New("unsupported or oversized device registry")
	}
	for id, device := range stored.Devices {
		if !deviceIDPattern.MatchString(id) {
			return nil, fmt.Errorf("invalid stored device id %q", id)
		}
		device.ID = id
		device.IPs = normalizeIPs(device.IPs)
		device.Discovered = false
		device.State = "offline"
		m.devices[id] = device
	}
	return m, nil
}

func (m *Manager) List(ctx context.Context) []Device {
	discovered := m.discover(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := false
	for id, stored := range m.devices {
		stored.Discovered = false
		stored.State = "offline"
		m.devices[id] = stored
	}
	for id, live := range discovered {
		stored := m.devices[id]
		live.Name, live.Group = stored.Name, stored.Group
		if live.Hostname == "" {
			live.Hostname = stored.Hostname
		}
		if live.Interface == "" {
			live.Interface = stored.Interface
		}
		live.IPs = normalizeIPs(append(stored.IPs, live.IPs...))
		if !samePersistentDevice(stored, live) {
			changed = true
		}
		m.devices[id] = live
	}
	if changed {
		_ = m.saveLocked()
	}
	out := make([]Device, 0, len(m.devices))
	for _, device := range m.devices {
		device.IPs = append([]string(nil), device.IPs...)
		out = append(out, device)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Discovered != out[j].Discovered {
			return out[i].Discovered
		}
		left, right := displayName(out[i]), displayName(out[j])
		if left == right {
			return out[i].ID < out[j].ID
		}
		return left < right
	})
	return out
}

func (m *Manager) Update(id, name, group string) (Device, error) {
	id, name, group = strings.TrimSpace(strings.ToLower(id)), strings.TrimSpace(name), strings.TrimSpace(group)
	if !deviceIDPattern.MatchString(id) {
		return Device{}, errors.New("invalid device id")
	}
	if len(name) > 80 || strings.ContainsAny(name, "\r\n\x00") {
		return Device{}, errors.New("device name is invalid")
	}
	if len(group) > 64 || strings.ContainsAny(group, "\r\n\x00") {
		return Device{}, errors.New("device group is invalid")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	device, ok := m.devices[id]
	if !ok {
		return Device{}, errors.New("unknown device; refresh discovery first")
	}
	previous := device
	device.Name, device.Group = name, group
	m.devices[id] = device
	if err := m.saveLocked(); err != nil {
		m.devices[id] = previous
		return Device{}, err
	}
	device.IPs = append([]string(nil), device.IPs...)
	return device, nil
}

// Known returns the persisted discovery cache without touching the network.
// It is intended for high-frequency local consumers such as conntrack labels.
func (m *Manager) Known() []Device {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Device, 0, len(m.devices))
	for _, device := range m.devices {
		device.IPs = append([]string(nil), device.IPs...)
		out = append(out, device)
	}
	return out
}

func (m *Manager) MergeMetadata(input []Device) error {
	if len(input) > maxDevices {
		return errors.New("device registry limit exceeded")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := cloneDevices(m.devices)
	for _, incoming := range input {
		device, err := sanitizeStoredDevice(incoming)
		if err != nil {
			m.devices = previous
			return err
		}
		current := m.devices[device.ID]
		if device.Name != "" {
			current.Name = device.Name
		}
		if device.Group != "" {
			current.Group = device.Group
		}
		if device.Hostname != "" {
			current.Hostname = device.Hostname
		}
		if device.MAC != "" {
			current.MAC = device.MAC
		}
		if device.Interface != "" {
			current.Interface = device.Interface
		}
		current.ID = device.ID
		current.IPs = normalizeIPs(append(current.IPs, device.IPs...))
		current.Discovered, current.State, current.LastSeenAt = false, "offline", ""
		m.devices[device.ID] = current
	}
	if len(m.devices) > maxDevices {
		m.devices = previous
		return errors.New("device registry limit exceeded")
	}
	if err := m.saveLocked(); err != nil {
		m.devices = previous
		return err
	}
	return nil
}

// ReplaceAll restores an exact trusted snapshot and is used only for local
// transaction rollback after a later import phase fails.
func (m *Manager) ReplaceAll(input []Device) error {
	if len(input) > maxDevices {
		return errors.New("device registry limit exceeded")
	}
	replacement := map[string]Device{}
	for _, incoming := range input {
		device, err := sanitizeStoredDevice(incoming)
		if err != nil {
			return err
		}
		if _, exists := replacement[device.ID]; exists {
			return fmt.Errorf("duplicate device %q", device.ID)
		}
		replacement[device.ID] = device
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.devices
	m.devices = replacement
	if err := m.saveLocked(); err != nil {
		m.devices = previous
		return err
	}
	return nil
}

func sanitizeStoredDevice(device Device) (Device, error) {
	device.ID = strings.ToLower(strings.TrimSpace(device.ID))
	device.Name, device.Group = strings.TrimSpace(device.Name), strings.TrimSpace(device.Group)
	if !deviceIDPattern.MatchString(device.ID) {
		return Device{}, fmt.Errorf("invalid device id %q", device.ID)
	}
	if len(device.Name) > 80 || len(device.Group) > 64 || strings.ContainsAny(device.Name+device.Group, "\r\n\x00") {
		return Device{}, fmt.Errorf("invalid metadata for device %q", device.ID)
	}
	device.MAC = normalizeMAC(device.MAC)
	device.IPs = normalizeIPs(device.IPs)
	if len(device.Hostname) > 253 || strings.ContainsAny(device.Hostname, "\r\n\x00") || len(device.Interface) > 32 || strings.ContainsAny(device.Interface, " /\\\r\n\x00") {
		return Device{}, fmt.Errorf("invalid discovered metadata for device %q", device.ID)
	}
	device.Discovered, device.State, device.LastSeenAt = false, "offline", ""
	return device, nil
}

func cloneDevices(input map[string]Device) map[string]Device {
	out := make(map[string]Device, len(input))
	for id, device := range input {
		device.IPs = append([]string(nil), device.IPs...)
		out[id] = device
	}
	return out
}

func (m *Manager) discover(parent context.Context) map[string]Device {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	leases := m.readLeases()
	rows := map[string]Device{}
	ipCommand := m.IPCommand
	if ipCommand == "" {
		ipCommand = findIPCommand()
	}
	if m.Runner != nil && ipCommand != "" {
		if output, err := m.Runner.Run(ctx, ipCommand, "neigh", "show"); err == nil {
			parseNeighbors(string(output), leases, rows)
		}
	}
	for _, path := range m.ARPPaths {
		if data, err := os.ReadFile(path); err == nil {
			parseARP(string(data), leases, rows)
		}
	}
	return rows
}

type lease struct {
	MAC      string
	Hostname string
}

func (m *Manager) readLeases() map[string]lease {
	result := map[string]lease{}
	for _, path := range m.LeasePaths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 2<<20 {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			address, err := netip.ParseAddr(fields[2])
			if err != nil || !address.IsValid() {
				continue
			}
			mac := normalizeMAC(fields[1])
			hostname := fields[3]
			if hostname == "*" || len(hostname) > 253 || strings.ContainsAny(hostname, "\r\n\x00") {
				hostname = ""
			}
			result[address.Unmap().String()] = lease{MAC: mac, Hostname: hostname}
		}
	}
	return result
}

func parseNeighbors(output string, leases map[string]lease, rows map[string]Device) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil || address.IsLoopback() || address.IsMulticast() || address.IsUnspecified() {
			continue
		}
		address = address.Unmap()
		interfaceName, mac, state := "", "", strings.ToLower(fields[len(fields)-1])
		for index := 1; index+1 < len(fields); index++ {
			switch fields[index] {
			case "dev":
				interfaceName = fields[index+1]
			case "lladdr":
				mac = normalizeMAC(fields[index+1])
			}
		}
		if state == "failed" || state == "incomplete" {
			continue
		}
		addDiscovery(rows, address.String(), mac, interfaceName, state, leases)
	}
}

func parseARP(output string, leases map[string]lease, rows map[string]Device) {
	for index, line := range strings.Split(output, "\n") {
		if index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		address, err := netip.ParseAddr(fields[0])
		mac := normalizeMAC(fields[3])
		if err != nil || mac == "" {
			continue
		}
		addDiscovery(rows, address.Unmap().String(), mac, fields[5], "reachable", leases)
	}
}

func addDiscovery(rows map[string]Device, ip, mac, interfaceName, state string, leases map[string]lease) {
	if leased := leases[ip]; mac == "" {
		mac = leased.MAC
	}
	id := deviceID(mac, ip)
	row := rows[id]
	row.ID, row.MAC, row.Interface = id, mac, interfaceName
	row.IPs = normalizeIPs(append(row.IPs, ip))
	row.Discovered, row.State = true, state
	row.LastSeenAt = time.Now().UTC().Format(time.RFC3339)
	if row.Hostname == "" {
		row.Hostname = leases[ip].Hostname
	}
	rows[id] = row
}

func deviceID(mac, ip string) string {
	if mac != "" {
		return "mac-" + strings.ReplaceAll(mac, ":", "-")
	}
	digest := sha256.Sum256([]byte(ip))
	return "ip-" + hex.EncodeToString(digest[:8])
}

func normalizeMAC(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if !macPattern.MatchString(value) || value == "00:00:00:00:00:00" {
		return ""
	}
	return value
}

func normalizeIPs(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || address.IsLoopback() || address.IsMulticast() || address.IsUnspecified() {
			continue
		}
		value = address.Unmap().String()
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := netip.ParseAddr(out[i])
		right, _ := netip.ParseAddr(out[j])
		if left.BitLen() != right.BitLen() {
			return left.BitLen() < right.BitLen()
		}
		return left.Less(right)
	})
	return out
}

func displayName(device Device) string {
	if device.Name != "" {
		return strings.ToLower(device.Name)
	}
	if device.Hostname != "" {
		return strings.ToLower(device.Hostname)
	}
	if len(device.IPs) > 0 {
		return device.IPs[0]
	}
	return device.ID
}

func samePersistentDevice(left, right Device) bool {
	return left.ID == right.ID && left.Name == right.Name && left.Group == right.Group &&
		left.Hostname == right.Hostname && left.MAC == right.MAC && left.Interface == right.Interface &&
		strings.Join(normalizeIPs(left.IPs), "\x00") == strings.Join(normalizeIPs(right.IPs), "\x00")
}

func (m *Manager) saveLocked() error {
	if strings.TrimSpace(m.Path) == "" {
		return errors.New("device registry path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(m.Path), 0o700); err != nil {
		return err
	}
	stored := make(map[string]Device, len(m.devices))
	for id, device := range m.devices {
		device.Discovered = false
		device.State = "offline"
		device.LastSeenAt = ""
		stored[id] = device
	}
	data, err := json.MarshalIndent(document{Schema: 1, Devices: stored}, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(m.Path), ".devices.tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, m.Path)
}

func findIPCommand() string {
	for _, candidate := range []string{"/opt/sbin/ip", "/opt/bin/ip", "/sbin/ip", "ip"} {
		if strings.Contains(candidate, "/") {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate
			}
			continue
		}
		if found, err := exec.LookPath(candidate); err == nil {
			return found
		}
	}
	return ""
}
