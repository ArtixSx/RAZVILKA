package conntrack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/telemetry"
)

const maxConnections = 512

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type Collector struct {
	Store          *telemetry.Store
	Config         *config.Store
	Catalog        func() catalog.Catalog
	Devices        *devices.Manager
	LatestPlan     func() (dataplane.Plan, bool, error)
	WANInterface   func() string
	Runner         Runner
	IPCommand      string
	ConntrackPaths []string
	Interval       time.Duration
	ResolveTimeout time.Duration
	Resolver       func(context.Context, string) ([]netip.Addr, error)

	mu          sync.Mutex
	index       map[netip.Addr][]serviceMatch
	indexRev    uint64
	indexAt     time.Time
	indexErr    error
	indexRoutes map[string]string
}

type serviceMatch struct {
	ID          string
	Name        string
	Specificity int
}

type flow struct {
	Protocol        string
	Source          netip.Addr
	Destination     netip.Addr
	SourcePort      string
	DestinationPort string
	Upload          uint64
	Download        uint64
}

func New(store *telemetry.Store, configuration *config.Store, catalogProvider func() catalog.Catalog) *Collector {
	return &Collector{
		Store: store, Config: configuration, Catalog: catalogProvider, Runner: execRunner{},
		ConntrackPaths: []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"}, Interval: 8 * time.Second,
		ResolveTimeout: 8 * time.Second,
		Resolver: func(ctx context.Context, domain string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
		},
	}
}

func (c *Collector) Start(ctx context.Context) {
	if c == nil || c.Store == nil {
		return
	}
	go func() {
		c.collectAndReport(ctx)
		interval := c.Interval
		if interval < 2*time.Second {
			interval = 8 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				c.Store.SetProducer(false, "kernel-conntrack", "telemetry collector stopped")
				return
			case <-ticker.C:
				c.collectAndReport(ctx)
			}
		}
	}()
}

func (c *Collector) collectAndReport(parent context.Context) {
	// The first pass may also refresh DNS indexes. Leave enough time for route
	// verification instead of publishing an incomplete snapshot on slower routers.
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	connections, err := c.Collect(ctx)
	if err != nil {
		c.Store.ReplaceActive("kernel-conntrack", nil)
		c.Store.SetProducer(false, "kernel-conntrack", err.Error())
		return
	}
	c.Store.ReplaceActive("kernel-conntrack", connections)
	c.Store.SetProducer(true, "kernel-conntrack", "conntrack readable; only routes confirmed by the kernel are shown")
}

func (c *Collector) Collect(ctx context.Context) ([]telemetry.Connection, error) {
	if c == nil || c.Store == nil || c.Config == nil || c.Catalog == nil {
		return nil, errors.New("conntrack collector is not configured")
	}
	data, source, err := c.readConntrack()
	if err != nil {
		return nil, err
	}
	configuration := c.Config.Get()
	if err := c.ensureIndex(ctx, configuration); err != nil {
		return nil, err
	}
	deviceNames := c.deviceNames()
	wanInterface := ""
	if c.WANInterface != nil {
		wanInterface = c.WANInterface()
	}
	flows := parseFlows(string(data))
	out := make([]telemetry.Connection, 0, len(flows))
	for _, item := range flows {
		match, route, ok := c.classify(configuration, item.Source, item.Destination)
		if !ok || route == "nfqws2" {
			// NFQUEUE counters can prove that a request crossed a queue, but the
			// global conntrack table cannot correlate that counter to one row.
			continue
		}
		device, evidence, ok := c.verifyRoute(ctx, item.Source, item.Destination, route, wanInterface)
		if !ok {
			continue
		}
		identity := strings.Join([]string{item.Protocol, item.Source.String(), item.SourcePort, item.Destination.String(), item.DestinationPort}, "|")
		digest := sha256.Sum256([]byte(identity))
		sourceName := deviceNames[item.Source.Unmap().String()]
		out = append(out, telemetry.Connection{
			ID: "ct-" + hex.EncodeToString(digest[:10]), ServiceID: match.ID, ServiceName: match.Name,
			DestinationIP: item.Destination.String(), DestinationPort: item.DestinationPort, Protocol: item.Protocol,
			SourceIP: item.Source.String(), SourceName: sourceName, Route: route, Chain: []string{match.Name, route},
			Upload: item.Upload, Download: item.Download, UpdatedAt: time.Now().UTC(),
			Evidence: source + " · " + evidence + " · dev " + device,
		})
		if len(out) >= maxConnections {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (c *Collector) readConntrack() ([]byte, string, error) {
	for _, path := range c.ConntrackPaths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > 32<<20 {
			return nil, "", errors.New("kernel conntrack table exceeds the 32 MiB safety limit")
		}
		data, err := os.ReadFile(path)
		if err == nil {
			return data, filepathLabel(path), nil
		}
	}
	return nil, "", errors.New("kernel conntrack table is unavailable; load nf_conntrack or use a compatible KeeneticOS build")
}

func (c *Collector) ensureIndex(parent context.Context, configuration config.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.index != nil && c.indexRev == configuration.AppliedRevision && time.Since(c.indexAt) < 15*time.Minute {
		return c.indexErr
	}
	ctx, cancel := context.WithTimeout(parent, c.resolveTimeout())
	defer cancel()
	index := map[netip.Addr][]serviceMatch{}
	cat := c.Catalog()
	for _, service := range cat.Services {
		state := configuration.AppliedServices[service.ID]
		if !state.Enabled {
			continue
		}
		for _, raw := range service.CIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				if address, addressErr := netip.ParseAddr(raw); addressErr == nil {
					prefix = netip.PrefixFrom(address.Unmap(), address.BitLen())
				} else {
					continue
				}
			}
			// CIDR membership is handled separately during classification; exact
			// host entries are placed directly in the fast index.
			if prefix.Bits() == prefix.Addr().BitLen() {
				address := prefix.Addr().Unmap()
				index[address] = append(index[address], serviceMatch{ID: service.ID, Name: service.Name, Specificity: prefix.Bits()})
			}
		}
		for _, domain := range service.Domains {
			addresses, err := c.Resolver(ctx, domain)
			if err != nil {
				continue
			}
			for _, address := range addresses {
				address = address.Unmap()
				if !publicAddress(address) {
					continue
				}
				index[address] = append(index[address], serviceMatch{ID: service.ID, Name: service.Name, Specificity: address.BitLen()})
			}
		}
	}
	routes := map[string]string{}
	if c.LatestPlan != nil {
		if plan, exists, err := c.LatestPlan(); err == nil && exists && plan.State == "committed" {
			for _, route := range plan.Routes {
				routes[route.ServiceID] = route.Resolved
			}
		}
	}
	c.index, c.indexRoutes, c.indexRev, c.indexAt, c.indexErr = index, routes, configuration.AppliedRevision, time.Now(), nil
	return nil
}

func (c *Collector) classify(configuration config.Config, source, destination netip.Addr) (serviceMatch, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	candidates := append([]serviceMatch(nil), c.index[destination.Unmap()]...)
	for _, service := range c.Catalog().Services {
		state := configuration.AppliedServices[service.ID]
		if !state.Enabled {
			continue
		}
		for _, raw := range service.CIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			if prefix.Contains(destination) {
				candidates = append(candidates, serviceMatch{ID: service.ID, Name: service.Name, Specificity: prefix.Bits()})
			}
		}
	}
	filtered := make([]serviceMatch, 0, len(candidates))
	seen := map[string]bool{}
	for _, candidate := range candidates {
		state := configuration.AppliedServices[candidate.ID]
		if !matchesSources(source, state.Sources) || seen[candidate.ID] {
			continue
		}
		seen[candidate.ID] = true
		filtered = append(filtered, candidate)
	}
	if len(filtered) == 0 {
		return serviceMatch{}, "", false
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Specificity == filtered[j].Specificity {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].Specificity > filtered[j].Specificity
	})
	if len(filtered) > 1 && filtered[0].Specificity == filtered[1].Specificity {
		return serviceMatch{}, "", false
	}
	winner := filtered[0]
	state := configuration.AppliedServices[winner.ID]
	route := state.Route
	if route == "" {
		route = state.Mode
	}
	if route == "" {
		route = "auto"
	}
	if route == "auto" {
		route = c.indexRoutes[winner.ID]
	}
	if route == "" || route == "auto" {
		return serviceMatch{}, "", false
	}
	return winner, route, true
}

func (c *Collector) verifyRoute(ctx context.Context, source, destination netip.Addr, route, wanInterface string) (string, string, bool) {
	ipCommand := c.IPCommand
	if ipCommand == "" {
		ipCommand = findIPCommand()
	}
	if ipCommand == "" || c.Runner == nil {
		return "", "", false
	}
	args := []string{"route", "get", destination.String(), "from", source.String()}
	if destination.Is6() {
		args = append([]string{"-6"}, args...)
	}
	output, err := c.Runner.Run(ctx, ipCommand, args...)
	if err != nil {
		return "", "", false
	}
	device := routeDevice(string(output))
	if device == "" {
		return "", "", false
	}
	expected := map[string]string{"usque": "rz-usque", "sing-box": "rz-sing", "xray": "rz-xray", "warp-wg": "rz-warp", "amneziawg": "rz-awg"}[route]
	if route == "direct" {
		if wanInterface == "" || device != wanInterface {
			return device, "", false
		}
		return device, "kernel route confirmed DIRECT WAN", true
	}
	if expected == "" || device != expected {
		return device, "", false
	}
	return device, "kernel policy route confirmed " + route, true
}

func (c *Collector) deviceNames() map[string]string {
	result := map[string]string{}
	if c.Devices == nil {
		return result
	}
	for _, device := range c.Devices.Known() {
		name := device.Name
		if name == "" {
			name = device.Hostname
		}
		for _, ip := range device.IPs {
			result[ip] = name
		}
	}
	return result
}

func parseFlows(text string) []flow {
	out := []flow{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		protocol := ""
		for _, field := range fields {
			if field == "tcp" || field == "udp" {
				protocol = field
				break
			}
		}
		if protocol == "" {
			continue
		}
		values := map[string][]string{}
		for _, field := range fields {
			key, value, ok := strings.Cut(field, "=")
			if ok {
				values[key] = append(values[key], value)
			}
		}
		if len(values["src"]) < 1 || len(values["dst"]) < 1 {
			continue
		}
		source, sourceErr := netip.ParseAddr(values["src"][0])
		destination, destinationErr := netip.ParseAddr(values["dst"][0])
		if sourceErr != nil || destinationErr != nil || !lanAddress(source.Unmap()) || !publicAddress(destination.Unmap()) {
			continue
		}
		item := flow{Protocol: protocol, Source: source.Unmap(), Destination: destination.Unmap()}
		if len(values["sport"]) > 0 {
			item.SourcePort = validPort(values["sport"][0])
		}
		if len(values["dport"]) > 0 {
			item.DestinationPort = validPort(values["dport"][0])
		}
		if len(values["bytes"]) > 0 {
			item.Upload, _ = strconv.ParseUint(values["bytes"][0], 10, 64)
		}
		if len(values["bytes"]) > 1 {
			item.Download, _ = strconv.ParseUint(values["bytes"][1], 10, 64)
		}
		out = append(out, item)
	}
	return out
}

func matchesSources(source netip.Addr, sources []string) bool {
	if len(sources) == 0 {
		return true
	}
	for _, raw := range sources {
		if address, err := netip.ParseAddr(raw); err == nil && address.Unmap() == source.Unmap() {
			return true
		}
		if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Contains(source) {
			return true
		}
	}
	return false
}

func routeDevice(output string) string {
	fields := strings.Fields(output)
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "dev" {
			return fields[index+1]
		}
	}
	return ""
}

func validPort(value string) string {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return ""
	}
	return strconv.Itoa(port)
}

func lanAddress(address netip.Addr) bool {
	return address.IsPrivate() || address.IsLinkLocalUnicast()
}

func publicAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
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

func filepathLabel(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		path = path[index+1:]
	}
	return path
}

func (c *Collector) resolveTimeout() time.Duration {
	if c.ResolveTimeout <= 0 {
		return 8 * time.Second
	}
	return c.ResolveTimeout
}
