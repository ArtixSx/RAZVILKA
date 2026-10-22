package engineconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var ErrNFQWSFirstStart = errors.New("closed NFQWS2 first-start requires unchanged reviewed stock configuration")

const NFQWSFirstStartFormat = "# RAZVILKA NFQWS2 TCP443 STARTER v1"
const NFQWSFirstStartInitFormat = "# RAZVILKA NFQWS2 TCP443 INIT v1"
const NFQWSFirstStartStockInitSHA256 = "3c3edefdab45e1f9f7db7a9c28dae2e3c18cf6b50547045d16c7de7cbad4dacc"

// These are the original 1.3.1 stock strategy/mode assignments. Only the
// transport/access-policy assignments below may differ; expert recipes are
// never silently adopted by first-start. The original document is retained.
const nfqwsFirstStartStockFieldsSHA256 = "6b0a713076923a77259f26506b3e0d65dcc932cac5f6eb55188cabeb831eab5a"

var nfqwsFirstStartStockFields = []string{"NFQWS_BASE_ARGS", "NFQWS_ARGS", "NFQWS_ARGS_QUIC", "NFQWS_ARGS_UDP", "MODE_LIST", "MODE_ALL", "MODE_AUTO", "NFQWS_EXTRA_ARGS", "NFQWS_ARGS_IPSET", "NFQWS_ARGS_CUSTOM", "TCP_PORTS", "UDP_PORTS", "LOG_LEVEL", "LOG_DEBUG_PATH", "USER", "CONFIG_VERSION"}
var nfqwsFirstStartOwner = regexp.MustCompile(`^[0-9a-f]{24}$`)
var nfqwsFirstStartInterface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`)

func nfqwsFirstStartDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func NFQWSFirstStartStockConfig(raw []byte) error {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return ErrNFQWSFirstStart
	}
	fields, err := parseShellAssignments(string(raw))
	if err != nil || len(fields) != len(nfqwsFirstStartStockFields)+5 {
		return ErrNFQWSFirstStart
	}
	for _, key := range append(slices.Clone(nfqwsFirstStartStockFields), "ISP_INTERFACE", "IPV6_ENABLED", "POLICY_NAME", "POLICY_EXCLUDE", "NFQUEUE_NUM") {
		if _, ok := fields[key]; !ok {
			return ErrNFQWSFirstStart
		}
	}
	var static strings.Builder
	for _, key := range nfqwsFirstStartStockFields {
		value, ok := fields[key]
		if !ok {
			return ErrNFQWSFirstStart
		}
		static.WriteString(key + "\x00" + value + "\x00")
	}
	if nfqwsFirstStartDigest([]byte(static.String())) != nfqwsFirstStartStockFieldsSHA256 {
		return ErrNFQWSFirstStart
	}
	for _, name := range strings.Fields(fields["ISP_INTERFACE"]) {
		if !nfqwsFirstStartInterface.MatchString(name) {
			return ErrNFQWSFirstStart
		}
	}
	if len(strings.Fields(fields["ISP_INTERFACE"])) == 0 || (fields["IPV6_ENABLED"] != "0" && fields["IPV6_ENABLED"] != "1") ||
		(fields["POLICY_EXCLUDE"] != "0" && fields["POLICY_EXCLUDE"] != "1") || !regexp.MustCompile(`^[a-zA-Z0-9_. -]*$`).MatchString(fields["POLICY_NAME"]) {
		return ErrNFQWSFirstStart
	}
	queue, err := strconv.Atoi(fields["NFQUEUE_NUM"])
	if err != nil || queue < 1 || queue > 65535 || strconv.Itoa(queue) != fields["NFQUEUE_NUM"] {
		return ErrNFQWSFirstStart
	}
	return nil
}

// NFQWSFirstStartConfig uses inline immutable lists from the actual plan.
// No mutable stock user/auto/ipset list widens this profile, and nobody needs
// access to a private transaction directory. Native validation owns the argv.
func NFQWSFirstStartConfig(original []byte, owner string, domains, excludedDomains, excludedCIDRs []string) ([]byte, error) {
	if !nfqwsFirstStartOwner.MatchString(owner) || NFQWSFirstStartStockConfig(original) != nil {
		return nil, ErrNFQWSFirstStart
	}
	names := func(values []string) ([]string, error) {
		out := slices.Clone(values)
		for _, name := range out {
			if len(name) == 0 || len(name) > 253 || strings.ContainsAny(name, " ,/\t\r\n$`'\"\\") || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-.") != "" || !strings.Contains(name, ".") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
				return nil, ErrNFQWSFirstStart
			}
		}
		slices.Sort(out)
		return slices.Compact(out), nil
	}
	include, err := names(domains)
	if err != nil || len(include) == 0 {
		return nil, ErrNFQWSFirstStart
	}
	exclude, err := names(excludedDomains)
	if err != nil {
		return nil, err
	}
	prefixes := make([]string, 0, len(excludedCIDRs))
	for _, raw := range excludedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() {
			return nil, ErrNFQWSFirstStart
		}
		prefixes = append(prefixes, prefix.String())
	}
	slices.Sort(prefixes)
	prefixes = slices.Compact(prefixes)
	args := "--hostlist-domains=" + strings.Join(include, ",")
	if len(exclude) != 0 {
		args += " --hostlist-exclude-domains=" + strings.Join(exclude, ",")
	}
	if len(prefixes) != 0 {
		args += " --ipset-exclude-ip=" + strings.Join(prefixes, ",")
	}
	// The concrete process identity reader caps /proc/cmdline at 32768.
	// Leave room for the fixed recipe, program, pidfile and NUL separators.
	if len(args) > 24<<10 {
		return nil, ErrNFQWSFirstStart
	}
	block := ManagedListBegin + "\n# RAZVILKA INSTANCE " + owner + "\n" + NFQWSFirstStartFormat + "\n" +
		"NFQWS_BASE_ARGS='--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua --lua-init=@/opt/etc/nfqws2/lua/zapret-antidpi.lua --fastpath-workaround=0 --ipcache-hostname=0'\n" +
		"NFQWS_ARGS='--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld'\n" +
		"NFQWS_ARGS_QUIC=''\nNFQWS_ARGS_UDP=''\nNFQWS_ARGS_IPSET=''\nNFQWS_ARGS_CUSTOM=''\n" +
		"NFQWS_EXTRA_ARGS='" + args + "'\nTCP_PORTS=443\nUDP_PORTS=''\nLOG_LEVEL=0\n" + ManagedListEnd + "\n"
	separator := ""
	if len(original) != 0 && original[len(original)-1] != '\n' {
		separator = "\n"
	}
	return append(append(slices.Clone(original), []byte(separator)...), []byte(block)...), nil
}

// The original prefix remains exact evidence. Callers still bind this document
// to its actual plan/lease before using it; recognition grants no mutation.
func NFQWSFirstStartOriginalConfig(raw []byte, owner string) ([]byte, error) {
	if !nfqwsFirstStartOwner.MatchString(owner) {
		return nil, ErrNFQWSFirstStart
	}
	start := bytes.Index(raw, []byte(ManagedListBegin))
	if start < 0 {
		if NFQWSFirstStartStockConfig(raw) != nil {
			return nil, ErrNFQWSFirstStart
		}
		return slices.Clone(raw), nil
	}
	if bytes.Count(raw, []byte(ManagedListBegin)) != 1 || bytes.Count(raw, []byte(ManagedListEnd)) != 1 ||
		!bytes.HasPrefix(raw[start:], []byte(ManagedListBegin+"\n# RAZVILKA INSTANCE "+owner+"\n"+NFQWSFirstStartFormat+"\n")) ||
		!bytes.HasSuffix(raw, []byte(ManagedListEnd+"\n")) {
		return nil, ErrNFQWSFirstStart
	}
	original := slices.Clone(raw[:start])
	if NFQWSFirstStartStockConfig(original) != nil {
		return nil, ErrNFQWSFirstStart
	}
	return original, nil
}

func NFQWSFirstStartEffectiveConfig(raw []byte, owner string) (string, error) {
	original, err := NFQWSFirstStartOriginalConfig(raw, owner)
	if err != nil || bytes.Equal(original, raw) {
		return "", ErrNFQWSFirstStart
	}
	block := strings.TrimSuffix(string(raw[len(original):]), ManagedListEnd+"\n")
	overrides, err := parseShellAssignments(block)
	if err != nil || len(overrides) != 10 {
		return "", ErrNFQWSFirstStart
	}
	var domains, excluded, addresses []string
	seen := map[string]bool{}
	for _, arg := range strings.Fields(overrides["NFQWS_EXTRA_ARGS"]) {
		key, value, ok := strings.Cut(arg, "=")
		if !ok || seen[key] {
			return "", ErrNFQWSFirstStart
		}
		seen[key] = true
		switch key {
		case "--hostlist-domains":
			domains = strings.Split(value, ",")
		case "--hostlist-exclude-domains":
			excluded = strings.Split(value, ",")
		case "--ipset-exclude-ip":
			addresses = strings.Split(value, ",")
		default:
			return "", ErrNFQWSFirstStart
		}
	}
	expected, err := NFQWSFirstStartConfig(original, owner, domains, excluded, addresses)
	if err != nil || !bytes.Equal(raw, expected) {
		return "", ErrNFQWSFirstStart
	}
	return updateShellAssignments(string(original), overrides)
}

// Every stock action sources this overlay. Only the eight generated fields
// are admitted, with the closed TCP/UDP transport unchanged.
func NFQWSFirstStartRunningConfig(config []byte, owner string, raw []byte) error {
	main, err := NFQWSFirstStartEffectiveConfig(config, owner)
	if err != nil {
		return err
	}
	if err := NFQWSRunningConfigMatches(main, string(raw)); err != nil {
		return err
	}
	fields, err := parseShellAssignments(string(raw))
	if err != nil || len(fields) != 8 || fields["TCP_PORTS"] != "443" || fields["UDP_PORTS"] != "" {
		return ErrNFQWSFirstStart
	}
	base, err := parseShellAssignments(main)
	if err != nil || fields["POLICY_NAME"] != base["POLICY_NAME"] || fields["POLICY_EXCLUDE"] != base["POLICY_EXCLUDE"] {
		return ErrNFQWSFirstStart
	}
	if fields["POLICY_MARK"] != "" && !regexp.MustCompile(`^0x[0-9a-fA-F]+/0x0fffffff$`).MatchString(fields["POLICY_MARK"]) {
		return ErrNFQWSFirstStart
	}
	return nil
}

// Scope fields are data, not proof that this interface or policy applies to
// the current network. The caller must independently observe both before use.
func NFQWSFirstStartScope(config []byte, owner string) (interfaces []string, err error) {
	original, err := NFQWSFirstStartOriginalConfig(config, owner)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(config, original) {
		if _, err := NFQWSFirstStartEffectiveConfig(config, owner); err != nil {
			return nil, err
		}
	}
	fields, err := parseShellAssignments(string(original))
	if err != nil {
		return nil, err
	}
	return strings.Fields(fields["ISP_INTERFACE"]), nil
}

func NFQWSFirstStartRunningAllLAN(config []byte, owner string, raw []byte) error {
	if err := NFQWSFirstStartRunningConfig(config, owner, raw); err != nil {
		return err
	}
	fields, err := parseShellAssignments(string(raw))
	if err != nil || fields["POLICY_MARK"] != "" {
		return ErrNFQWSFirstStart
	}
	return nil
}
