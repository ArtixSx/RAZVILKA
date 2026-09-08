package z2kimport

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/strategylab"
)

const maxSourceBytes = 2 << 20

type File struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Strategy struct {
	PoolID     string   `json:"pool_id"`
	Name       string   `json:"name"`
	Arguments  string   `json:"arguments"`
	Source     string   `json:"source"`
	Compatible bool     `json:"compatible"`
	Issues     []string `json:"issues"`
}

type Preview struct {
	SchemaVersion  int        `json:"schema_version"`
	Found          bool       `json:"found"`
	Root           string     `json:"root"`
	Version        string     `json:"version,omitempty"`
	Files          []File     `json:"files"`
	Strategies     []Strategy `json:"strategies"`
	ExtraDomains   []string   `json:"extra_domains"`
	AutoDomains    []string   `json:"auto_domains"`
	ExcludeDomains []string   `json:"exclude_domains"`
	ExcludeCIDRs   []string   `json:"exclude_cidrs"`
	WarpCIDRs      []string   `json:"warp_cidrs"`
	StateRows      int        `json:"state_rows"`
	Warnings       []string   `json:"warnings"`
	ReadOnly       bool       `json:"read_only"`
}

type Scanner struct {
	Root string
}

var strategyFiles = map[string]string{
	"rkn_tcp.txt":       "tcp-tls",
	"yt_tcp.txt":        "youtube-tcp",
	"gv_tcp.txt":        "googlevideo",
	"yt_quic.txt":       "quic-udp",
	"discord_voice.txt": "discord-voice",
}

var domainPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (s Scanner) Scan() (Preview, error) {
	root := strings.TrimSpace(s.Root)
	if root == "" {
		root = "/opt/zapret2"
	}
	preview := Preview{SchemaVersion: 1, Root: root, Files: []File{}, Strategies: []Strategy{}, ExtraDomains: []string{}, AutoDomains: []string{}, ExcludeDomains: []string{}, ExcludeCIDRs: []string{}, WarpCIDRs: []string{}, Warnings: []string{}, ReadOnly: true}
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return preview, nil
		}
		return preview, err
	}
	if !info.IsDir() {
		return preview, fmt.Errorf("z2k root is not a directory: %s", root)
	}
	preview.Found = true
	preview.Version = firstLine(filepath.Join(root, ".z2k-installed-tag"))

	for name, poolID := range strategyFiles {
		path := filepath.Join(root, "lists", "custom-strategies", name)
		content, file, err := readSource(root, path, "strategy")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			preview.Warnings = append(preview.Warnings, err.Error())
			continue
		}
		preview.Files = append(preview.Files, file)
		strategy := Strategy{PoolID: poolID, Name: "z2k " + strings.TrimSuffix(name, ".txt"), Arguments: strings.TrimSpace(string(content)), Source: file.Path, Issues: []string{}}
		if _, err := strategylab.ParseArguments(strategy.Arguments); err != nil {
			strategy.Issues = append(strategy.Issues, err.Error())
		} else {
			strategy.Compatible = true
		}
		preview.Strategies = append(preview.Strategies, strategy)
	}

	preview.ExtraDomains = s.readDomains(&preview, "extra-domains", filepath.Join(root, "lists", "extra-domains.txt"))
	preview.AutoDomains = s.readDomains(&preview, "autohostlist", filepath.Join(root, "lists", "autohostlist-domains.txt"))
	for _, path := range []string{filepath.Join(root, "lists", "exclude-domains.txt"), filepath.Join(root, "ipset", "zapret-hosts-user-exclude-domains.txt")} {
		preview.ExcludeDomains = append(preview.ExcludeDomains, s.readDomains(&preview, "exclude-domains", path)...)
	}
	preview.ExcludeDomains = unique(preview.ExcludeDomains)
	preview.ExcludeCIDRs = s.readCIDRs(&preview, "exclude-cidrs", filepath.Join(root, "ipset", "zapret-hosts-user-exclude.txt"))
	for _, path := range []string{filepath.Join(root, "lists", "warp-user.txt"), filepath.Join(root, "lists", "warp-custom.txt"), filepath.Join(root, "warp", "user-cidrs.txt")} {
		preview.WarpCIDRs = append(preview.WarpCIDRs, s.readCIDRs(&preview, "warp-cidrs", path)...)
	}
	preview.WarpCIDRs = unique(preview.WarpCIDRs)
	for _, path := range []string{filepath.Join(root, "state.tsv"), filepath.Join(root, "lua", "state.tsv"), filepath.Join(root, "state", "state.tsv")} {
		content, file, err := readSource(root, path, "strategy-state")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			preview.Warnings = append(preview.Warnings, err.Error())
			continue
		}
		preview.Files = append(preview.Files, file)
		preview.StateRows += countDataRows(content)
	}
	if preview.StateRows > 0 {
		preview.Warnings = append(preview.Warnings, "state.tsv обнаружен, но его внутренние номера стратегий не импортируются без соответствующего пула и нативной повторной проверки")
	}
	sort.Slice(preview.Files, func(i, j int) bool { return preview.Files[i].Path < preview.Files[j].Path })
	sort.Slice(preview.Strategies, func(i, j int) bool { return preview.Strategies[i].PoolID < preview.Strategies[j].PoolID })
	return preview, nil
}

func (s Scanner) readDomains(preview *Preview, kind, path string) []string {
	content, file, err := readSource(preview.Root, path, kind)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}
	}
	if err != nil {
		preview.Warnings = append(preview.Warnings, err.Error())
		return []string{}
	}
	preview.Files = append(preview.Files, file)
	out := []string{}
	for _, line := range dataLines(content) {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(line, "*.")), ".")
		if domainPattern.MatchString(domain) {
			out = append(out, domain)
		} else {
			preview.Warnings = append(preview.Warnings, fmt.Sprintf("%s: неподдерживаемая запись %q", file.Path, line))
		}
	}
	return unique(out)
}

func (s Scanner) readCIDRs(preview *Preview, kind, path string) []string {
	content, file, err := readSource(preview.Root, path, kind)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}
	}
	if err != nil {
		preview.Warnings = append(preview.Warnings, err.Error())
		return []string{}
	}
	preview.Files = append(preview.Files, file)
	out := []string{}
	for _, line := range dataLines(content) {
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			if address, addressErr := netip.ParseAddr(line); addressErr == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
			} else {
				preview.Warnings = append(preview.Warnings, fmt.Sprintf("%s: неподдерживаемая сеть %q", file.Path, line))
				continue
			}
		}
		out = append(out, prefix.Masked().String())
	}
	return unique(out)
}

func readSource(root, path, kind string) ([]byte, File, error) {
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, File{}, err
	}
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return nil, File{}, err
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, File{}, errors.New("z2k source escaped the configured root")
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, File{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, File{}, fmt.Errorf("z2k source is not a regular file: %s", relative)
	}
	if info.Size() > maxSourceBytes {
		return nil, File{}, fmt.Errorf("z2k source is larger than %d bytes: %s", maxSourceBytes, relative)
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, File{}, err
	}
	digest := sha256.Sum256(data)
	return data, File{Kind: kind, Path: filepath.ToSlash(relative), Size: info.Size(), SHA256: hex.EncodeToString(digest[:])}, nil
}

func dataLines(content []byte) []string {
	lines := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func countDataRows(content []byte) int { return len(dataLines(content)) }

func firstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
	return strings.TrimSpace(line)
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
