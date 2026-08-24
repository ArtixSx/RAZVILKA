package components

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxReleaseAssetBytes = 64 << 20

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseInfo struct {
	Version  string
	Asset    releaseAsset
	Checksum releaseAsset
}

type externalReceipt struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

var externalVersionPattern = regexp.MustCompile(`(?i)(?:v|version\s*)?(\d+\.\d+(?:\.\d+)?)`)
var externalVersionValuePattern = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

func releaseHTTPClient() *http.Client {
	return &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 6 {
			return errors.New("too many release redirects")
		}
		if !trustedReleaseHost(request.URL.Hostname()) {
			return fmt.Errorf("untrusted release redirect host %q", request.URL.Hostname())
		}
		return nil
	}}
}

func trustedReleaseHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "github.com" || host == "api.github.com" || host == "objects.githubusercontent.com" || host == "release-assets.githubusercontent.com"
}

func (m *Manager) externalView(ctx context.Context, spec Spec, refresh bool) (View, error) {
	target := filepath.Join(defaultValue(m.BinDir, "/opt/bin"), spec.Binary)
	installedVersion := externalInstalledVersion(target)
	view := View{Spec: spec, Installed: installedVersion != "", InstalledVersion: installedVersion}
	info, cached := m.external[spec.ID]
	if !refresh && !cached {
		if view.Installed {
			view.State = "installed-unchecked"
		} else {
			view.State = "refresh-required"
		}
		return view, nil
	}
	if refresh {
		var err error
		info, err = m.latestRelease(ctx, spec)
		if err != nil {
			if view.Installed {
				view.State = "installed-check-failed"
			} else {
				view.State = "check-failed"
			}
			return view, err
		}
		if m.external == nil {
			m.external = map[string]releaseInfo{}
		}
		m.external[spec.ID] = info
	}
	view.Available = info.Version != "" && info.Asset.URL != "" && info.Checksum.URL != ""
	view.AvailableVersion = info.Version
	switch {
	case view.Installed && view.Available && compareVersions(view.InstalledVersion, view.AvailableVersion) < 0:
		view.State, view.UpdateAvailable = "update", true
	case view.Installed:
		view.State = "installed"
	case view.Available:
		view.State = "available"
	default:
		view.State = "unavailable"
	}
	return view, nil
}

func (m *Manager) latestRelease(ctx context.Context, spec Spec) (releaseInfo, error) {
	repository, err := url.Parse(spec.Repository)
	if err != nil || repository.Scheme != "https" || repository.Hostname() != "github.com" {
		return releaseInfo{}, errors.New("invalid GitHub release repository")
	}
	parts := strings.Split(strings.Trim(repository.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return releaseInfo{}, errors.New("invalid GitHub repository path")
	}
	apiURL := "https://api.github.com/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/releases/latest"
	body, err := m.download(ctx, apiURL, 2<<20)
	if err != nil {
		return releaseInfo{}, err
	}
	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return releaseInfo{}, fmt.Errorf("decode GitHub release: %w", err)
	}
	version := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
	if !externalVersionValuePattern.MatchString(version) {
		return releaseInfo{}, fmt.Errorf("release has invalid version %q", release.TagName)
	}
	assetName, err := releaseAssetName(spec, version, m.Arch)
	if err != nil {
		return releaseInfo{}, err
	}
	info := releaseInfo{Version: version}
	for _, asset := range release.Assets {
		switch asset.Name {
		case assetName:
			info.Asset = asset
		case "checksums.txt":
			info.Checksum = asset
		}
	}
	if info.Asset.URL == "" || info.Checksum.URL == "" {
		return releaseInfo{}, fmt.Errorf("release %s has no verified asset %s or checksums.txt", version, assetName)
	}
	return info, nil
}

func releaseAssetName(spec Spec, version, architecture string) (string, error) {
	architecture = strings.TrimSpace(architecture)
	switch architecture {
	case "386", "amd64", "arm64", "mips", "mipsle", "mips64", "mips64le":
	default:
		return "", fmt.Errorf("component %s has no supported asset for architecture %s", spec.ID, architecture)
	}
	name := fmt.Sprintf("%s_%s_linux_%s", spec.Binary, version, architecture)
	if spec.Archive == "zip" {
		name += ".zip"
	}
	return name, nil
}

func (m *Manager) installExternal(ctx context.Context, spec Spec) (Result, error) {
	info, err := m.latestRelease(ctx, spec)
	if err != nil {
		return Result{Component: spec.ID, Action: "install"}, err
	}
	checksumBody, err := m.download(ctx, info.Checksum.URL, 1<<20)
	if err != nil {
		return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("download checksums: %w", err)
	}
	want, err := checksumForAsset(checksumBody, info.Asset.Name)
	if err != nil {
		return Result{Component: spec.ID, Action: "install"}, err
	}
	assetBody, err := m.download(ctx, info.Asset.URL, maxReleaseAssetBytes)
	if err != nil {
		return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("download release asset: %w", err)
	}
	actual := sha256.Sum256(assetBody)
	if !strings.EqualFold(hex.EncodeToString(actual[:]), want) {
		return Result{Component: spec.ID, Action: "install"}, errors.New("release asset SHA-256 does not match checksums.txt")
	}
	binary := assetBody
	if spec.Archive == "zip" {
		binary, err = binaryFromZIP(assetBody, spec.Binary)
		if err != nil {
			return Result{Component: spec.ID, Action: "install"}, err
		}
	}
	if len(binary) == 0 || len(binary) > maxReleaseAssetBytes {
		return Result{Component: spec.ID, Action: "install"}, errors.New("release binary is empty or too large")
	}
	target := filepath.Join(defaultValue(m.BinDir, "/opt/bin"), spec.Binary)
	receipt := externalReceiptPath(target)
	oldBinary, oldErr := os.ReadFile(target)
	oldExisted := oldErr == nil
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("snapshot installed component: %w", oldErr)
	}
	oldReceipt, oldReceiptErr := os.ReadFile(receipt)
	oldReceiptExisted := oldReceiptErr == nil
	if oldReceiptErr != nil && !errors.Is(oldReceiptErr, os.ErrNotExist) {
		return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("snapshot component receipt: %w", oldReceiptErr)
	}
	restorePrevious := func() {
		if oldExisted {
			_ = installReleaseBinary(target, oldBinary)
		} else {
			_ = os.Remove(target)
		}
		if oldReceiptExisted {
			_ = installExternalReceipt(receipt, oldReceipt)
		} else {
			_ = os.Remove(receipt)
		}
	}
	if err := installReleaseBinary(target, binary); err != nil {
		return Result{Component: spec.ID, Action: "install"}, err
	}
	reportedVersion := externalReportedVersion(target)
	if reportedVersion != "" && compareVersions(reportedVersion, info.Version) != 0 {
		restorePrevious()
		return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("installed binary reported version %q, expected %q; previous binary restored", reportedVersion, info.Version)
	}
	if reportedVersion == "" {
		if err := verifyExternalCLI(target, spec.Binary); err != nil {
			restorePrevious()
			return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("verify installed binary: %w; previous binary restored", err)
		}
	}
	if err := writeExternalReceipt(target, info.Version, binary); err != nil {
		restorePrevious()
		return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("write component receipt: %w; previous binary restored", err)
	}
	installedVersion := externalInstalledVersion(target)
	if installedVersion == "" || compareVersions(installedVersion, info.Version) != 0 {
		restorePrevious()
		return Result{Component: spec.ID, Action: "install"}, fmt.Errorf("installed binary reported version %q, expected %q; previous binary restored", installedVersion, info.Version)
	}
	if m.external == nil {
		m.external = map[string]releaseInfo{}
	}
	m.external[spec.ID] = info
	action := "install"
	if oldExisted {
		action = "update"
	}
	return Result{OK: true, Component: spec.ID, Action: action, Output: fmt.Sprintf("installed %s %s from verified upstream release", spec.Name, info.Version)}, nil
}

func (m *Manager) download(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !trustedReleaseHost(u.Hostname()) || u.User != nil {
		return nil, errors.New("untrusted release URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json, application/octet-stream")
	request.Header.Set("User-Agent", "RAZVILKA-component-manager/0.6")
	client := m.Client
	if client == nil {
		client = releaseHTTPClient()
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release server returned HTTP %d", response.StatusCode)
	}
	reader := &io.LimitedReader{R: response.Body, N: limit + 1}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || int64(len(body)) > limit {
		return nil, errors.New("release response is empty or exceeds size limit")
	}
	return body, nil
}

func checksumForAsset(body []byte, assetName string) (string, error) {
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || strings.TrimPrefix(fields[len(fields)-1], "*") != assetName {
			continue
		}
		value := strings.ToLower(fields[0])
		if len(value) != 64 {
			break
		}
		if _, err := hex.DecodeString(value); err == nil {
			return value, nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no valid SHA-256 for %s", assetName)
}

func binaryFromZIP(body []byte, binaryName string) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open release ZIP: %w", err)
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || filepath.Base(strings.ReplaceAll(file.Name, "\\", "/")) != binaryName {
			continue
		}
		if file.UncompressedSize64 == 0 || file.UncompressedSize64 > maxReleaseAssetBytes {
			return nil, errors.New("release ZIP binary is empty or too large")
		}
		stream, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, maxReleaseAssetBytes+1))
		closeErr := stream.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(data) == 0 || len(data) > maxReleaseAssetBytes {
			return nil, errors.New("invalid release ZIP binary size")
		}
		return data, nil
	}
	return nil, fmt.Errorf("release ZIP does not contain %s", binaryName)
}

func installReleaseBinary(target string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".razvilka-component-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return fmt.Errorf("install component binary: %w", err)
	}
	return nil
}

func externalInstalledVersion(path string) string {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	if version := externalReceiptVersion(path); version != "" {
		return version
	}
	if version := externalReportedVersion(path); version != "" {
		return version
	}
	return ""
}

// InstalledReleaseVersion returns a version only when the executable reports
// it or when an integrity-bound RAZVILKA receipt matches the current binary.
func InstalledReleaseVersion(path string) string { return externalInstalledVersion(path) }

func externalReportedVersion(path string) string {
	for _, args := range [][]string{{"--version"}, {"version"}, {"-v"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		output, commandErr := exec.CommandContext(ctx, path, args...).CombinedOutput()
		cancel()
		if commandErr != nil {
			continue
		}
		if match := externalVersionPattern.FindStringSubmatch(string(output)); len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

func verifyExternalCLI(path, binaryName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return errors.New("help command timed out")
	}
	if err != nil {
		return fmt.Errorf("help command failed: %w", err)
	}
	if !strings.Contains(strings.ToLower(string(output)), strings.ToLower(binaryName)) {
		return errors.New("help output does not identify the installed binary")
	}
	return nil
}

func externalReceiptPath(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".razvilka.json")
}

func writeExternalReceipt(target, version string, binary []byte) error {
	if !externalVersionValuePattern.MatchString(strings.TrimSpace(version)) {
		return fmt.Errorf("invalid component version %q", version)
	}
	sum := sha256.Sum256(binary)
	receipt := externalReceipt{Version: strings.TrimSpace(version), SHA256: hex.EncodeToString(sum[:])}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return installExternalReceipt(externalReceiptPath(target), data)
}

func installExternalReceipt(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".razvilka-receipt-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func externalReceiptVersion(target string) string {
	data, err := os.ReadFile(externalReceiptPath(target))
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return ""
	}
	var receipt externalReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return ""
	}
	receipt.Version = strings.TrimSpace(receipt.Version)
	receipt.SHA256 = strings.ToLower(strings.TrimSpace(receipt.SHA256))
	if !externalVersionValuePattern.MatchString(receipt.Version) || len(receipt.SHA256) != 64 {
		return ""
	}
	binary, err := os.ReadFile(target)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(binary)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), receipt.SHA256) {
		return ""
	}
	return receipt.Version
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
