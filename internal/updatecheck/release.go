package updatecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const MaximumArchiveBytes int64 = 128 << 20
const MaximumBinaryBytes int64 = 64 << 20

type Asset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
	URL    string `json:"url"`
}

type Release struct {
	ID           int64  `json:"id"`
	Tag          string `json:"tag"`
	Version      string `json:"version"`
	PublishedAt  string `json:"published_at"`
	Page         string `json:"page"`
	Architecture string `json:"architecture"`
	Archive      Asset  `json:"archive"`
	Binary       Asset  `json:"binary"`
}

var exactStableTag = regexp.MustCompile(`^v?([0-9]+\.[0-9]+\.[0-9]+)$`)

// CanUpgrade refuses unknown versions and older stable bases. A matching
// stable release may replace its prerelease only after deployment review.
func CanUpgrade(current, target string) bool {
	left, pre, ok := parseComparableVersion(current)
	if !ok || !exactStableTag.MatchString(target) {
		return false
	}
	right, _, ok := parseComparableVersion(target)
	if !ok {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return pre != ""
}

func OfficialClient(timeout time.Duration) *http.Client {
	client := publicfetch.WithPolicy(publicfetch.NewClient(25*time.Second), "https://github.com", []string{"release-assets.githubusercontent.com", "objects.githubusercontent.com"})
	client.Timeout = timeout // Download is streaming and additionally job-bounded.
	return client
}

// FetchRelease reads only the hard-coded official repository; neither a URL
// nor an architecture supplied by the browser reaches this boundary.
func FetchRelease(ctx context.Context, client *http.Client, current, arch string, releaseID int64) (Release, error) {
	return FetchReleaseChannel(ctx, client, current, arch, releaseID, "stable")
}
func FetchReleaseChannel(ctx context.Context, client *http.Client, current, arch string, releaseID int64, channel string) (Release, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if !supportedArchitecture(arch) || !ValidChannel(channel) {
		return Release{}, errors.New("unsupported-architecture")
	}
	endpoint := "https://api.github.com/repos/" + officialRepository + "/releases/latest"
	if NormalizedChannel(channel) == "preview" {
		endpoint = "https://api.github.com/repos/" + officialRepository + "/releases?per_page=30"
	}
	if releaseID > 0 {
		endpoint = fmt.Sprintf("https://api.github.com/repos/%s/releases/%d", officialRepository, releaseID)
	}
	data, err := fetchLimited(ctx, client, endpoint, 2<<20)
	if err != nil {
		return Release{}, err
	}
	if releaseID == 0 {
		data, err = selectChannelMetadata(data, channel)
		if err != nil {
			return Release{}, err
		}
	}
	return parseReleaseChannel(data, current, arch, releaseID, channel)
}

func parseRelease(data []byte, current, arch string, expectedID int64) (Release, error) {
	return parseReleaseChannel(data, current, arch, expectedID, "stable")
}
func parseReleaseChannel(data []byte, current, arch string, expectedID int64, channel string) (Release, error) {
	var raw struct {
		ID         int64  `json:"id"`
		Tag        string `json:"tag_name"`
		Published  string `json:"published_at"`
		Page       string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			Digest string `json:"digest"`
			URL    string `json:"browser_download_url"`
			State  string `json:"state"`
		} `json:"assets"`
	}
	if json.Unmarshal(data, &raw) != nil || raw.ID <= 0 || expectedID > 0 && raw.ID != expectedID || raw.Draft || (NormalizedChannel(channel) != "preview" && raw.Prerelease) || !CanUpgradeChannel(current, raw.Tag, channel) || !supportedArchitecture(arch) || len(raw.Assets) > 100 {
		return Release{}, errors.New("release-not-an-upgrade")
	}
	if NormalizedChannel(channel) == "preview" {
		_, pre, ok := parseComparableVersion(raw.Tag)
		if !ok || (pre == "") == raw.Prerelease {
			return Release{}, errors.New("release-channel-identity-invalid")
		}
	}
	version := strings.TrimPrefix(raw.Tag, "v")
	page := "https://github.com/" + officialRepository + "/releases/tag/" + raw.Tag
	if raw.Page != page {
		return Release{}, errors.New("release-identity-invalid")
	}
	if _, err := time.Parse(time.RFC3339, raw.Published); err != nil {
		return Release{}, errors.New("release-date-invalid")
	}
	r := Release{ID: raw.ID, Tag: raw.Tag, Version: version, PublishedAt: raw.Published, Page: page, Architecture: arch}
	archiveName := "RAZVILKA-" + version + "-entware.tar.gz"
	binaryName := "razvilka-linux-" + arch
	for _, a := range raw.Assets {
		if a.Name != archiveName && a.Name != binaryName {
			continue
		}
		if a.ID <= 0 || a.State != "uploaded" || a.Size <= 0 || a.Size > MaximumArchiveBytes || !validDigest(a.Digest) || a.URL != "https://github.com/"+officialRepository+"/releases/download/"+raw.Tag+"/"+a.Name {
			return Release{}, errors.New("release-asset-invalid")
		}
		asset := Asset{ID: a.ID, Name: a.Name, Size: a.Size, Digest: a.Digest, URL: a.URL}
		if a.Name == archiveName {
			if r.Archive.ID != 0 {
				return Release{}, errors.New("duplicate-archive")
			}
			r.Archive = asset
		} else {
			if r.Binary.ID != 0 || a.Size > MaximumBinaryBytes {
				return Release{}, errors.New("duplicate-or-large-binary")
			}
			r.Binary = asset
		}
	}
	if r.Archive.ID == 0 || r.Binary.ID == 0 {
		return Release{}, errors.New("release-asset-missing")
	}
	return r, nil
}

func supportedArchitecture(arch string) bool {
	return arch == "arm64" || arch == "mips" || arch == "mipsle" || arch == "amd64"
}
func validDigest(d string) bool {
	if !strings.HasPrefix(d, "sha256:") || len(d) != 71 {
		return false
	}
	b, err := hex.DecodeString(d[7:])
	return err == nil && len(b) == sha256.Size && d == strings.ToLower(d)
}

func fetchLimited(ctx context.Context, client *http.Client, rawURL string, maximum int64) ([]byte, error) {
	response, err := officialGET(ctx, client, rawURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("release-response-size-or-read")
	}
	return data, nil
}

func officialGET(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || publicfetch.ValidateURL(rawURL) != nil || u.RawQuery != "" || (u.Host != "api.github.com" && u.Host != "github.com") {
		return nil, errors.New("release-url-refused")
	}
	if client == nil {
		client = OfficialClient(3 * time.Minute)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "RAZVILKA-Self-Update/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("official-release-unavailable")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("official-release-http-%d", response.StatusCode)
	}
	return response, nil
}
