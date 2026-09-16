package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const officialRepository = "ArtixSx/RAZVILKA"

type Result struct {
	Channel          string `json:"channel"`
	MetadataStale    bool   `json:"metadata_stale"`
	RetryAt          string `json:"retry_at,omitempty"`
	InstalledVersion string `json:"installed_version"`
	LatestVersion    string `json:"latest_version,omitempty"`
	UpdateAvailable  bool   `json:"update_available"`
	State            string `json:"state"`
	ReleaseURL       string `json:"release_url,omitempty"`
	PublishedAt      string `json:"published_at,omitempty"`
	CheckedAt        string `json:"checked_at"`
	InstallCommand   string `json:"install_command"`
	VerifyCommand    string `json:"verify_command"`
	Error            string `json:"error,omitempty"`
	ReleaseTag       string `json:"release_tag,omitempty"`
	CanPrepare       bool   `json:"can_prepare"`
	Verification     string `json:"verification"`
}

type Manager struct {
	Current  string
	Endpoint string
	Client   *http.Client
	TTL      time.Duration

	mu       sync.Mutex
	cached   Result
	cachedAt time.Time
	channel  string
	etag     string
	lastGood Result
	retryAt  time.Time
}

func New(current string) *Manager {
	return &Manager{
		Current: current, Endpoint: "https://api.github.com/repos/" + officialRepository + "/releases/latest", TTL: 30 * time.Minute,
		Client: func() *http.Client {
			client := publicfetch.NewClient(12 * time.Second)
			client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
				if request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Hostname(), "api.github.com") {
					return errors.New("untrusted update-check redirect")
				}
				return nil
			}
			return client
		}(),
	}
}

func (m *Manager) Check(parent context.Context, refresh bool) Result {
	return m.CheckChannel(parent, refresh, "stable")
}
func (m *Manager) CheckChannel(parent context.Context, refresh bool, channel string) Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	channel = NormalizedChannel(channel)
	if !ValidChannel(channel) {
		return Result{State: "check-failed", Error: "release-channel-invalid", Channel: channel}
	}
	if m.channel != channel {
		m.channel = channel
		m.cachedAt = time.Time{}
		m.etag = ""
		m.lastGood = Result{}
	}
	if time.Now().Before(m.retryAt) {
		result := m.lastGood
		result.InstalledVersion = m.Current
		result.Channel = channel
		result.State = "check-failed"
		result.Error = "Сервер обновлений запросил паузу. Установленная версия не менялась."
		result.MetadataStale = true
		result.UpdateAvailable = false
		result.CanPrepare = false
		result.RetryAt = m.retryAt.UTC().Format(time.RFC3339)
		return result
	}
	if !refresh && !m.cachedAt.IsZero() && time.Since(m.cachedAt) < m.ttl() {
		return m.cached
	}
	result := Result{Channel: channel, InstalledVersion: m.Current, State: "check-failed", CheckedAt: time.Now().UTC().Format(time.RFC3339), InstallCommand: installCommand(), VerifyCommand: verifyCommand()}
	if err := m.check(parent, &result); err != nil {
		result.Error = "Не удалось подтвердить каталог обновлений. Повторите проверку позже."
		result.MetadataStale = m.lastGood.ReleaseTag != ""
		result.LatestVersion = m.lastGood.LatestVersion
		result.ReleaseTag = m.lastGood.ReleaseTag
		result.ReleaseURL = m.lastGood.ReleaseURL
		result.CanPrepare = false
		result.UpdateAvailable = false
		if !m.retryAt.IsZero() {
			result.RetryAt = m.retryAt.UTC().Format(time.RFC3339)
		}
	} else {
		m.lastGood = result
	}
	m.cached, m.cachedAt = result, time.Now()
	return result
}

func (m *Manager) check(parent context.Context, result *Result) error {
	if m.Client == nil || strings.TrimSpace(m.Endpoint) == "" {
		return errors.New("update checker is not configured")
	}
	endpoint := m.Endpoint
	if m.channel == "preview" {
		endpoint = strings.TrimSuffix(m.Endpoint, "/latest") + "?per_page=30"
	}
	request, err := http.NewRequestWithContext(parent, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	if m.etag != "" {
		request.Header.Set("If-None-Match", m.etag)
	}
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "RAZVILKA-Update-Check/1")
	response, err := m.Client.Do(request)
	if err != nil {
		return fmt.Errorf("check official GitHub release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if m.etag == "" || m.lastGood.ReleaseTag == "" {
			return errors.New("unexpected-304")
		}
		checked := result.CheckedAt
		*result = m.lastGood
		result.CheckedAt = checked
		result.MetadataStale = false
		return nil
	}
	if response.StatusCode == 429 || response.StatusCode == 503 || response.StatusCode == 403 {
		m.retryAt = updateRetryAfter(response.Header, time.Now())
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("official GitHub release returned HTTP %d", response.StatusCode)
	}
	var release struct {
		TagName     string `json:"tag_name"`
		HTMLURL     string `json:"html_url"`
		PublishedAt string `json:"published_at"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	const maximumMetadataBytes = 2 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumMetadataBytes+1))
	if err != nil || len(data) > maximumMetadataBytes {
		return errors.New("official release metadata exceeds the size limit")
	}
	data, err = selectChannelMetadata(data, m.channel)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return errors.New("invalid official release metadata")
	}
	latest, versionOK := normalizeVersion(release.TagName)
	if release.Draft || (m.channel != "preview" && release.Prerelease) || !versionOK {
		return errors.New("latest official release metadata is not stable")
	}
	page, err := url.Parse(release.HTMLURL)
	if err != nil || page.Scheme != "https" || !strings.EqualFold(page.Hostname(), "github.com") || !strings.HasPrefix(page.Path, "/"+officialRepository+"/releases/") {
		return errors.New("official release link failed validation")
	}
	result.LatestVersion, result.ReleaseURL, result.PublishedAt, result.ReleaseTag = latest, page.String(), release.PublishedAt, release.TagName
	if m.channel == "preview" {
		latest = strings.TrimPrefix(release.TagName, "v")
		result.LatestVersion = latest
	}
	m.etag = safeUpdateETag(response.Header.Get("ETag"))
	m.retryAt = time.Time{}
	result.UpdateAvailable = CanUpgradeChannel(m.Current, release.TagName, m.channel)
	result.CanPrepare = result.UpdateAvailable
	result.Verification = "github-release-sha256"
	if result.UpdateAvailable {
		result.State = "update"
	} else {
		result.State = "current"
		_, pre, recognized := parseComparableVersion(m.Current)
		if !recognized {
			result.State = "unrecognized"
		} else if strings.Contains(strings.ToLower(pre), "dev") || strings.Contains(strings.ToLower(pre), "local") {
			result.State = "development"
		} else if compareVersions(m.Current, latest) > 0 {
			result.State = "ahead"
		}
	}
	return nil
}

func installCommand() string {
	return "curl -fsSL https://raw.githubusercontent.com/ArtixSx/RAZVILKA/main/scripts/bootstrap.sh | sh"
}

func verifyCommand() string {
	return "gh attestation verify RAZVILKA-entware.tar.gz --repo " + officialRepository
}

var versionPart = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

func compareVersions(left, right string) int {
	if leftVersion, leftPre, leftOK := parseComparableVersion(left); leftOK {
		if rightVersion, rightPre, rightOK := parseComparableVersion(right); rightOK {
			for index := range leftVersion {
				if leftVersion[index] < rightVersion[index] {
					return -1
				}
				if leftVersion[index] > rightVersion[index] {
					return 1
				}
			}
			if leftPre == rightPre {
				return 0
			}
			if leftPre != "" && rightPre == "" {
				return -1
			}
			if leftPre == "" && rightPre != "" {
				return 1
			}
			return comparePrerelease(leftPre, rightPre)
		}
	}
	a, b := versionPart.FindAllString(strings.TrimPrefix(left, "v"), -1), versionPart.FindAllString(strings.TrimPrefix(right, "v"), -1)
	count := len(a)
	if len(b) > count {
		count = len(b)
	}
	for index := 0; index < count; index++ {
		if index >= len(a) {
			return -1
		}
		if index >= len(b) {
			return 1
		}
		if a[index] == b[index] {
			continue
		}
		leftNumber, leftErr := strconv.Atoi(a[index])
		rightNumber, rightErr := strconv.Atoi(b[index])
		if leftErr == nil && rightErr == nil {
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		}
		if a[index] < b[index] {
			return -1
		}
		return 1
	}
	return 0
}

var comparableVersionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

func parseComparableVersion(value string) ([3]uint64, string, bool) {
	match := comparableVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 5 {
		return [3]uint64{}, "", false
	}
	var version [3]uint64
	for index := range version {
		if len(match[index+1]) > 1 && match[index+1][0] == '0' {
			return [3]uint64{}, "", false
		}
		number, err := strconv.ParseUint(match[index+1], 10, 32)
		if err != nil {
			return [3]uint64{}, "", false
		}
		version[index] = number
	}
	for _, part := range strings.Split(match[4], ".") {
		if match[4] != "" && (part == "" || allDigits(part) && len(part) > 1 && part[0] == '0') {
			return [3]uint64{}, "", false
		}
	}
	return version, match[4], true
}

var stableTagPattern = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)(?:[-+][0-9A-Za-z.-]+)?$`)

func normalizeVersion(value string) (string, bool) {
	match := stableTagPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 2 {
		return "", false
	}
	parts := strings.Split(match[1], ".")
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return "", false
		}
	}
	return match[1], true
}

func (m *Manager) ttl() time.Duration {
	if m.TTL <= 0 {
		return 30 * time.Minute
	}
	return m.TTL
}
