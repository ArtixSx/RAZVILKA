package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const xrayAutoFetchPrefix = "RAZVILKA_NATIVE_XRAY_AUTO_"
const xrayAutoFetchBudget = 30 * time.Minute

// Test-only input/chronology skeleton. There is deliberately no native test,
// worker, checker substitute or runtime issuer here. The eventual native owner
// must collect original production evidence independently of these comparisons.
type xrayAutoFetchInput struct {
	Base               xraySelectedNativeInput
	Profiles           [3]string
	FeedURLFile, RunID string
}

func (xrayAutoFetchInput) String() string   { return "[private AUTO QA input]" }
func (xrayAutoFetchInput) GoString() string { return "[private AUTO QA input]" }

func xrayAutoFetchParseInput(getenv func(string) string) (xrayAutoFetchInput, error) {
	var in xrayAutoFetchInput
	if getenv == nil || getenv(xrayAutoFetchPrefix+"ENABLED") != "1" {
		return in, errors.New("explicit AUTO QA opt-in required")
	}
	base, err := xraySelectedParseInput(func(key string) string {
		suffix := strings.TrimPrefix(key, "RAZVILKA_NATIVE_XRAY_SELECTED_")
		if suffix == "SOAK" {
			return ""
		}
		if suffix == "PROFILE" {
			suffix = "PROFILE_A"
		}
		return getenv(xrayAutoFetchPrefix + suffix)
	})
	if err != nil {
		return in, errors.New("invalid AUTO QA scope input")
	}
	in.Base = base
	in.Profiles = [3]string{base.Profile, getenv(xrayAutoFetchPrefix + "PROFILE_B"), getenv(xrayAutoFetchPrefix + "PROFILE_C")}
	in.FeedURLFile = getenv(xrayAutoFetchPrefix + "FEED_URL_FILE")
	in.RunID = getenv(xrayAutoFetchPrefix + "RUN_ID")
	if len(in.RunID) < 12 || len(in.RunID) > 64 || strings.Trim(in.RunID, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return xrayAutoFetchInput{}, errors.New("invalid AUTO QA run identity")
	}
	seen := map[string]bool{}
	for _, path := range []string{in.Profiles[0], in.Profiles[1], in.Profiles[2], in.FeedURLFile, base.Catalog, base.Sources, base.Scope} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.TrimSpace(path) != path || filepath.Dir(path) == path {
			return xrayAutoFetchInput{}, errors.New("canonical private AUTO QA file required")
		}
		// Be conservative on Windows: different spelling is not independent material.
		key := strings.ToLower(path)
		if seen[key] || strings.EqualFold(path, base.Root) {
			return xrayAutoFetchInput{}, errors.New("distinct AUTO QA input files required")
		}
		seen[key] = true
	}
	return in, nil
}

// This only parses bytes already read by the eventual bounded private-file
// reader. It does not resolve DNS, establish TLS or authorize a source. The real
// providerfeed/publicfetch path must perform its ordinary checks at execution.
func xrayAutoFetchURL(data []byte) (string, error) {
	if len(data) == 0 || len(data) > 4096 {
		return "", errors.New("invalid private AUTO QA source URL")
	}
	raw := strings.TrimSuffix(string(data), "\n")
	if strings.ContainsAny(raw, "\x00\r\n\t ") || publicfetch.ValidateURL(raw) != nil {
		return "", errors.New("invalid private AUTO QA source URL")
	}
	return raw, nil
}

// Detached metadata only. An ordered trace is necessary for the demand-fetch
// assertion, but cannot establish a verdict, consent, physical proof, current
// owner, successful Apply or retirement. No consumer may turn it into a grant.
// Populate from original job/history/Store/runtime producers, never a command
// file's timestamps. Root's publication/fault events describe intent only.
type xrayAutoFetchChronology struct {
	BootstrapAttempt, BootstrapFinished, NormalRefreshDue time.Time
	AppliedA, FaultA, FailureA1, FailureA2, FailureB      time.Time
	Exhausted, PublishedC, JobCreated                     time.Time
	RequestStarted, RequestFinished, AdmittedC            time.Time
	CheckedC, CommittedC                                  time.Time
	OriginalSourceID, FetchedSourceID                     string
	BootstrapNodeIDs                                      [2]string
	NodeC, BootstrapBodySHA256, FetchedBodySHA256         string
	HTTPStatus                                            int
}

func (xrayAutoFetchChronology) String() string   { return "[private AUTO QA chronology]" }
func (xrayAutoFetchChronology) GoString() string { return "[private AUTO QA chronology]" }

func xrayAutoFetchChronologyCheck(s xrayAutoFetchChronology, now time.Time, failureGap time.Duration) error {
	if now.IsZero() || failureGap < 10*time.Second {
		return errors.New("invalid AUTO QA observation window")
	}
	ordered := []time.Time{s.BootstrapAttempt, s.BootstrapFinished, s.AppliedA, s.FaultA,
		s.FailureA1, s.FailureA2, s.FailureB, s.Exhausted, s.PublishedC, s.JobCreated,
		s.RequestStarted, s.RequestFinished, s.AdmittedC, s.CheckedC, s.CommittedC}
	for i, at := range ordered {
		if at.IsZero() || at.After(now) || i > 0 && at.Before(ordered[i-1]) {
			return errors.New("AUTO QA chronology incomplete or unordered")
		}
	}
	if s.FailureA2.Sub(s.FailureA1) < failureGap {
		return errors.New("AUTO QA failure quorum gap missing")
	}
	// A successful bootstrap with the ordinary 60-minute interval leaves a
	// genuine 15-minute demand window. Error/backoff/429 observations cannot be
	// represented as this successful-bootstrap case; the native owner must stop.
	// Job.FinishedAt can follow completeSavedLocked's scheduling timestamp;
	// use the earlier actual attempt boundary, not an invented completion clock.
	if s.NormalRefreshDue.Before(s.BootstrapAttempt.Add(time.Hour)) ||
		!s.CommittedC.Before(s.NormalRefreshDue) ||
		s.JobCreated.Before(s.BootstrapAttempt.Add(15*time.Minute)) ||
		s.CommittedC.Sub(s.BootstrapAttempt) > xrayAutoFetchBudget {
		return errors.New("AUTO QA demand window unconfirmed")
	}
	if s.HTTPStatus != 200 || s.OriginalSourceID == "" || s.OriginalSourceID != s.FetchedSourceID ||
		s.BootstrapNodeIDs[0] == "" || s.BootstrapNodeIDs[1] == "" || s.BootstrapNodeIDs[0] == s.BootstrapNodeIDs[1] ||
		s.NodeC == "" || s.NodeC == s.BootstrapNodeIDs[0] || s.NodeC == s.BootstrapNodeIDs[1] {
		return errors.New("AUTO QA fresh source identity unconfirmed")
	}
	for _, value := range []string{s.BootstrapBodySHA256, s.FetchedBodySHA256} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || strings.ToLower(value) != value {
			return errors.New("AUTO QA body digest missing")
		}
	}
	if s.BootstrapBodySHA256 == s.FetchedBodySHA256 {
		return errors.New("AUTO QA changed response body missing")
	}
	return nil
}

func TestXrayAutoFetchInputKeepsCanonicalPrivateFilesAndOriginalScope(t *testing.T) {
	root := t.TempDir()
	values := map[string]string{"ENABLED": "1", "RUN_ID": "auto-qa-0123456789", "ROOT": root,
		"PROFILE_A": filepath.Join(root, "a.private.json"), "PROFILE_B": filepath.Join(root, "b.private.json"),
		"PROFILE_C": filepath.Join(root, "c.private.json"), "FEED_URL_FILE": filepath.Join(root, "url.private.txt"),
		"CATALOG": filepath.Join(root, "catalog.json"), "SOURCES": filepath.Join(root, "sources.json"),
		"SCOPE": filepath.Join(root, "scope.json"), "HTTPS_IPV4": "1.1.1.1", "CLIENT_IPV4": "192.168.1.40"}
	get := func(key string) string { return values[strings.TrimPrefix(key, xrayAutoFetchPrefix)] }
	in, err := xrayAutoFetchParseInput(get)
	if err != nil || in.Base.Soak || in.Base.Profile != in.Profiles[0] || in.Base.Client.String() != values["CLIENT_IPV4"] {
		t.Fatal("valid private input refused or scope changed")
	}
	for name, change := range map[string]func(){
		"missing opt-in":       func() { values["ENABLED"] = "" },
		"same profiles":        func() { values["PROFILE_C"] = values["PROFILE_A"] },
		"case alias":           func() { values["PROFILE_C"] = strings.ToUpper(values["PROFILE_A"]) },
		"relative source file": func() { values["FEED_URL_FILE"] = "secret-url.txt" },
		"root as file":         func() { values["PROFILE_B"] = root },
		"noncanonical path": func() {
			values["PROFILE_C"] = root + string(filepath.Separator) + ".." + string(filepath.Separator) + "private.json"
		},
		"URL as path":   func() { values["FEED_URL_FILE"] = "https://source.example/private-token" },
		"private HTTPS": func() { values["HTTPS_IPV4"] = "127.0.0.1" },
		"run path":      func() { values["RUN_ID"] = "../private-run-token" },
	} {
		t.Run(name, func(t *testing.T) {
			before := make(map[string]string, len(values))
			for k, v := range values {
				before[k] = v
			}
			defer func() { values = before }()
			change()
			if _, err := xrayAutoFetchParseInput(get); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(verb, in), root) {
			t.Fatal("private input formatting leaked a path")
		}
	}
}

func TestXrayAutoFetchPrivateURLUsesProductionSyntaxWithoutNetwork(t *testing.T) {
	const good = "https://source.example/qa-vless.txt?private-token=secret"
	if got, err := xrayAutoFetchURL([]byte(good + "\n")); err != nil || got != good {
		t.Fatal("valid private source URL refused")
	}
	for _, raw := range []string{"", "http://source.example/secret", "https://localhost/secret", "https://127.0.0.1/secret",
		"https://user:secret@source.example/", "https://source.example:8443/secret", good + "\n\n", good + "\r\n", good + "#secret", strings.Repeat("s", 4097)} {
		got, err := xrayAutoFetchURL([]byte(raw))
		if err == nil || got != "" || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe URL accepted or private cause exposed")
		}
	}
}

func TestXrayAutoFetchChronologyRejectsPreparedReserveAndPrematureFetch(t *testing.T) {
	start := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }
	base := xrayAutoFetchChronology{BootstrapAttempt: start, BootstrapFinished: at(5), NormalRefreshDue: at(3605),
		AppliedA: at(40), FaultA: at(50), FailureA1: at(65), FailureA2: at(95), FailureB: at(120),
		Exhausted: at(121), PublishedC: at(130), JobCreated: at(900), RequestStarted: at(902), RequestFinished: at(905),
		AdmittedC: at(906), CheckedC: at(930), CommittedC: at(960), OriginalSourceID: "feed-original", FetchedSourceID: "feed-original",
		BootstrapNodeIDs: [2]string{"node-a", "node-b"}, NodeC: "node-c", HTTPStatus: 200,
		BootstrapBodySHA256: strings.Repeat("a", 64), FetchedBodySHA256: strings.Repeat("b", 64)}
	if err := xrayAutoFetchChronologyCheck(base, at(1000), 10*time.Second); err != nil {
		t.Fatal("valid comparison chronology refused")
	}
	completionRace := base
	completionRace.NormalRefreshDue = at(3601)
	if err := xrayAutoFetchChronologyCheck(completionRace, at(1000), 10*time.Second); err != nil {
		t.Fatal("original due boundary refused because job publication finished later")
	}
	for name, change := range map[string]func(*xrayAutoFetchChronology){
		"before fault":        func(s *xrayAutoFetchChronology) { s.RequestStarted = at(45) },
		"before exhaustion":   func(s *xrayAutoFetchChronology) { s.JobCreated = at(100) },
		"cooldown bypass":     func(s *xrayAutoFetchChronology) { s.JobCreated = at(899) },
		"failure gap bypass":  func(s *xrayAutoFetchChronology) { s.FailureA2 = at(66) },
		"missing exhaustion":  func(s *xrayAutoFetchChronology) { s.Exhausted = time.Time{} },
		"normal refresh due":  func(s *xrayAutoFetchChronology) { s.NormalRefreshDue = at(902) },
		"deadline extension":  func(s *xrayAutoFetchChronology) { s.CommittedC = at(1801) },
		"304 cached snapshot": func(s *xrayAutoFetchChronology) { s.HTTPStatus = 304 },
		"rate limit":          func(s *xrayAutoFetchChronology) { s.HTTPStatus = 429 },
		"same payload":        func(s *xrayAutoFetchChronology) { s.FetchedBodySHA256 = s.BootstrapBodySHA256 },
		"foreign source":      func(s *xrayAutoFetchChronology) { s.FetchedSourceID = "feed-other" },
		"C already local":     func(s *xrayAutoFetchChronology) { s.NodeC = s.BootstrapNodeIDs[0] },
		"missing body digest": func(s *xrayAutoFetchChronology) { s.FetchedBodySHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			change(&s)
			if err := xrayAutoFetchChronologyCheck(s, at(2000), 10*time.Second); err == nil {
				t.Fatal("invalid demand chronology accepted")
			}
		})
	}
	if err := xrayAutoFetchChronologyCheck(base, at(950), 10*time.Second); err == nil {
		t.Fatal("future commit accepted")
	}
	if err := xrayAutoFetchChronologyCheck(base, at(1000), time.Second); err == nil {
		t.Fatal("quorum guard shortened")
	}
	if strings.Contains(fmt.Sprintf("%#v", base), "feed-original") {
		t.Fatal("private trace identity leaked")
	}
}
