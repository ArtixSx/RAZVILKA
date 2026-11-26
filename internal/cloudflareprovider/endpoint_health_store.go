package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrEndpointHealthStore = errors.New("Cloudflare endpoint health journal is unavailable or invalid")

const (
	endpointHealthFile       = "endpoint-health.private.json"
	endpointHealthSchema     = 1
	maxEndpointHealthRecords = MaxAccounts * 8
	maxEndpointHealthBytes   = 512 << 10
)

type storedEndpointHealth struct {
	AccountID           string             `json:"account_id"`
	AccountDigest       string             `json:"account_digest"`
	RoutePathID         string             `json:"route_path_id"`
	Endpoint            string             `json:"endpoint"`
	Catalog             EndpointAssessment `json:"catalog"`
	State               string             `json:"state"`
	Score               int                `json:"score"`
	ConsecutiveFailures int                `json:"consecutive_failures"`
	LastTestedAt        time.Time          `json:"last_tested_at"`
	LastVerifiedAt      time.Time          `json:"last_verified_at,omitempty"`
	EvidenceValidUntil  time.Time          `json:"evidence_valid_until,omitempty"`
	CooldownUntil       time.Time          `json:"cooldown_until,omitempty"`
}

type endpointHealthDocument struct {
	Schema     int                    `json:"schema"`
	Owner      string                 `json:"owner"`
	Generation uint64                 `json:"generation"`
	Records    []storedEndpointHealth `json:"records"`
}

// RecordEndpointHealth atomically commits only state derived from this
// process's candidate and ScanReport proofs. The account snapshot and health
// journal share the Provider writer lock, so a restore/import cannot change the
// account between identity validation and commit.
func (s *Store) RecordEndpointHealth(ctx context.Context, accountID string, options CandidateOptions, report ScanReport) (EndpointHealth, error) {
	if !report.valid || report.evaluatedAt.IsZero() {
		return EndpointHealth{}, ErrEndpointHealth
	}
	now := report.evaluatedAt.UTC()
	release, err := s.lockWrite(ctx)
	if err != nil {
		return EndpointHealth{}, err
	}
	defer release()
	candidate, record, err := s.candidatePreviewLocked(ctx, accountID, options)
	if err != nil {
		return EndpointHealth{}, err
	}
	doc, err := readEndpointHealthDocument(ctx, s.root, now)
	if err != nil {
		return EndpointHealth{}, err
	}
	var previous EndpointHealth
	for _, item := range doc.Records {
		if item.RoutePathID == candidate.RoutePathID {
			previous, err = restoreEndpointHealth(item, candidate, now)
			if err != nil {
				return EndpointHealth{}, err
			}
			break
		}
	}
	health, err := UpdateEndpointHealth(previous, candidate, report, now)
	if err != nil {
		return EndpointHealth{}, err
	}
	next := make([]storedEndpointHealth, 0, len(doc.Records)+1)
	for _, item := range doc.Records {
		// A changed MTU/keepalive creates a new identity but must not leave an
		// unlimited history for the same account endpoint.
		if item.AccountID == accountID && item.Endpoint == candidate.Endpoint {
			continue
		}
		next = append(next, item)
	}
	if len(next) >= maxEndpointHealthRecords || doc.Generation == ^uint64(0) {
		return EndpointHealth{}, ErrEndpointHealthStore
	}
	doc.Generation++
	doc.Records = append(next, storeEndpointHealth(health, record.ID, record.Digest))
	if err := commitEndpointHealthDocument(ctx, s.root, doc, now); err != nil {
		return EndpointHealth{}, err
	}
	return health, nil
}

// LoadEndpointHealth restores trust only after rebuilding the candidate from
// the current private account snapshot and matching its complete identity.
// Expired evidence can be shown diagnostically but Selectable remains false.
func (s *Store) LoadEndpointHealth(ctx context.Context, accountID string, options CandidateOptions, now time.Time) (EndpointHealth, bool, error) {
	if now.IsZero() {
		return EndpointHealth{}, false, ErrEndpointHealthStore
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return EndpointHealth{}, false, err
	}
	candidate, _, err := s.candidatePreviewLocked(ctx, accountID, options)
	if err != nil {
		return EndpointHealth{}, false, err
	}
	doc, err := readEndpointHealthDocument(ctx, s.root, now)
	if err != nil {
		return EndpointHealth{}, false, err
	}
	for _, item := range doc.Records {
		if item.RoutePathID != candidate.RoutePathID {
			continue
		}
		health, restoreErr := restoreEndpointHealth(item, candidate, now)
		return health, true, restoreErr
	}
	return EndpointHealth{}, false, nil
}

// candidatePreviewLocked requires s.mu and, for mutations, the OS writer lock.
func (s *Store) candidatePreviewLocked(ctx context.Context, accountID string, options CandidateOptions) (CandidatePreview, storedAccount, error) {
	doc, err := s.loadContext(ctx)
	if err != nil {
		return CandidatePreview{}, storedAccount{}, err
	}
	for _, record := range doc.Accounts {
		if record.ID != accountID {
			continue
		}
		if record.Kind != SourceLocalRegistration {
			return CandidatePreview{}, storedAccount{}, ErrTunnelMaterialUnavailable
		}
		material, decodeErr := decodeTunnelMaterial(record.Raw)
		if decodeErr != nil {
			return CandidatePreview{}, storedAccount{}, ErrStore
		}
		material.binding = record.Digest
		defer material.erase()
		candidate, candidateErr := wireGuardCandidateFromMaterial(record.ID, material, options)
		if candidateErr != nil {
			return CandidatePreview{}, storedAccount{}, candidateErr
		}
		view := candidate.Public()
		candidate.erase()
		return view, record, nil
	}
	return CandidatePreview{}, storedAccount{}, ErrAccountNotFound
}

func storeEndpointHealth(health EndpointHealth, accountID, accountDigest string) storedEndpointHealth {
	return storedEndpointHealth{
		AccountID: accountID, AccountDigest: accountDigest,
		RoutePathID: health.RoutePathID, Endpoint: health.Endpoint, Catalog: health.Catalog,
		State: health.State, Score: health.Score, ConsecutiveFailures: health.ConsecutiveFailures,
		LastTestedAt: health.LastTestedAt, LastVerifiedAt: health.LastVerifiedAt,
		EvidenceValidUntil: health.EvidenceValidUntil, CooldownUntil: health.CooldownUntil,
	}
}

func restoreEndpointHealth(item storedEndpointHealth, candidate CandidatePreview, now time.Time) (EndpointHealth, error) {
	if item.AccountID != candidate.AccountID || item.AccountDigest != candidate.materialBinding || item.RoutePathID != candidate.RoutePathID ||
		item.Endpoint != candidate.Endpoint || item.Catalog != candidate.EndpointCatalog {
		return EndpointHealth{}, ErrEndpointHealthStore
	}
	health := EndpointHealth{
		RoutePathID: item.RoutePathID, Endpoint: item.Endpoint, Catalog: item.Catalog,
		State: item.State, Score: item.Score, ConsecutiveFailures: item.ConsecutiveFailures,
		LastTestedAt: item.LastTestedAt, LastVerifiedAt: item.LastVerifiedAt,
		EvidenceValidUntil: item.EvidenceValidUntil, CooldownUntil: item.CooldownUntil, valid: true,
	}
	if !validRestoredEndpointHealth(health, now) {
		return EndpointHealth{}, ErrEndpointHealthStore
	}
	return health, nil
}

func validRestoredEndpointHealth(health EndpointHealth, now time.Time) bool {
	if health.RoutePathID == "" || health.Endpoint == "" || health.Catalog.Endpoint != health.Endpoint || health.LastTestedAt.IsZero() || health.LastTestedAt.After(now.Add(5*time.Minute)) ||
		health.Score < 0 || health.Score > 100 || health.ConsecutiveFailures < 0 {
		return false
	}
	switch health.State {
	case EndpointHealthVerified:
		return health.Score > 0 && health.ConsecutiveFailures == 0 && !health.LastVerifiedAt.IsZero() && !health.EvidenceValidUntil.IsZero() &&
			health.EvidenceValidUntil.After(health.LastVerifiedAt) && !health.EvidenceValidUntil.After(health.LastTestedAt.Add(24*time.Hour)) && health.CooldownUntil.IsZero()
	case EndpointHealthCooldown:
		return health.ConsecutiveFailures > 0 && health.EvidenceValidUntil.IsZero() && !health.CooldownUntil.IsZero() && health.CooldownUntil.After(health.LastTestedAt) &&
			!health.CooldownUntil.After(health.LastTestedAt.Add(30*time.Minute))
	default:
		return false
	}
}

func readEndpointHealthDocument(ctx context.Context, root *ownedfs.Root, now time.Time) (endpointHealthDocument, error) {
	doc := endpointHealthDocument{Schema: endpointHealthSchema, Owner: "razvilka", Records: []storedEndpointHealth{}}
	if err := ctx.Err(); err != nil {
		return endpointHealthDocument{}, err
	}
	info, err := root.Stat(endpointHealthFile)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil || !validWriterFile(info) || info.Size() > maxEndpointHealthBytes {
		return endpointHealthDocument{}, ErrEndpointHealthStore
	}
	file, err := root.OpenFile(endpointHealthFile, os.O_RDONLY, 0)
	if err != nil {
		return endpointHealthDocument{}, ErrEndpointHealthStore
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !validWriterFile(actual) || !os.SameFile(info, actual) {
		return endpointHealthDocument{}, ErrEndpointHealthStore
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEndpointHealthBytes+1))
	if err != nil || len(data) > maxEndpointHealthBytes {
		return endpointHealthDocument{}, ErrEndpointHealthStore
	}
	decoded := endpointHealthDocument{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateEndpointHealthDocument(decoded, now) != nil {
		return endpointHealthDocument{}, ErrEndpointHealthStore
	}
	return decoded, nil
}

func validateEndpointHealthDocument(doc endpointHealthDocument, now time.Time) error {
	if doc.Schema != endpointHealthSchema || doc.Owner != "razvilka" || len(doc.Records) > maxEndpointHealthRecords || now.IsZero() {
		return ErrEndpointHealthStore
	}
	seen := map[string]bool{}
	for _, item := range doc.Records {
		_, digestErr := hex.DecodeString(item.AccountDigest)
		if !validID(item.AccountID) || len(item.AccountDigest) != 64 || digestErr != nil || !strings.HasPrefix(item.RoutePathID, "cloudflare-wg:") || seen[item.RoutePathID] {
			return ErrEndpointHealthStore
		}
		seen[item.RoutePathID] = true
		health := EndpointHealth{
			RoutePathID: item.RoutePathID, Endpoint: item.Endpoint, Catalog: item.Catalog,
			State: item.State, Score: item.Score, ConsecutiveFailures: item.ConsecutiveFailures,
			LastTestedAt: item.LastTestedAt, LastVerifiedAt: item.LastVerifiedAt,
			EvidenceValidUntil: item.EvidenceValidUntil, CooldownUntil: item.CooldownUntil,
		}
		if !validRestoredEndpointHealth(health, now) {
			return ErrEndpointHealthStore
		}
	}
	return nil
}

func commitEndpointHealthDocument(ctx context.Context, root *ownedfs.Root, doc endpointHealthDocument, now time.Time) error {
	if err := validateEndpointHealthDocument(doc, now); err != nil {
		return err
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) > maxEndpointHealthBytes {
		return ErrEndpointHealthStore
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.WriteAtomic(endpointHealthFile, data, 0o600); err != nil {
		return restorejournal.ErrRecovery
	}
	if runtime.GOOS == "linux" && root.Sync() != nil {
		return restorejournal.ErrRecovery
	}
	return nil
}
