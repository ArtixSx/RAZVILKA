package sources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrServiceCIDRReview = errors.New("original applied canonical CIDR source changed or unavailable")

const (
	serviceReviewMaxSources = 16
	serviceReviewMaxCIDRs   = 512
	serviceReviewMaxBytes   = 256 << 10
)

// Comparison data only. No receipt, readiness, health or effect authority is
// created by reading an applied source's existing cache.
type ServiceCIDRRevision struct {
	SourceID, SourceHash, ContentSHA256, RawSHA256 string
	URL, FinalURL, TrustTier                       string
	FetchedAt, ExpiresAt                           time.Time
}

type ServiceCIDRObservation struct {
	ServiceID        string
	SourceIDs, CIDRs []string
	Revisions        []ServiceCIDRRevision
}

type serviceReviewDirectory struct {
	path string
	info os.FileInfo
}
type serviceReviewFile struct {
	source    Source
	cache     cacheDocument
	info      os.FileInfo
	bytesHash string
}

// Only the original Manager issues a review. It retains opened descriptors and
// immutable cache/config images; there is no constructor from observation DTOs.
type ServiceCIDRReview struct {
	self            *ServiceCIDRReview
	mu              sync.Mutex
	closed, invalid bool
	closeErr        error
	manager         *Manager
	root            string
	owned           *ownedfs.Root
	directories     []serviceReviewDirectory
	service         string
	ids             []string
	files           []serviceReviewFile
	observation     ServiceCIDRObservation
}

func (*ServiceCIDRReview) String() string   { return "[original applied CIDR source review]" }
func (*ServiceCIDRReview) GoString() string { return "[original applied CIDR source review]" }

// IDs select existing sources only, never expected provenance or permission.
// Require the complete applied enrichment set: an unheld source cannot silently
// add destinations or change provenance while producing the same CIDR union.
// This reads local files only; it does not fetch, upgrade legacy caches or write.
func (m *Manager) ReviewServiceCIDRs(ctx context.Context, serviceID string, sourceIDs []string) (*ServiceCIDRReview, error) {
	if err := serviceReviewContext(ctx); err != nil {
		return nil, errors.Join(ErrServiceCIDRReview, err)
	}
	if m == nil || serviceID == "" || len(serviceID) > 64 || strings.TrimSpace(serviceID) != serviceID || strings.ToLower(serviceID) != serviceID || len(sourceIDs) == 0 || len(sourceIDs) > serviceReviewMaxSources {
		return nil, ErrServiceCIDRReview
	}
	ids := slices.Clone(sourceIDs)
	slices.Sort(ids)
	for i, id := range ids {
		if !validSourceID(id) || i > 0 && ids[i-1] == id {
			return nil, ErrServiceCIDRReview
		}
	}
	root := m.cacheDir
	dirs, err := serviceReviewDirectories(root)
	if err != nil {
		return nil, errors.Join(ErrServiceCIDRReview, err)
	}
	owned, err := ownedfs.Open(root)
	if err != nil {
		return nil, errors.Join(ErrServiceCIDRReview, err)
	}
	r := &ServiceCIDRReview{manager: m, root: root, owned: owned, directories: dirs, service: serviceID, ids: ids}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	m.mu.RLock()
	srcs, err := r.appliedSourcesLocked()
	if err == nil {
		for _, src := range srcs {
			var f serviceReviewFile
			f, err = r.readFile(ctx, src)
			if err != nil {
				break
			}
			r.files = append(r.files, f)
		}
	}
	m.mu.RUnlock()
	if err != nil {
		return nil, errors.Join(ErrServiceCIDRReview, err)
	}
	obs := ServiceCIDRObservation{ServiceID: serviceID, SourceIDs: slices.Clone(ids)}
	for _, f := range r.files {
		obs.CIDRs = append(obs.CIDRs, strings.Split(strings.TrimSuffix(f.cache.Content, "\n"), "\n")...)
		c := f.cache
		obs.Revisions = append(obs.Revisions, ServiceCIDRRevision{SourceID: c.ID, SourceHash: c.SourceHash, ContentSHA256: c.SHA256, RawSHA256: c.Provenance.RawSHA256,
			URL: c.Provenance.URL, FinalURL: c.Provenance.FinalURL, TrustTier: c.Provenance.TrustTier, FetchedAt: c.FetchedAt, ExpiresAt: c.ExpiresAt})
	}
	obs.CIDRs = uniqueSorted(obs.CIDRs)
	if len(obs.CIDRs) == 0 || len(obs.CIDRs) > serviceReviewMaxCIDRs {
		return nil, ErrServiceCIDRReview
	}
	r.observation = obs
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	keep = true
	return r, nil
}

// Called with the original Manager read lock. Draft-only edits do not change
// the applied set. Each selected entry must be actual fresh schema-2 state.
func (r *ServiceCIDRReview) appliedSourcesLocked() ([]Source, error) {
	if r.manager.cacheDir != r.root {
		return nil, ErrServiceCIDRReview
	}
	var srcs []Source
	for _, src := range r.manager.reg.Sources {
		if !r.manager.settings.Applied[src.ID] || src.Kind == "reference" || !containsFold(src.Services, r.service) {
			continue
		}
		if src.Kind != "cidrs" || !slices.Contains(r.ids, src.ID) || validateSource(src) != nil {
			return nil, ErrServiceCIDRReview
		}
		state := currentState(r.manager.states[src.ID], time.Now())
		if !state.Ready || state.LegacyCache || state.LastKnownGood || state.CacheStatus != "fresh" || state.LastError != "" {
			return nil, ErrServiceCIDRReview
		}
		src.Services, src.RedirectHosts = slices.Clone(src.Services), slices.Clone(src.RedirectHosts)
		srcs = append(srcs, src)
	}
	slices.SortFunc(srcs, func(a, b Source) int { return strings.Compare(a.ID, b.ID) })
	if len(srcs) != len(r.ids) {
		return nil, ErrServiceCIDRReview
	}
	for i, src := range srcs {
		if src.ID != r.ids[i] {
			return nil, ErrServiceCIDRReview
		}
	}
	return srcs, nil
}

func serviceReviewDirectories(path string) ([]serviceReviewDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == filepath.VolumeName(path)+string(filepath.Separator) {
		return nil, ErrServiceCIDRReview
	}
	var dirs []serviceReviewDirectory
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !serviceReviewDirectoryOwner(info, len(dirs) == 0) {
			return nil, errors.Join(ErrServiceCIDRReview, err)
		}
		dirs = append(dirs, serviceReviewDirectory{p, info})
		if filepath.Dir(p) == p {
			break
		}
	}
	return dirs, nil
}

func (r *ServiceCIDRReview) originalRoot() error {
	for _, d := range r.directories {
		actual, err := os.Lstat(d.path)
		if err != nil || !actual.IsDir() || actual.Mode()&os.ModeSymlink != 0 || !os.SameFile(actual, d.info) || !serviceReviewSameOwner(d.info, actual) {
			return errors.Join(ErrServiceCIDRReview, err)
		}
	}
	actual, err := r.owned.RootInfo()
	if err != nil || !os.SameFile(actual, r.directories[0].info) {
		return errors.Join(ErrServiceCIDRReview, err)
	}
	return nil
}

func (r *ServiceCIDRReview) readFile(ctx context.Context, src Source) (serviceReviewFile, error) {
	if err := errors.Join(serviceReviewContext(ctx), r.originalRoot()); err != nil {
		return serviceReviewFile{}, err
	}
	name := src.ID + ".cache.json"
	f, err := r.owned.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return serviceReviewFile{}, err
	} // Never fall back to .lst.
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !serviceReviewFileOwner(info) || info.Size() > serviceReviewMaxBytes {
		return serviceReviewFile{}, ErrServiceCIDRReview
	}
	data, err := io.ReadAll(io.LimitReader(f, serviceReviewMaxBytes+1))
	if err != nil || len(data) > serviceReviewMaxBytes {
		return serviceReviewFile{}, ErrServiceCIDRReview
	}
	var c cacheDocument
	if serviceReviewDecode(data, &c) != nil || c.Schema != 2 {
		return serviceReviewFile{}, ErrServiceCIDRReview
	}
	// Existing cache validation retains its original public-origin/pin/canonical
	// content checks. Comparing this result closes on the SAME descriptor bytes.
	validated, err := r.manager.readCache(src)
	if err != nil || !reflect.DeepEqual(c, validated) || c.FetchedAt.After(time.Now()) || !time.Now().Before(c.ExpiresAt) || c.Entries == 0 || c.Entries > serviceReviewMaxCIDRs {
		return serviceReviewFile{}, ErrServiceCIDRReview
	}
	for _, raw := range strings.Split(strings.TrimSuffix(c.Content, "\n"), "\n") {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Masked().String() != raw || p.Bits() == 0 {
			return serviceReviewFile{}, ErrServiceCIDRReview
		}
	}
	state := r.manager.states[src.ID]
	if state.SHA256 != c.SHA256 || !state.UpdatedAt.Equal(c.FetchedAt) || !state.ExpiresAt.Equal(c.ExpiresAt) || state.Provenance == nil || !reflect.DeepEqual(*state.Provenance, c.Provenance) {
		return serviceReviewFile{}, ErrServiceCIDRReview
	}
	if err := r.quarantine(src, c.FetchedAt); err != nil {
		return serviceReviewFile{}, err
	}
	actual, err := r.owned.Stat(name)
	if err != nil || !os.SameFile(info, actual) || !serviceReviewSameOwner(info, actual) {
		return serviceReviewFile{}, ErrServiceCIDRReview
	}
	if err := errors.Join(serviceReviewContext(ctx), r.originalRoot()); err != nil {
		return serviceReviewFile{}, err
	}
	return serviceReviewFile{src, c, info, contentHash(data)}, nil
}

func (r *ServiceCIDRReview) quarantine(src Source, fetched time.Time) error {
	data, err := r.owned.ReadLimited(src.ID+".quarantine.json", 8192)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var q quarantineDocument
	if err != nil || serviceReviewDecode(data, &q) != nil || q.Schema != 2 || q.SourceHash != sourceHash(src) || q.CheckedAt.IsZero() || q.CheckedAt.After(fetched) {
		return ErrServiceCIDRReview
	}
	return nil
}

// Reject unknown/duplicate keys and trailing values at the authority boundary,
// without changing the older display/cache readers' compatibility behavior.
func serviceReviewDecode(data []byte, out any) error {
	d := json.NewDecoder(strings.NewReader(string(data)))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return ErrServiceCIDRReview
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				key, ok := k.(string)
				if err != nil || !ok || seen[key] {
					return ErrServiceCIDRReview
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrServiceCIDRReview
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrServiceCIDRReview
	}
	d = json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func serviceReviewContext(ctx context.Context) error {
	if ctx == nil {
		return ErrServiceCIDRReview
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrServiceCIDRReview
	}
	return nil
}

func (r *ServiceCIDRReview) Current(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrServiceCIDRReview
	}
	if err := serviceReviewContext(ctx); err != nil {
		return errors.Join(ErrServiceCIDRReview, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.invalid {
		return ErrServiceCIDRReview
	}
	err := r.current(ctx)
	if err != nil {
		r.invalid = true
		return errors.Join(ErrServiceCIDRReview, err)
	}
	return nil
}

func (r *ServiceCIDRReview) current(ctx context.Context) error {
	r.manager.mu.RLock()
	defer r.manager.mu.RUnlock()
	srcs, err := r.appliedSourcesLocked()
	if err != nil || len(srcs) != len(r.files) {
		return ErrServiceCIDRReview
	}
	for i, src := range srcs {
		old := r.files[i]
		if !reflect.DeepEqual(src, old.source) {
			return ErrServiceCIDRReview
		}
		actual, err := r.readFile(ctx, src)
		if err != nil || actual.bytesHash != old.bytesHash || !os.SameFile(actual.info, old.info) || !serviceReviewSameOwner(old.info, actual.info) || !reflect.DeepEqual(actual.cache, old.cache) {
			return ErrServiceCIDRReview
		}
	}
	return errors.Join(serviceReviewContext(ctx), r.originalRoot())
}

func (r *ServiceCIDRReview) Observation(ctx context.Context) (ServiceCIDRObservation, error) {
	if err := r.Current(ctx); err != nil {
		return ServiceCIDRObservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.invalid {
		return ServiceCIDRObservation{}, ErrServiceCIDRReview
	}
	o := r.observation
	o.SourceIDs, o.CIDRs, o.Revisions = slices.Clone(o.SourceIDs), slices.Clone(o.CIDRs), slices.Clone(o.Revisions)
	return o, nil
}

func (r *ServiceCIDRReview) Close() error {
	if r == nil || r.self != r {
		return ErrServiceCIDRReview
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	r.closeErr = r.owned.Close()
	return r.closeErr
}
