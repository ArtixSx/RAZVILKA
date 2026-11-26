package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type strictConfigTarget interface {
	restorejournal.Target
	Close() error
}

// Only the offline operator owns this policy. It retains the original bounded
// context and one exact before image; it is neither a normal Store nor a
// recovery writer. The package-private opener permits failure tests around the
// real file target, not an externally supplied writer or alternate authority.
type strictExistingStore struct {
	ctx           context.Context
	before        Config
	attempted     bool
	writingManual bool
	openTarget    func(string) (strictConfigTarget, error)
}

// LoadExistingStrict reads an existing current-schema Store without migration
// or normalization. The caller must hold the deployment's actual offline
// lifetime leases. The resulting Store allows one transition from auto (or
// legacy empty mode) to manual through UpdateServiceControl, with no schedule
// or other configuration change. It creates no marker, directory or target.
// This is not an independent grant of recovery or runtime authority.
func LoadExistingStrict(ctx context.Context, path string) (*Store, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.TrimSpace(path) != path {
		return nil, restorejournal.ErrInvalid
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, restorejournal.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := restorejournal.OpenExistingFileTarget(path)
	if err != nil {
		return nil, err
	}
	// Capture the original bytes under the real existing file owner, including
	// its actual UID, marker and closing observation. A path-only read followed
	// by later admission would allow this strict loader to return an unowned
	// Store before the first CheckStrictImage call.
	image, readErr := target.Read(ctx)
	closeErr := target.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return nil, err
	}
	if !image.Exists {
		return nil, os.ErrNotExist
	}
	cfg, err := strictConfigImage(image.Data)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Store{
		path: path, cfg: cfg, diskImage: image,
		strict: &strictExistingStore{
			ctx: ctx, before: cloneConfig(cfg),
			openTarget: func(path string) (strictConfigTarget, error) {
				return restorejournal.OpenExistingFileTarget(path)
			},
		},
	}, nil
}

func strictConfigImage(data []byte) (Config, error) {
	if err := strictUniqueJSON(data); err != nil {
		return Config{}, restorejournal.ErrInvalid
	}
	inspected, report, err := InspectBytes(data)
	if err != nil || report.Changed || inspected.SchemaVersion != CurrentSchemaVersion {
		return Config{}, restorejournal.ErrInvalid
	}
	var decoded Config
	if json.Unmarshal(data, &decoded) != nil || !reflect.DeepEqual(decoded, inspected) {
		return Config{}, restorejournal.ErrInvalid
	}
	// A normal Store write must not silently drop explicit fields, change JSON
	// null/empty distinctions, or accept case-insensitive aliases. Whitespace
	// and property order are irrelevant; all actual JSON values remain exact.
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return Config{}, restorejournal.ErrInvalid
	}
	left, leftErr := strictJSONValue(data)
	right, rightErr := strictJSONValue(canonical)
	if leftErr != nil || rightErr != nil || !reflect.DeepEqual(left, right) {
		return Config{}, restorejournal.ErrInvalid
	}
	return decoded, nil
}

func strictJSONValue(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(d); err != nil {
		return nil, err
	}
	return value, nil
}

// encoding/json otherwise accepts duplicate properties by retaining only the
// last value. Reject them at every depth before binding a strict before image.
func strictUniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return restorejournal.ErrInvalid
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, valid := key.(string)
				if err != nil || !valid || seen[name] {
					return restorejournal.ErrInvalid
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return restorejournal.ErrInvalid
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return restorejournal.ErrInvalid
			}
		default:
			return restorejournal.ErrInvalid
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return restorejournal.ErrInvalid
	}
	return nil
}

func (s *Store) admitStrictManualLocked(mode *string, schedule *ServiceCheckSchedule, revision uint64) error {
	if s.writeUncertain {
		return restorejournal.ErrRecovery
	}
	if err := s.strict.ctx.Err(); err != nil {
		return err
	}
	if s.strict.attempted || s.strict.writingManual || mode == nil || *mode != "manual" || schedule != nil || s.cfg.ServiceControl.Mode == "manual" {
		return restorejournal.ErrInvalid
	}
	if s.cfg.Revision != revision || revision == ^uint64(0) || !reflect.DeepEqual(s.cfg, s.strict.before) {
		return ErrRevisionChanged
	}
	s.strict.attempted, s.strict.writingManual = true, true
	return nil
}

func (s *Store) saveStrictLocked(data []byte) (result error) {
	if s.strict == nil || !s.strict.writingManual || !s.strict.attempted {
		return restorejournal.ErrInvalid
	}
	if err := s.strict.ctx.Err(); err != nil {
		return err
	}
	wanted := cloneConfig(s.strict.before)
	wanted.ServiceControl.Mode = "manual"
	wanted.Revision++
	if !reflect.DeepEqual(s.cfg, wanted) {
		return restorejournal.ErrInvalid
	}
	target, err := s.strict.openTarget(s.path)
	if err != nil {
		return err
	}
	defer func() {
		if err := target.Close(); err != nil {
			// Close verifies the original directory/marker before releasing the
			// real lease. A failed closing observation cannot certify a write.
			s.writeUncertain = true
			result = errors.Join(result, restorejournal.ErrRecovery, err)
		}
		if err := s.strict.ctx.Err(); err != nil {
			s.writeUncertain = true
			result = errors.Join(result, restorejournal.ErrRecovery, err)
		}
	}()
	if err := s.persistLockedContext(s.strict.ctx, target, data); err != nil {
		return err
	}
	actual, err := target.Read(s.strict.ctx)
	if err != nil || !actual.Exists || !bytes.Equal(actual.Data, data) || s.strict.ctx.Err() != nil {
		s.writeUncertain = true
		return errors.Join(restorejournal.ErrRecovery, err, s.strict.ctx.Err())
	}
	return nil
}

// CheckStrictImage compares the real file with this exact Store's current raw
// image under the pre-existing file lease. It never reloads, normalizes, writes,
// renews the original context, or converts an uncertain write into success.
func (s *Store) CheckStrictImage() (result error) {
	if s == nil {
		return restorejournal.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.strict == nil {
		return restorejournal.ErrInvalid
	}
	if s.writeUncertain {
		return restorejournal.ErrRecovery
	}
	if err := s.strict.ctx.Err(); err != nil {
		return err
	}
	target, err := s.strict.openTarget(s.path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, target.Close(), s.strict.ctx.Err()) }()
	image, err := target.Read(s.strict.ctx)
	if err != nil {
		return err
	}
	if !image.Exists || !bytes.Equal(image.Data, s.diskImage.Data) {
		return restorejournal.ErrConflict
	}
	return s.strict.ctx.Err()
}

// StrictImageSHA256 identifies the same retained image used by CAS and closing
// readback. It reads no new disk image and exposes no configuration contents.
func (s *Store) StrictImageSHA256() (string, error) {
	if s == nil {
		return "", restorejournal.ErrInvalid
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.strict == nil {
		return "", restorejournal.ErrInvalid
	}
	if s.writeUncertain {
		return "", restorejournal.ErrRecovery
	}
	if err := s.strict.ctx.Err(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(s.diskImage.Data)
	return hex.EncodeToString(sum[:]), nil
}
