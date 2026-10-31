//go:build linux && razvilka_native_fixture

package components

// Explicit CI-only original installation issuer. The manifest's architecture
// classification is modeled; executable/assets, installer, generation hashes,
// journal, writer lease, receipt and runtime reader are actual. This file is
// absent from ordinary builds and cannot approve a router deployment.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
)

type nativeFixtureReview struct {
	BinaryPath, BinarySHA256 string
	Assets                   []struct{ Path, SHA256 string }
	BaseArguments            []string
}
type nativeFixtureTransport struct {
	data []byte
	url  string
}

func (t nativeFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "GET" || r.URL.String() != t.url {
		return nil, ErrManagedNFQWSBundle
	}
	return &http.Response{StatusCode: 200, ContentLength: int64(len(t.data)), Body: io.NopCloser(bytes.NewReader(t.data)), Request: r}, nil
}

func nativeFixtureTar(entries []struct {
	name string
	data []byte
}) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0755, Size: int64(len(e.data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// InstallNativeFixtureManagedNFQWS seals actual explicitly reviewed artifact
// bytes through the ordinary installer, including its caller's real control
// admission/inactivity proof. No provided descriptor or receipt is installed.
func InstallNativeFixtureManagedNFQWS(ctx context.Context, base, reviewPath string, revision uint64, authority ManagedNFQWSBundleAuthority) (*Manager, error) {
	ns, err := os.Readlink("/proc/self/ns/net")
	init, e2 := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || err != nil || e2 != nil || ns == init || !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return nil, ErrManagedNFQWSBundle
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode().Perm()&077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrManagedNFQWSBundle
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		return nil, ErrManagedNFQWSBundle
	}
	raw, err := os.ReadFile(reviewPath)
	if err != nil || len(raw) > 64<<10 {
		return nil, ErrManagedNFQWSBundle
	}
	var review nativeFixtureReview
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&review) != nil || d.Decode(new(any)) != io.EOF || len(review.Assets) != 5 {
		return nil, ErrManagedNFQWSBundle
	}
	manifest, err := ReviewedManagedNFQWSManifest("arm64")
	if err != nil {
		return nil, err
	}
	manifest.Flavor = "ci-only-native-platform-classification-modeled"
	manifest.ABI = "CI ONLY: actual reviewed native artifact; ARM64 classification modeled"
	manifest.SourceRepo = "https://github.com/bol-van/zapret2"
	manifest.Tag = "v1.0.6"
	manifest.SourceCommit = "221d7dff24bfec0cd5ac0a5070b8acef2008af3d"
	manifest.ParentAssetURL = "https://fixture.invalid/ci-only-sealed-native-wrapper.ipk"
	paths := []struct{ Path, SHA256 string }{{review.BinaryPath, review.BinarySHA256}}
	paths = append(paths, review.Assets...)
	var archiveEntries []struct {
		name string
		data []byte
	}
	for i, path := range paths {
		before, err := os.Lstat(path.Path)
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&022 != 0 || !bundleHash(path.SHA256, 64) || before.Size() <= 0 || before.Size() > 16<<20 {
			return nil, ErrManagedNFQWSBundle
		}
		data, err := os.ReadFile(path.Path)
		after, e := os.Lstat(path.Path)
		if err != nil || e != nil || !os.SameFile(before, after) || digest(data) != path.SHA256 {
			return nil, ErrManagedNFQWSBundle
		}
		member := &manifest.Members[i]
		member.RawSHA256 = path.SHA256
		member.RawSize = int64(len(data))
		encoded := data
		if member.Gzip {
			var compressed bytes.Buffer
			gz := gzip.NewWriter(&compressed)
			if _, err := gz.Write(data); err != nil {
				return nil, err
			}
			if err := gz.Close(); err != nil {
				return nil, err
			}
			encoded = compressed.Bytes()
		}
		member.SHA256 = digest(encoded)
		member.Size = int64(len(encoded))
		archiveEntries = append(archiveEntries, struct {
			name string
			data []byte
		}{member.Path, encoded})
	}
	dataTar, err := nativeFixtureTar(archiveEntries)
	if err != nil {
		return nil, err
	}
	controlTar, err := nativeFixtureTar(nil)
	if err != nil {
		return nil, err
	}
	input, err := nativeFixtureTar([]struct {
		name string
		data []byte
	}{{"control.tar.gz", controlTar}, {"data.tar.gz", dataTar}, {"debian-binary", []byte("2.0\n")}})
	if err != nil {
		return nil, err
	}
	manifest.ParentAssetSize = int64(len(input))
	manifest.ParentSHA256 = digest(input)
	expected, err := manifest.Digest()
	if err != nil {
		return nil, err
	}
	m := &Manager{StateDir: filepath.Join(base, "state"), nfqwsReleases: filepath.Join(base, "releases"), Arch: "arm64", Client: &http.Client{Transport: nativeFixtureTransport{input, manifest.ParentAssetURL}}}
	m.nfqwsFixture = &managedNFQWSFixtureBoundary{base, info}
	m.nfqwsReview = func(actual ManagedNFQWSManifest) error {
		hash, err := actual.Digest()
		if err != nil || hash != expected || !reflect.DeepEqual(actual, manifest) {
			return ErrManagedNFQWSBundle
		}
		for _, path := range paths {
			data, err := os.ReadFile(path.Path)
			if err != nil || digest(data) != path.SHA256 {
				return errors.Join(ErrManagedNFQWSBundle, err)
			}
		}
		return nil
	}
	if _, err := m.InstallManagedBundle(ctx, manifest, revision, authority); err != nil {
		return nil, err
	}
	return m, nil
}
