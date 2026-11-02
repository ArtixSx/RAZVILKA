package startuptools

import (
	"os"
	"path/filepath"
	"reflect"
)

// Acquisition-derived pathname only. This establishes no current filesystem
// observation: the caller still observes the complete named node/link graph
// before and after every use, then opens and lists the original directory.
type reviewedExtensionPath struct {
	self             *reviewedExtensionPath
	review           *heldReview
	profile          profile
	alias, canonical string
	target           os.FileInfo
}

func (r *heldReview) retainExtensionPath(canonical string) error {
	if r == nil || r.extensionPath != nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return at("EXTENSION_PATH_SOURCE", nil)
	}
	n, ok := r.nodes[canonical]
	if !ok || n.path != canonical || n.info == nil || !n.info.IsDir() || n.link != "" {
		return at("EXTENSION_PATH_SOURCE", nil)
	}
	e := &reviewedExtensionPath{review: r, profile: cloneVersionProfile(r.profile), alias: r.profile.extension, canonical: canonical, target: n.info}
	e.self = e
	r.extensionPath = e
	return nil
}

func (r *heldReview) versionExtensionPath() (string, error) {
	if r == nil {
		return "", at("EXTENSION_PATH_SOURCE", nil)
	}
	e := r.extensionPath
	if e == nil || e.self != e || e.review != r || e.alias != r.profile.extension || !reflect.DeepEqual(e.profile, r.profile) {
		return "", at("EXTENSION_PATH_SOURCE", nil)
	}
	n, ok := r.nodes[e.canonical]
	if !ok || n.path != e.canonical || n.link != "" || n.info == nil || !n.info.IsDir() || !reflect.DeepEqual(n.info, e.target) {
		return "", at("EXTENSION_PATH_SOURCE", nil)
	}
	return e.canonical, nil
}
