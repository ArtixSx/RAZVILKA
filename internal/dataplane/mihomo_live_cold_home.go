package dataplane

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/components"
)

// Inert comparison history only. Neither absence nor copied bytes construct a
// warm owner, permit deletion, or replace complete offline negative authority.
type mihomoColdHomeArchive struct {
	Schema         int                                `json:"schema"`
	State          string                             `json:"state"`
	Reference      components.MihomoLiveHomeReference `json:"reference"`
	ObservedParent string                             `json:"observed_parent"`
	OriginalParent bool                               `json:"original_parent"`
	Receipt        []byte                             `json:"receipt,omitempty"`
	Files          map[string][]byte                  `json:"files,omitempty"`
	Identities     map[string]string                  `json:"identities,omitempty"`
	Directories    map[string]string                  `json:"directories,omitempty"`
}

const mihomoColdHomeLimit = 4 << 20

// Validate saved documentary bytes without issuing absence, native ownership,
// or a path operation. Recovery still needs its independent genuine observer.
func validateMihomoColdHomeArchive(d ExecutionMihomoLiveDefinition, h mihomoColdHomeArchive) error {
	if d.validate() != nil || d.NativeHome == nil || h.Schema != 1 || h.Reference != *d.NativeHome || h.Reference.Parent != filepath.Clean(os.TempDir()) || !strings.HasPrefix(h.Reference.Name, ".razvilka-mihomo-live-") || !validMihomoColdHomeHex(strings.TrimPrefix(h.Reference.Name, ".razvilka-mihomo-live-")) {
		return ErrMihomoLiveRetirement
	}
	p, ok := mihomoColdHomeNumbers(h.ObservedParent, 5)
	if !ok || p[1] == 0 || p[2] != uint64(os.Geteuid()) || p[4] == 0 || h.OriginalParent != (p[0] == h.Reference.ParentDevice && p[1] == h.Reference.ParentInode) {
		return ErrMihomoLiveRetirement
	}
	if h.State == "absent" {
		if len(h.Receipt)+len(h.Files)+len(h.Identities)+len(h.Directories) != 0 {
			return ErrMihomoLiveRetirement
		}
		return nil
	}
	if h.State != "present" || !h.OriginalParent || len(h.Files) == 0 || len(h.Files) > 128 || len(h.Identities) != len(h.Files) || len(h.Directories) == 0 || len(h.Directories) > 32 || !bytes.Equal(h.Receipt, h.Files[".razvilka-origin-v1.json"]) {
		return ErrMihomoLiveRetirement
	}
	total := 0
	for name, raw := range h.Files {
		if !mihomoColdHomeLocalName(name) || name == "." || h.Directories[name] != "" || h.Directories[path.Dir(name)] == "" || len(raw) > mihomoColdHomeLimit-total {
			return ErrMihomoLiveRetirement
		}
		total += len(raw)
		parts, ok := mihomoColdHomeSavedNode(h.Identities[name], false)
		if !ok || parts[6] != uint64(len(raw)) {
			return ErrMihomoLiveRetirement
		}
	}
	for name, identity := range h.Directories {
		if !mihomoColdHomeLocalName(name) || name != "." && (strings.Count(name, "/") >= 4 || h.Directories[path.Dir(name)] == "") {
			return ErrMihomoLiveRetirement
		}
		parts, ok := mihomoColdHomeSavedNode(identity, true)
		if !ok || name == "." && (parts[0] != h.Reference.Device || parts[1] != h.Reference.Inode) {
			return ErrMihomoLiveRetirement
		}
	}
	return validateMihomoColdHomeReceipt(d, h)
}

func validateMihomoColdHomeReceipt(d ExecutionMihomoLiveDefinition, h mihomoColdHomeArchive) error {
	var receipt components.MihomoLiveHomeReceipt
	decoder := json.NewDecoder(bytes.NewReader(h.Receipt))
	decoder.DisallowUnknownFields()
	ref := h.Reference
	if len(h.Receipt) == 0 || len(h.Receipt) > 16<<10 || nfqws2ManagedUniqueJSON(h.Receipt) != nil || decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF || receipt.Schema != 1 || !validMihomoColdHomeHex(receipt.Nonce) || nodeDefaultSourceMaterialHash(h.Receipt) != ref.ReceiptSHA256 || !reflect.DeepEqual(receipt.Source, d.Source) || receipt.ProfileSHA != d.Profile.ConfigSHA256 || receipt.ParentDevice != ref.ParentDevice || receipt.ParentInode != ref.ParentInode || receipt.Device != ref.Device || receipt.Inode != ref.Inode {
		return ErrMihomoLiveRetirement
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, h.Receipt) {
		return ErrMihomoLiveRetirement
	}
	return nil
}

func mihomoColdHomeNumbers(s string, count int) ([]uint64, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != count {
		return nil, false
	}
	values := make([]uint64, count)
	for i, p := range parts {
		value, err := strconv.ParseUint(p, 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != p {
			return nil, false
		}
		values[i] = value
	}
	return values, true
}

func mihomoColdHomeSavedNode(s string, directory bool) ([]uint64, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 10 {
		return nil, false
	}
	values, ok := mihomoColdHomeNumbers(strings.Join(parts[:7], ":"), 7)
	if !ok || values[1] == 0 || values[2] != uint64(os.Geteuid()) || values[4] == 0 || !directory && values[4] != 1 || values[5] > 1<<32-1 || values[6] > 1<<63-1 {
		return nil, false
	}
	mode := os.FileMode(values[5])
	typeBits := os.FileMode(0)
	if directory {
		typeBits = os.ModeDir
	}
	if mode.Perm()&0077 != 0 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || mode&os.ModeType != typeBits {
		return nil, false
	}
	for _, p := range parts[7:9] {
		value, err := strconv.ParseInt(p, 10, 64)
		if err != nil || strconv.FormatInt(value, 10) != p {
			return nil, false
		}
	}
	ns, err := strconv.ParseUint(parts[9], 10, 32)
	return values, err == nil && ns < 1e9 && strconv.FormatUint(ns, 10) == parts[9]
}

func mihomoColdHomeLocalName(name string) bool {
	return name != "" && len(name) <= 4096 && path.Clean(name) == name && !path.IsAbs(name) && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00\r\n")
}

func validMihomoColdHomeHex(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
