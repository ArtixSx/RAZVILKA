package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// The complete closed runtime directory is retained as history. No serialized
// filename is interpreted as a command or selected as an arbitrary move path.
type mihomoColdRuntimeArchive struct {
	Present        bool              `json:"present"`
	Identity       string            `json:"identity,omitempty"`
	Files          map[string][]byte `json:"files,omitempty"`
	FileIdentities map[string]string `json:"file_identities,omitempty"`
	Directories    map[string]string `json:"directories,omitempty"`
}

func mihomoColdRuntimeNames(a *ProxyTunnelAdapter) map[string]bool {
	names := map[string]bool{}
	for _, path := range bootRetirementRuntimePaths(a) {
		if name, err := filepath.Rel(a.StateRoot, path); err == nil && filepath.IsLocal(name) {
			names[name] = true
		}
	}
	for _, p := range []ProcessSpec{a.engineProcess(), a.sidecarProcess()} {
		if name, err := filepath.Rel(a.StateRoot, p.LogPath); err == nil && filepath.IsLocal(name) {
			names[name] = true
		}
	}
	return names
}

func readMihomoColdRuntime(root *os.Root, name string, a *ProxyTunnelAdapter) (out mihomoColdRuntimeArchive, resultErr error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil || !networkPolicyPrivateDirectory(info) || !executionHistoryOwner(info, true) {
		return out, ErrMihomoLiveRetirement
	}
	dir, err := root.OpenRoot(name)
	if err != nil {
		return out, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, dir.Close())
		if resultErr != nil {
			for _, data := range out.Files {
				clear(data)
			}
			out = mihomoColdRuntimeArchive{}
		}
	}()
	held, err := dir.Stat(".")
	if err != nil || !os.SameFile(info, held) {
		return out, ErrMihomoLiveRetirement
	}
	out.Present, out.Identity, out.Files = true, executionHistoryIdentity(info), map[string][]byte{}
	out.Directories = map[string]string{}
	out.FileIdentities = map[string]string{}
	allowed := mihomoColdRuntimeNames(a)
	total := 0
	var walk func(string, int) error
	walk = func(parent string, depth int) error {
		f, err := dir.Open(parent)
		if err != nil {
			return err
		}
		entries, readErr := f.ReadDir(513)
		closeErr := f.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 512 {
			return ErrMihomoLiveRetirement
		}
		for _, entry := range entries {
			child := filepath.Join(parent, entry.Name())
			info, err := dir.Lstat(child)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if !networkPolicyPrivateDirectory(info) || !executionHistoryOwner(info, true) {
					return ErrMihomoLiveRetirement
				}
				if len(out.Directories) >= 128 {
					return ErrMihomoLiveRetirement
				}
				out.Directories[child] = executionHistoryIdentity(info)
				if depth == 0 && (entry.Name() == "policy-generations" || entry.Name() == "runtime") {
					if err := walk(child, 1); err != nil {
						return err
					}
					continue
				}
				if depth == 1 && parent == "policy-generations" {
					if _, err := a.policyGenerationRoot(entry.Name()); err != nil {
						return err
					}
					if err := walk(child, 2); err != nil {
						return err
					}
					continue
				}
				return ErrMihomoLiveRetirement
			}
			if !validNetworkPolicyReceiptFile(info) || !executionHistoryOwner(info, false) || !allowed[child] && !(depth == 2 && filepath.Dir(parent) == "policy-generations" && slices.Contains([]string{policyAdditionFile, policyAdditionLock, "policy-state.json"}, entry.Name())) {
				return ErrMihomoLiveRetirement
			}
			raw, err := readMihomoColdFileAt(dir, child, info)
			if err != nil {
				return err
			}
			closing, err := dir.Lstat(child)
			if err != nil || mihomoColdFileIdentity(info) != mihomoColdFileIdentity(closing) {
				return ErrMihomoLiveRetirement
			}
			total += len(raw)
			if total > bootRetirementLimit || len(out.Files) >= 512 {
				return ErrMihomoLiveRetirement
			}
			out.Files[child] = raw
			out.FileIdentities[child] = mihomoColdFileIdentity(info)
		}
		return nil
	}
	if err := walk(".", 0); err != nil {
		return out, err
	}
	closing, err := root.Lstat(name)
	held, heldErr := dir.Stat(".")
	if err != nil || heldErr != nil || !os.SameFile(info, closing) || !os.SameFile(info, held) || !networkPolicyPrivateDirectory(closing) {
		return out, ErrMihomoLiveRetirement
	}
	return out, nil
}

func validateMihomoColdRuntime(a *ProxyTunnelAdapter, d ExecutionMihomoLiveDefinition, r mihomoColdRuntimeArchive) error {
	if !r.Present {
		if r.Identity != "" || len(r.Files) != 0 || len(r.Directories) != 0 || len(r.FileIdentities) != 0 {
			return ErrMihomoLiveRetirement
		}
		return nil
	}
	if r.Identity == "" || len(r.Files) > 512 || len(r.Directories) > 128 || len(r.FileIdentities) != len(r.Files) {
		return ErrMihomoLiveRetirement
	}
	for name, identity := range r.Directories {
		if identity == "" || !filepath.IsLocal(name) || filepath.Clean(name) != name {
			return ErrMihomoLiveRetirement
		}
		if name == "policy-generations" || name == "runtime" {
			continue
		}
		parts := strings.Split(name, string(filepath.Separator))
		if len(parts) != 2 || parts[0] != "policy-generations" || r.Directories[parts[0]] == "" {
			return ErrMihomoLiveRetirement
		}
		if _, err := a.policyGenerationRoot(parts[1]); err != nil {
			return err
		}
	}
	allowed := mihomoColdRuntimeNames(a)
	total := 0
	for name, raw := range r.Files {
		if r.FileIdentities[name] == "" {
			return ErrMihomoLiveRetirement
		}
		total += len(raw)
		if total > bootRetirementLimit {
			return ErrMihomoLiveRetirement
		}
		if !filepath.IsLocal(name) || filepath.Clean(name) != name || len(raw) > bootRetirementLimit {
			return ErrMihomoLiveRetirement
		}
		parts := strings.Split(name, string(filepath.Separator))
		if allowed[name] {
			if len(parts) > 1 && r.Directories[filepath.Dir(name)] == "" {
				return ErrMihomoLiveRetirement
			}
		} else {
			if len(parts) != 3 || parts[0] != "policy-generations" {
				return ErrMihomoLiveRetirement
			}
			if r.Directories[filepath.Dir(name)] == "" {
				return ErrMihomoLiveRetirement
			}
			path, err := a.policyGenerationRoot(parts[1])
			if err != nil {
				return err
			}
			if !slices.Contains([]string{policyAdditionFile, policyAdditionLock, "policy-state.json"}, parts[2]) {
				return ErrMihomoLiveRetirement
			}
			if !bytes.Equal(r.Files[filepath.Join(parts[0], parts[1], policyAdditionLock)], []byte(policyAdditionMarker)) {
				return ErrMihomoLiveRetirement
			}
			if parts[2] == policyAdditionFile {
				var document policyAdditionDocument
				if nfqws2ManagedUniqueJSON(raw) != nil || json.Unmarshal(raw, &document) != nil || !kernelBootIDPattern.MatchString(document.Boot) {
					return ErrMihomoLiveRetirement
				}
				// The current generation must exactly match the frozen selectors.
				// Older generations may be archived only when already terminal.
				state := &d.Policy
				removedOnly := document.PolicyHash != policyAdditionHash(d.Policy)
				if removedOnly {
					state = nil
				}
				if validateBootRetirementReceipt(raw, path, document.Boot, state, removedOnly) != nil {
					return ErrMihomoLiveRetirement
				}
			}
		}
	}
	if raw, exists := r.Files[filepath.Base(a.policyBindingPath())]; exists {
		var binding proxyPolicyBinding
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&binding) != nil || decoder.Decode(new(any)) != io.EOF || binding.Schema != 1 || binding.Engine != "mihomo" || binding.Digest != proxyPolicyDigest(d.Policy) || !slices.Contains([]string{"pending", "active", "removed"}, binding.Phase) {
			return ErrMihomoLiveRetirement
		}
		if _, err := a.policyGenerationRoot(binding.Generation); err != nil {
			return err
		}
		var doc policyAdditionDocument
		receipt := r.Files[filepath.Join("policy-generations", binding.Generation, policyAdditionFile)]
		if json.Unmarshal(receipt, &doc) != nil || binding.ReceiptID != "" && binding.ReceiptID != doc.ID || doc.PolicyHash != policyAdditionHash(d.Policy) {
			return ErrMihomoLiveRetirement
		}
	}
	for path, want := range map[string]string{a.engineConfigPath(): d.Profile.ConfigSHA256, a.sidecarConfigPath(): d.Sidecar.ConfigSHA256} {
		if raw, exists := r.Files[mihomoColdRelative(a, path)]; exists && nodeDefaultSourceMaterialHash(raw) != want {
			return ErrMihomoLiveRetirement
		}
	}
	if raw, exists := r.Files[filepath.Base(a.policyPath())]; exists {
		var p proxyPolicyJournal
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || p.AdditionReceiptVersion != 1 || nodeServiceProofDigest(p.PolicyState) != nodeServiceProofDigest(d.Policy) {
			return ErrMihomoLiveRetirement
		}
	}
	if raw, exists := r.Files[filepath.Base(a.forwardingPath())]; exists {
		var f ProxyForwardingState
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if nfqws2ManagedUniqueJSON(raw) != nil || decoder.Decode(&f) != nil || decoder.Decode(new(any)) != io.EOF || !reflect.DeepEqual(&f, d.Policy.Forwarding) {
			return ErrMihomoLiveRetirement
		}
	}
	if raw, exists := r.Files[mihomoColdRelative(a, a.sidecarProcess().PIDPath)+routeidentity.ReceiptSuffix]; exists && d.Observation != nil && routeidentity.Hash(raw) != d.Observation.SidecarReceiptSHA256 {
		return ErrMihomoLiveRetirement
	}
	return nil
}

func mihomoColdFileIdentity(info os.FileInfo) string {
	if info == nil || !executionHistoryOwner(info, false) {
		return ""
	}
	return fmt.Sprintf("%s:%d:%d:%d", executionHistoryIdentity(info), info.Size(), info.Mode(), info.ModTime().UnixNano())
}

func mihomoColdRelative(a *ProxyTunnelAdapter, path string) string {
	name, err := filepath.Rel(a.StateRoot, path)
	if err != nil || !filepath.IsLocal(name) {
		return ""
	}
	return name
}
