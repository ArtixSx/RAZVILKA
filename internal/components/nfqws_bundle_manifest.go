package components

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

const ManagedNFQWSProvider = "managed-nfqws-payload"
const ManagedNFQWSJournalSchema = 3

var ErrManagedNFQWSBundle = errors.New("managed NFQWS bundle evidence is invalid or incomplete")

type ManagedNFQWSMember struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Destination string `json:"destination"`
	Gzip        bool   `json:"gzip,omitempty"`
	RawSize     int64  `json:"raw_size"`
	RawSHA256   string `json:"raw_sha256"`
}

type ManagedNFQWSNotice struct {
	Project     string `json:"project"`
	License     string `json:"license"`
	SourceURL   string `json:"source_url"`
	BuildStatus string `json:"build_status"`
}

// This is a trusted, reviewed code/catalog value, never an HTTP-supplied
// extraction recipe. Installers do not discover latest releases or execute it.
type ManagedNFQWSManifest struct {
	Schema          int                  `json:"schema"`
	ProviderID      string               `json:"provider_id"`
	Flavor          string               `json:"flavor"`
	SourceRepo      string               `json:"source_repo"`
	Tag             string               `json:"tag"`
	SourceCommit    string               `json:"source_commit"`
	ParentAssetURL  string               `json:"parent_asset_url"`
	ParentAssetSize int64                `json:"parent_asset_size"`
	ParentSHA256    string               `json:"parent_sha256"`
	Architecture    string               `json:"architecture"`
	ABI             string               `json:"abi"`
	LuaCompat       int                  `json:"lua_compat"`
	Members         []ManagedNFQWSMember `json:"members"`
	Notices         []ManagedNFQWSNotice `json:"notices"`
	AllowedFeatures []string             `json:"allowed_features"`
}

// Only this ARM64 flavor has reviewed payload hashes. Other architectures
// need independent payload/ABI review; no uname alias or binary fallback.
func ReviewedManagedNFQWSManifest(architecture string) (ManagedNFQWSManifest, error) {
	if architecture != "arm64" {
		return ManagedNFQWSManifest{}, ErrManagedNFQWSBundle
	}
	m := ManagedNFQWSManifest{
		Schema: 1, ProviderID: ManagedNFQWSProvider, Flavor: "keenetic-payload-1.3.1",
		SourceRepo: "https://github.com/nfqws/nfqws2-keenetic", Tag: "v1.3.1", SourceCommit: "077f9af6068cd3380527085ca351b503a2dcf926",
		ParentAssetURL:  "https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.3.1/nfqws2-keenetic_1.3.1_aarch64-3.10.ipk",
		ParentAssetSize: 381072, ParentSHA256: "9167d72053a83a78f48f6439af38432fb2d1d411fb22c0980240a949ace614df",
		Architecture: "arm64", ABI: "ELF64-LE-AArch64; native compatibility unverified", LuaCompat: 6,
		AllowedFeatures: []string{"tcp", "udp", "quic", "keenetic-fastpath-patch"},
		Members: []ManagedNFQWSMember{
			{"./opt/usr/bin/nfqws2", 318336, "0c97153a2cc72392776fc550bf7be1cec77bc5db2505ab5b9dbc6d071e739c09", "bin/rzv-nfqws2", false, 318336, "0c97153a2cc72392776fc550bf7be1cec77bc5db2505ab5b9dbc6d071e739c09"},
			{"./opt/etc/nfqws2/lua/zapret-lib.lua.gz", 22403, "7c586c11c8cfa14031c348cb7715890434df779d2bb0cc7ddf0f81f599c70024", "lua/zapret-lib.lua", true, 92970, "b67a470f23b00a8d6e732c4e5135a39b224511e0b71809d5f4616adf62674980"},
			{"./opt/etc/nfqws2/lua/zapret-antidpi.lua.gz", 8400, "9017b2684a0b7aba96221fde0f9548254764f946b8d73f7abbb2ea8286e6f0b6", "lua/zapret-antidpi.lua", true, 51782, "31c9dd75b0bd55e98e5306293f2be81e9d2ecadcbbf9157394ff37dcff7dc85a"},
			{"./opt/etc/nfqws2/lua/zapret-auto.lua.gz", 5475, "f643392e43f5b87cd75e71fb38883dece57df30d563cd86aca987654c75df422", "lua/zapret-auto.lua", true, 20988, "c2028f544134b0dec33f054ac54fe4f2315d969ba034601456f72017fd5f8528"},
			{"./opt/etc/nfqws2/blobs/quic_initial.bin", 1200, "f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a", "blobs/quic_initial.bin", false, 1200, "f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a"},
			{"./opt/etc/nfqws2/blobs/tls_clienthello.bin", 681, "936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c", "blobs/tls_clienthello.bin", false, 681, "936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c"},
		},
		Notices: []ManagedNFQWSNotice{
			{"nfqws2-keenetic", "MIT", "https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/LICENSE", "wrapper-source-pinned; exact parent build inputs unresolved"},
			{"Keenetic fastpath patch", "wrapper MIT", "https://github.com/nfqws/nfqws2-keenetic/blob/077f9af6068cd3380527085ca351b503a2dcf926/patches/001-tls-reasm-fastpath.patch", "source evidence; hardware/packet visibility unverified"},
			{"zapret2", "MIT and embedded crypto notices", "https://github.com/bol-van/zapret2", "parent upstream commit unresolved; not an unmodified bol-van binary"},
			{"libnfnetlink", "GPL-2.0-only and GPL-2.0-or-later files", "https://www.netfilter.org/projects/libnfnetlink/", "recipe 1.0.2; parent build attestation unresolved"},
			{"libnetfilter_queue", "GPL-2.0-or-later", "https://www.netfilter.org/projects/libnetfilter_queue/", "recipe 1.0.5; parent build attestation unresolved"},
			{"libmnl", "LGPL-2.1-or-later", "https://www.netfilter.org/projects/libmnl/", "recipe 1.0.5; parent build attestation unresolved"},
			{"LuaJIT", "MIT with additional notices", "https://github.com/openresty/luajit2/blob/v2.1-20250826/COPYRIGHT", "recipe 2.1-20250826; parent build attestation unresolved"},
			{"musl/compiler runtime", "source notices required", "https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT", "unresolved-build-input"},
			{"zlib", "zlib", "https://github.com/madler/zlib", "unresolved-build-input"},
		},
	}
	return m, nil
}

func bundleHash(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func bundleHTTPS(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func (m ManagedNFQWSManifest) bytes() ([]byte, error) {
	destinations := []string{"bin/rzv-nfqws2", "lua/zapret-lib.lua", "lua/zapret-antidpi.lua", "lua/zapret-auto.lua", "blobs/quic_initial.bin", "blobs/tls_clienthello.bin"}
	if m.Schema != 1 || m.ProviderID != ManagedNFQWSProvider || m.Architecture != "arm64" || m.LuaCompat != 6 || m.Flavor == "" || len(m.Flavor) > 128 || strings.ContainsAny(m.Flavor, "/\\\x00") || !bundleHTTPS(m.SourceRepo) || !bundleHTTPS(m.ParentAssetURL) || m.Tag == "" || len(m.Tag) > 128 || !bundleHash(m.SourceCommit, 40) || !bundleHash(m.ParentSHA256, 64) || m.ParentAssetSize <= 0 || m.ParentAssetSize > 8<<20 || len(m.Members) != 6 || len(m.Notices) == 0 || len(m.Notices) > 16 || len(m.AllowedFeatures) == 0 || len(m.AllowedFeatures) > 8 || m.ABI == "" || len(m.ABI) > 256 {
		return nil, ErrManagedNFQWSBundle
	}
	seen := map[string]bool{}
	for i, v := range m.Members {
		name, err := bundleArchivePath(v.Path)
		if err != nil || seen[name] || v.Destination != destinations[i] || v.Size <= 0 || v.Size > 1<<20 || v.RawSize <= 0 || v.RawSize > 1<<20 || !bundleHash(v.SHA256, 64) || !bundleHash(v.RawSHA256, 64) || (i >= 1 && i <= 3) != v.Gzip || (!v.Gzip && (v.SHA256 != v.RawSHA256 || v.Size != v.RawSize)) {
			return nil, ErrManagedNFQWSBundle
		}
		seen[name] = true
	}
	for _, n := range m.Notices {
		if n.Project == "" || n.License == "" || n.BuildStatus == "" || len(n.Project)+len(n.License)+len(n.BuildStatus) > 1024 || !bundleHTTPS(n.SourceURL) {
			return nil, ErrManagedNFQWSBundle
		}
	}
	seen = map[string]bool{}
	for _, feature := range m.AllowedFeatures {
		if seen[feature] {
			return nil, ErrManagedNFQWSBundle
		}
		switch feature {
		case "tcp", "udp", "quic", "keenetic-fastpath-patch":
		default:
			return nil, ErrManagedNFQWSBundle
		}
		seen[feature] = true
	}
	return json.Marshal(m)
}

func (m ManagedNFQWSManifest) Digest() (string, error) {
	b, err := m.bytes()
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

func bundleArchivePath(name string) (string, error) {
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimSuffix(name, "/")
	if name == "" || name == "." || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00:") || len(name) > 512 || strings.HasPrefix(name, "../") {
		return "", fmt.Errorf("%w: archive path", ErrManagedNFQWSBundle)
	}
	return name, nil
}
