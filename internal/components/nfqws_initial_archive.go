package components

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

const nfqwsInitialSourceURL = "https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.3.1/nfqws2-keenetic_1.3.1_all_entware.ipk"
const nfqwsInitialSourceSHA = "28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054"
const nfqwsInitialSourceSize = 2382102
const nfqwsInitialInitMember = "opt/etc/init.d/S51nfqws2"

var ErrNFQWSInitialInstall = errors.New("Безопасная первичная установка NFQWS2 недоступна; требуется проверка установки и её журнала")

type nfqwsInitialMember struct {
	name       string
	header     tar.Header
	start, end int
	data       []byte
}

// Every member, including unselected control hooks, is checked before rebuild.
// Raw tar records are retained verbatim except the one approved S51 record.
func nfqwsInitialTar(ctx context.Context, compressed []byte) ([]byte, []nfqwsInitialMember, error) {
	raw, err := bundleGunzip(ctx, compressed, 12<<20)
	if err != nil {
		return nil, nil, errors.Join(ErrNFQWSInitialInstall, err)
	}
	input := bytes.NewReader(raw)
	reader := tar.NewReader(input)
	var members []nfqwsInitialMember
	seen := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, errors.Join(ErrNFQWSInitialInstall, err)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if name == "." {
			name = ""
		}
		if name != "" {
			if _, err := bundleArchivePath(name); err != nil {
				return nil, nil, ErrNFQWSInitialInstall
			}
		}
		if len(members) >= 128 || seen[name] || len(h.Name) > 100 || name == "" && h.Typeflag != tar.TypeDir || h.Size < 0 || h.Size > 4<<20 || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 || h.Linkname != "" ||
			(h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir) || h.Mode & ^int64(0777) != 0 || (h.Typeflag == tar.TypeDir && h.Size != 0) {
			return nil, nil, ErrNFQWSInitialInstall
		}
		seen[name] = true
		start := len(raw) - input.Len() - 512
		end := start + 512 + int((h.Size+511)/512)*512
		if start < 0 || end > len(raw) {
			return nil, nil, ErrNFQWSInitialInstall
		}
		data, err := io.ReadAll(io.LimitReader(reader, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return nil, nil, ErrNFQWSInitialInstall
		}
		members = append(members, nfqwsInitialMember{name, *h, start, end, data})
	}
	for _, v := range raw[len(raw)-input.Len():] {
		if v != 0 {
			return nil, nil, ErrNFQWSInitialInstall
		}
	}
	return raw, members, nil
}

func nfqwsInitialGzip(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(raw); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func nfqwsInitialReplace(raw []byte, member nfqwsInitialMember, replacement []byte) []byte {
	header := bytes.Clone(raw[member.start : member.start+512])
	copy(header[124:136], []byte(fmt.Sprintf("%011o\x00", len(replacement))))
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	sum := 0
	for _, v := range header {
		sum += int(v)
	}
	copy(header[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	out := append(bytes.Clone(raw[:member.start]), header...)
	out = append(out, replacement...)
	out = append(out, make([]byte, (512-len(replacement)%512)%512)...)
	return append(out, raw[member.end:]...)
}

// Upstream records contain the build user's UID/GID 1001. The explicitly
// reviewed derivative installs root-owned Entware paths instead. Only owner
// metadata changes; names, modes, timestamps and non-S51 content stay intact.
func nfqwsInitialRootOwners(raw []byte, members []nfqwsInitialMember) []byte {
	out := bytes.Clone(raw)
	for _, member := range members {
		h := out[member.start : member.start+512]
		copy(h[108:116], []byte("0000000\x00"))
		copy(h[116:124], []byte("0000000\x00"))
		clear(h[265:329])
		copy(h[265:297], []byte("root"))
		copy(h[297:329], []byte("root"))
		for i := 148; i < 156; i++ {
			h[i] = ' '
		}
		sum := 0
		for _, v := range h {
			sum += int(v)
		}
		copy(h[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	}
	return out
}

type nfqwsInitialArchive struct {
	bytes   []byte
	files   map[string]nfqwsInitialMember
	control map[string][]byte
	init    []byte
}

func rebuildNFQWSInitialArchive(ctx context.Context, source []byte, owner string) (*nfqwsInitialArchive, error) {
	if len(source) != nfqwsInitialSourceSize || digest(source) != nfqwsInitialSourceSHA {
		return nil, ErrNFQWSInitialInstall
	}
	return rewriteNFQWSInitialArchive(ctx, source, owner)
}

// Caller must first verify the pinned whole upstream digest. Kept separate for
// synthetic format tests; it never authorizes an opkg command on its own.
func rewriteNFQWSInitialArchive(ctx context.Context, source []byte, owner string) (*nfqwsInitialArchive, error) {
	raw, outer, err := nfqwsInitialTar(ctx, source)
	if err != nil || len(outer) != 3 {
		return nil, ErrNFQWSInitialInstall
	}
	byName := map[string]nfqwsInitialMember{}
	for _, member := range outer {
		if member.header.Typeflag == tar.TypeDir {
			return nil, ErrNFQWSInitialInstall
		}
		byName[member.name] = member
	}
	if string(byName["debian-binary"].data) != "2.0\n" || len(byName["control.tar.gz"].data) == 0 || len(byName["data.tar.gz"].data) == 0 {
		return nil, ErrNFQWSInitialInstall
	}
	controlRaw, controls, err := nfqwsInitialTar(ctx, byName["control.tar.gz"].data)
	if err != nil {
		return nil, err
	}
	control := map[string][]byte{}
	for _, member := range controls {
		if member.header.Typeflag == tar.TypeDir && member.name == "" {
			continue
		}
		if member.name != "prerm" && member.name != "postinst" && member.name != "postrm" && member.name != "preinst" && member.name != "conffiles" && member.name != "control" {
			return nil, ErrNFQWSInitialInstall
		}
		control[member.name] = member.data
	}
	if len(control) != 6 || !bytes.Contains(control["control"], []byte("Package: nfqws2-keenetic\nVersion: 1.3.1\nDepends: iptables, busybox\n")) {
		return nil, ErrNFQWSInitialInstall
	}
	data, members, err := nfqwsInitialTar(ctx, byName["data.tar.gz"].data)
	if err != nil {
		return nil, err
	}
	files := map[string]nfqwsInitialMember{}
	for _, member := range members {
		if member.name == "" || member.header.Typeflag == tar.TypeDir {
			continue
		}
		if !strings.HasPrefix(member.name, "opt/") {
			return nil, ErrNFQWSInitialInstall
		}
		member.header.Uid, member.header.Gid = 0, 0
		member.header.Uname, member.header.Gname = "root", "root"
		files[member.name] = member
	}
	init, ok := files[nfqwsInitialInitMember]
	if !ok || digest(init.data) != engineconfig.NFQWSFirstStartStockInitSHA256 {
		return nil, ErrNFQWSInitialInstall
	}
	guarded, err := engineconfig.NFQWSFirstStartInit(init.data, owner)
	if err != nil {
		return nil, err
	}
	changedData, err := nfqwsInitialGzip(nfqwsInitialReplace(nfqwsInitialRootOwners(data, members), init, guarded))
	if err != nil {
		return nil, err
	}
	changedControl, err := nfqwsInitialGzip(nfqwsInitialRootOwners(controlRaw, controls))
	if err != nil {
		return nil, err
	}
	// Source order is pinned: control then data then debian-binary. Replace
	// backwards so changed compressed sizes cannot invalidate an earlier offset.
	if byName["control.tar.gz"].start >= byName["data.tar.gz"].start {
		return nil, ErrNFQWSInitialInstall
	}
	outerRaw := nfqwsInitialRootOwners(raw, outer)
	outerRaw = nfqwsInitialReplace(outerRaw, byName["data.tar.gz"], changedData)
	outerRaw = nfqwsInitialReplace(outerRaw, byName["control.tar.gz"], changedControl)
	result, err := nfqwsInitialGzip(outerRaw)
	if err != nil {
		return nil, err
	}
	init.data = guarded
	init.header.Size = int64(len(guarded))
	files[nfqwsInitialInitMember] = init
	return &nfqwsInitialArchive{result, files, control, guarded}, nil
}

func (m *Manager) downloadNFQWSInitialArchive(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nfqwsInitialSourceURL, nil)
	if err != nil {
		return nil, err
	}
	client := m.Client
	if client == nil {
		client = releaseHTTPClient()
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pinned NFQWS2 source: HTTP %s", strconv.Itoa(response.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, nfqwsInitialSourceSize+1))
	if err != nil || len(data) != nfqwsInitialSourceSize || digest(data) != nfqwsInitialSourceSHA {
		return nil, ErrNFQWSInitialInstall
	}
	return data, nil
}
