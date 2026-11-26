package components

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReleaseAssetNamesMatchUpstreamConventions(t *testing.T) {
	usque, err := releaseAssetName(Spec{ID: "usque", Binary: "usque", Archive: "zip"}, "4.2.1", "mipsle")
	if err != nil || usque != "usque_4.2.1_linux_mipsle.zip" {
		t.Fatalf("usque asset=%q err=%v", usque, err)
	}
	wgcf, err := releaseAssetName(Spec{ID: "wgcf", Binary: "wgcf", Archive: "binary"}, "2.2.32", "arm64")
	if err != nil || wgcf != "wgcf_2.2.32_linux_arm64" {
		t.Fatalf("wgcf asset=%q err=%v", wgcf, err)
	}
}

func TestChecksumParserRequiresExactAssetName(t *testing.T) {
	payload := []byte("binary")
	sum := sha256.Sum256(payload)
	line := hex.EncodeToString(sum[:]) + "  wgcf_2.2.32_linux_arm64\n"
	value, err := checksumForAsset([]byte(line), "wgcf_2.2.32_linux_arm64")
	if err != nil || value != hex.EncodeToString(sum[:]) {
		t.Fatalf("checksum=%q err=%v", value, err)
	}
	if _, err := checksumForAsset([]byte(line), "wgcf_2.2.32_linux_arm64.evil"); err == nil {
		t.Fatal("checksum parser accepted a suffix mismatch")
	}
}

func TestBinaryFromZIPSelectsExactBasename(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	bad, _ := writer.Create("../not-usque")
	_, _ = bad.Write([]byte("bad"))
	good, _ := writer.Create("release/usque")
	_, _ = good.Write([]byte("binary"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := binaryFromZIP(buffer.Bytes(), "usque")
	if err != nil || string(got) != "binary" {
		t.Fatalf("binary=%q err=%v", got, err)
	}
}

func TestExternalReceiptRequiresMatchingBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "wgcf")
	binary := []byte("verified upstream binary")
	if err := os.WriteFile(target, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeExternalReceipt(target, "2.2.32", binary); err != nil {
		t.Fatal(err)
	}
	if got := externalReceiptVersion(target); got != "2.2.32" {
		t.Fatalf("receipt version=%q", got)
	}
	if err := os.WriteFile(target, []byte("tampered binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := externalReceiptVersion(target); got != "" {
		t.Fatalf("tampered binary trusted as version %q", got)
	}
}

func TestExternalReceiptIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "wgcf")
	binary := []byte("binary")
	if err := os.WriteFile(target, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeExternalReceipt(target, "2.2.32", binary); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(externalReceiptPath(target))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode=%#o", info.Mode().Perm())
	}
}
