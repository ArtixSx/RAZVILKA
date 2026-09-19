package main

import (
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestOfflineKeySignVerifyAndNoOverwrite(t *testing.T) {
	d := t.TempDir()
	priv, pub, in, out := filepath.Join(d, "private.json"), filepath.Join(d, "public.json"), filepath.Join(d, "pack.json"), filepath.Join(d, "signed.json")
	if e := execute("keygen", "", "", "owner", priv, pub); e != nil {
		t.Fatal(e)
	}
	if e := execute("keygen", "", "", "owner", priv, pub); e == nil {
		t.Fatal("overwrote keys")
	}
	if e := writeNew(in, strategylab.BuiltinPack(time.Now())); e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS == "windows" {
		// Windows does not expose enforceable POSIX owner-only permissions.
		// The signer must fail closed; Linux CI covers the successful round trip.
		if e := execute("sign", in, out, "owner", priv, ""); e == nil {
			t.Fatal("read private key without POSIX access restrictions")
		}
		return
	}
	if e := execute("sign", in, out, "owner", priv, ""); e != nil {
		t.Fatal(e)
	}
	if e := execute("verify", out, "", "", "", pub); e != nil {
		t.Fatal(e)
	}
	if e := execute("sign", in, out, "owner", priv, ""); e == nil {
		t.Fatal("overwrote signature")
	}
	os.Chmod(priv, 0644)
	if e := execute("sign", in, out+".second", "owner", priv, ""); e == nil {
		t.Fatal("read weak key")
	}
}
