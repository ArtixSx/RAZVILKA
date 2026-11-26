// strategy-pack is an offline publisher tool, not a router daemon. Never copy
// its private signing key to subscriber routers. Key files are owner-provisioned.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"io"
	"os"
	"regexp"
	"time"
)

func writeNew(path string, data []byte) error {
	if path == "" {
		return errors.New("output path required")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(data); e != nil {
		return e
	}
	return f.Sync()
}
func readBounded(path string, secret bool) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > strategylab.MaxPackBytes || secret && st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("invalid file or unsafe private-key permissions")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	same, e := f.Stat()
	if e != nil || !os.SameFile(st, same) {
		return nil, errors.New("input replaced")
	}
	b, e := io.ReadAll(io.LimitReader(f, strategylab.MaxPackBytes+1))
	if len(b) > strategylab.MaxPackBytes {
		return nil, errors.New("input too large")
	}
	return b, e
}
func execute(mode, input, output, id, private, public string) error {
	switch mode {
	case "keygen":
		if private == "" || public == "" || private == public || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`).MatchString(id) {
			return errors.New("distinct private/public paths and key-id required")
		}
		// Both files must be new. Failure never deletes or replaces existing keys.
		for _, p := range []string{private, public} {
			if _, e := os.Lstat(p); !os.IsNotExist(e) {
				return errors.New("key output already exists or cannot be inspected")
			}
		}
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		data, _ := json.Marshal(map[string]string{"key_id": id, "private_key": base64.StdEncoding.EncodeToString(priv)})
		if e = writeNew(private, data); e != nil {
			return e
		}
		data, _ = json.Marshal(map[string]ed25519.PublicKey{id: pub})
		return writeNew(public, data)
	case "sign":
		payload, e := readBounded(input, false)
		if e != nil {
			return e
		}
		data, e := readBounded(private, true)
		if e != nil {
			return e
		}
		var k struct {
			KeyID   string `json:"key_id"`
			Private string `json:"private_key"`
		}
		if json.Unmarshal(data, &k) != nil || k.KeyID != id {
			return errors.New("private key-id mismatch")
		}
		raw, e := base64.StdEncoding.DecodeString(k.Private)
		if e != nil {
			return errors.New("invalid private key")
		}
		signed, e := strategylab.SignPack(payload, id, ed25519.PrivateKey(raw), time.Now())
		if e != nil {
			return e
		}
		return writeNew(output, signed)
	case "verify":
		data, e := readBounded(input, false)
		if e != nil {
			return e
		}
		keys, e := strategylab.LoadPackKeys(public)
		if e != nil {
			return e
		}
		r, e := strategylab.ReviewPack(data, true, keys, time.Now())
		if e != nil {
			return e
		}
		fmt.Printf("Verified pack %s sequence %d: %d candidates; no service proof\n", r.ID, r.Sequence, len(r.Entries))
		return nil
	default:
		return errors.New("mode must be keygen, sign or verify")
	}
}
func main() {
	mode := flag.String("mode", "verify", "keygen, sign or verify (offline)")
	input := flag.String("in", "", "input JSON pack")
	output := flag.String("out", "", "new output signed file")
	id := flag.String("key-id", "", "publisher key ID")
	priv := flag.String("private", "", "private key file; never on subscriber routers")
	pub := flag.String("public", "", "public key map for verification")
	flag.Parse()
	if e := execute(*mode, *input, *output, *id, *priv, *pub); e != nil {
		fmt.Fprintln(os.Stderr, "Strategy pack operation failed:", e)
		os.Exit(1)
	}
}
