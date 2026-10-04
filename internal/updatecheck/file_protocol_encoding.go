package updatecheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Reader version is a format capability, not production installer readiness.
const SelfUpdateReadVersion = 2

var ErrFileProtocol = errors.New("self update file/helper protocol requires matching trusted evidence")

func decodeFileProtocol(data []byte, out any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrFileProtocol
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrFileProtocol
	}
	return nil
}

func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
