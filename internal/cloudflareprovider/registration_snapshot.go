package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
)

// WritePrivateSnapshot exports a locally generated registration for encrypted
// backup/checkpoint storage only. It confers no runtime or health authority.
func (candidate RegistrationCandidate) WritePrivateSnapshot(w io.Writer) error {
	value, err := candidate.snapshot()
	if err != nil {
		return err
	}
	defer eraseBytes(value.raw)
	n, err := w.Write(value.raw)
	if err == nil && n != len(value.raw) {
		return io.ErrShortWrite
	}
	return err
}

// LegacyRegistrationSnapshot reads a single old private provider store without
// opening a writer or changing its bytes. It never contacts the provider.
func LegacyRegistrationSnapshot(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, ErrStore
	}
	var doc privateDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateDocument(doc) != nil || len(doc.Accounts) != 1 || doc.Accounts[0].Kind != SourceLocalRegistration {
		return nil, ErrStore
	}
	return bytes.Clone(doc.Accounts[0].Raw), nil
}

// WithRegistrationCandidate uses a validated inert registration image. Keys
// live only for the callback; callers still have to stage and test explicitly.
func WithRegistrationCandidate(ctx context.Context, raw []byte, consume func(context.Context, WireGuardCandidate) error) error {
	if consume == nil {
		return ErrCandidateInvalid
	}
	material, err := decodeTunnelMaterial(raw)
	if err != nil {
		return ErrStore
	}
	defer material.erase()
	material.binding = digest(raw)
	candidate, err := wireGuardCandidateFromMaterial("cf-"+material.binding[:32], material, CandidateOptions{})
	if err != nil {
		return err
	}
	defer candidate.erase()
	if err := ctx.Err(); err != nil {
		return err
	}
	return consume(ctx, candidate)
}
