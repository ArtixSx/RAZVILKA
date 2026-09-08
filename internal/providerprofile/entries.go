package providerprofile

import (
	"crypto/sha256"
	"encoding/json"
)

// EntryIssue deliberately retains no source text, URI, alias or credential.
type EntryIssue struct {
	Index  int    `json:"index"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

type entryReport struct {
	rejected []EntryIssue
	skipped  []EntryIssue
	firstErr error
	seen     map[[32]byte]bool
}

func (r *entryReport) reject(index int, err error) {
	if r.firstErr == nil {
		r.firstErr = err
	}
	code := ErrorCode(err)
	reason := "Запись повреждена или её формат пока не поддерживается."
	if code != "INVALID_PROFILE" {
		reason = (&ImportError{Code: code}).Error()
	}
	r.rejected = append(r.rejected, EntryIssue{Index: index, Code: code, Reason: reason})
}

func (r *entryReport) accept(index int, outbound map[string]any) bool {
	identity := make(map[string]any, len(outbound))
	for k, v := range outbound {
		if k != "tag" {
			identity[k] = v
		}
	}
	data, err := json.Marshal(identity)
	if err != nil {
		r.reject(index, importError("INVALID_PARAMETERS"))
		return false
	}
	digest := sha256.Sum256(data) // In-memory only; credentials are part of identity.
	if r.seen == nil {
		r.seen = map[[32]byte]bool{}
	}
	if r.seen[digest] {
		r.skipped = append(r.skipped, EntryIssue{Index: index, Code: "DUPLICATE_ENTRY", Reason: "Повтор уже принятого узла; в черновике останется одна копия."})
		return false
	}
	r.seen[digest] = true
	return true
}
