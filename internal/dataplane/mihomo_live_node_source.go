package dataplane

import "encoding/json"

// The Store supplies one canonical outbound, never a user-supplied routing
// document. The existing conservative compiler reviews all its source fields.
func mihomoNodeSourceProfile(material []byte) ([]byte, error) {
	if !json.Valid(material) {
		return nil, ErrNodeDefaultSource
	}
	return json.Marshal(struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}{Outbounds: []json.RawMessage{material}})
}
