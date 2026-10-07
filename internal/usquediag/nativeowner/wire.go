package nativeowner

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/ArtixSx/razvilka/internal/components"
)

const frameLimit = 32 << 10

type frame struct {
	Version       int
	Kind, Binding string
	Offer         *offer `json:",omitempty"`
	Helper        components.NFQWSSupervisionIdentity
	Child         components.NFQWSRuntimeProcessIdentity
	Receipt       components.NFQWSSupervisionReceipt
}

func decodeFrame(raw []byte) (frame, error) {
	var f frame
	if len(raw) == 0 || len(raw) > frameLimit {
		return f, ErrOwned
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if uniqueValue(check, 0) != nil {
		return f, ErrOwned
	}
	if _, err := check.Token(); err != io.EOF {
		return f, ErrOwned
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF || f.Version != 1 || !hexShape(f.Binding, 64) {
		return frame{}, ErrOwned
	}
	switch f.Kind {
	case "offer", "ready", "permit", "started", "stop", "terminal", "ack":
	default:
		return frame{}, ErrOwned
	}
	if (f.Kind == "offer") != (f.Offer != nil) {
		return frame{}, ErrOwned
	}
	return f, nil
}
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrOwned
	}
	token, err := d.Token()
	if err != nil {
		return ErrOwned
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrOwned
			}
			seen[name] = true
			if uniqueValue(d, depth+1) != nil {
				return ErrOwned
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrOwned
		}
	case '[':
		for d.More() {
			if uniqueValue(d, depth+1) != nil {
				return ErrOwned
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrOwned
		}
	default:
		return ErrOwned
	}
	return nil
}
