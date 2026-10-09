package physicalscope

import (
	"encoding/binary"
	"encoding/json"
	"strconv"
)

// Only a refused, already decoded LINK can create this comparison image. It
// retains no packet, attribute payload, address, name, index, PID or sequence.
// Nothing in this diagnostic grants continuity or permits an operation retry.
type linkFailureDiagnostic struct {
	Kind       uint16               `json:"kind"`
	Family     uint8                `json:"family"`
	Flags      uint32               `json:"flags"`
	Change     uint32               `json:"change"`
	Role       string               `json:"role"`
	Attributes []linkAttributeShape `json:"attributes"`
	Truncated  bool                 `json:"truncated,omitempty"`
}

type linkAttributeShape struct {
	Path  string `json:"path"`
	Type  uint16 `json:"type"`
	Bytes uint16 `json:"bytes"`
}

func (*linkFailureDiagnostic) Error() string { return "refused physical LINK shape" }

func refusedLinkShape(m message, link kernelLink, segments []Segment) error {
	d := &linkFailureDiagnostic{Kind: m.kind, Family: m.data[0], Flags: binary.NativeEndian.Uint32(m.data[8:12]), Change: binary.NativeEndian.Uint32(m.data[12:16]), Role: "unknown"}
	role := 0
	for _, s := range segments {
		if s.IfIndex == link.IfIndex {
			role |= 1
		}
		for _, member := range s.Members {
			if member.IfIndex == link.IfIndex {
				role |= 2
			}
			if member.Parent.Known && member.Parent.IfIndex == link.IfIndex {
				role |= 4
			}
		}
	}
	switch role {
	case 1:
		d.Role = "root"
	case 2:
		d.Role = "member"
	case 4:
		d.Role = "parent"
	default:
		d.Role = "multiple-or-unknown"
	}
	d.shapes(m.data[16:], "")
	return d
}

func (d *linkFailureDiagnostic) shapes(raw []byte, parent string) {
	for len(raw) > 0 {
		if len(raw) < 4 || len(d.Attributes) == 96 {
			d.Truncated = true
			return
		}
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		kind := binary.NativeEndian.Uint16(raw[2:4])
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(raw) {
			d.Truncated = true
			return
		}
		path := strconv.Itoa(int(kind & 0x3fff))
		if parent != "" {
			path = parent + "/" + path
		}
		d.Attributes = append(d.Attributes, linkAttributeShape{Path: path, Type: kind, Bytes: uint16(n - 4)})
		// These specific containers have TLV children. All values, including
		// unknown attributes and driver diagnostics, remain opaque.
		switch path {
		case "18", "18/2", "18/5", "26", "26/10":
			d.shapes(raw[4:n], path)
		}
		raw = raw[aligned:]
	}
}

// DiagnosticLinkRefusal returns bounded metadata from this package's private
// refusal only. Do not format a foreign error or follow an unbounded chain.
func DiagnosticLinkRefusal(err error) string {
	remaining := 64
	var found *linkFailureDiagnostic
	var visit func(error, int)
	visit = func(err error, depth int) {
		if err == nil || remaining == 0 || depth == 16 || found != nil {
			return
		}
		remaining--
		if d, ok := err.(*linkFailureDiagnostic); ok {
			found = d
			return
		}
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range e.Unwrap() {
				visit(cause, depth+1)
			}
		case interface{ Unwrap() error }:
			visit(e.Unwrap(), depth+1)
		}
	}
	visit(err, 0)
	if found == nil {
		return ""
	}
	data, err := json.Marshal(found)
	if err != nil || len(data) > 8192 {
		return ""
	}
	return string(data)
}
