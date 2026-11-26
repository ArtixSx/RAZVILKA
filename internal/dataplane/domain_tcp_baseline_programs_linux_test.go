//go:build linux

package dataplane

import (
	"testing"
	"unsafe"
)

func TestDomainTCPBaselineProgramQueryABI(t *testing.T) {
	// These are Linux UAPI offsets, not Go-derived expected values. In
	// particular, a count-only query still writes revision at bytes 56..63.
	var query domainTCPBaselineProgramQuery
	if got := unsafe.Sizeof(query); got != 64 {
		t.Fatalf("query storage = %d bytes, want 64 including revision output", got)
	}
	for _, field := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"target_fd", unsafe.Offsetof(query.FD), 0},
		{"attach_type", unsafe.Offsetof(query.Attach), 4},
		{"query_flags", unsafe.Offsetof(query.Flags), 8},
		{"attach_flags", unsafe.Offsetof(query.AttachFlags), 12},
		{"prog_ids", unsafe.Offsetof(query.IDs), 16},
		{"prog_cnt", unsafe.Offsetof(query.Count), 24},
		{"prog_attach_flags", unsafe.Offsetof(query.ProgramAttachFlags), 32},
		{"link_ids", unsafe.Offsetof(query.LinkIDs), 40},
		{"link_attach_flags", unsafe.Offsetof(query.LinkAttachFlags), 48},
		{"revision", unsafe.Offsetof(query.Revision), 56},
	} {
		if field.got != field.want {
			t.Errorf("%s offset = %d, want Linux UAPI %d", field.name, field.got, field.want)
		}
	}
}
