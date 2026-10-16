package physicalscope

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// ReadWGKernelServiceTable observes only absence or the compiler's exact
// single default route. The scalar is not interface, peer, receipt, source or
// mutation authority. The original WG issuer must hold its independent guards.
func ReadWGKernelServiceTable(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, table, family int, iface string) (int, error) {
	if provider == nil {
		return 0, ErrUnknown
	}
	return readWGKernelServiceTable(ctx, expected, table, family, iface, provider.WithCurrent, platformWGKernelRoutes, platformWGKernelLinks)
}

type wgKernelServiceRoute struct {
	oif     uint32
	present bool
}

const wgKernelRouteMaxBytes = 4 << 20 // Same complete-dump bound as the kernel transport.

func readWGKernelServiceTable(ctx context.Context, expected netidentity.Identity, table, family int, iface string, current func(context.Context, func(context.Context, netidentity.Identity) error) error, capture func(context.Context, byte) ([]message, error), links func(context.Context) ([]message, error)) (int, error) {
	if ctx == nil || ctx.Err() != nil || expected.Validate() != nil || table < 1 || uint64(table) > 0xffffffff || family != 4 && family != 6 || !interfaceName.MatchString(iface) || current == nil || capture == nil || links == nil {
		return 0, ErrUnknown
	}
	if _, finite := ctx.Deadline(); !finite {
		return 0, ErrUnknown
	}
	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	count, uses := 0, 0
	err := current(c, func(held context.Context, actual netidentity.Identity) error {
		uses++
		if uses != 1 || actual != expected || held.Err() != nil {
			return ErrUnknown
		}
		wireFamily := byte(2)
		if family == 6 {
			wireFamily = 10
		}
		read := func() (wgKernelServiceRoute, error) {
			leaf, stop := context.WithTimeout(held, 2*time.Second)
			defer stop()
			frames, err := capture(leaf, wireFamily)
			if err != nil {
				return wgKernelServiceRoute{}, err
			}
			route, err := wgKernelServiceTable(frames, uint32(table), family)
			return route, errors.Join(err, leaf.Err())
		}
		first, err := read()
		if err != nil {
			return err
		}
		if first.present {
			leaf, stop := context.WithTimeout(held, 2*time.Second)
			frames, err := links(leaf)
			var inventory []WGKernelLink
			if err == nil {
				inventory, err = wgKernelLinks(frames)
			}
			err = errors.Join(err, leaf.Err())
			stop()
			if err != nil {
				return err
			}
			matches := 0
			for _, link := range inventory {
				if link.Name == iface && uint32(link.Index) == first.oif {
					matches++
				}
			}
			if matches != 1 {
				return ErrUnknown
			}
		}
		last, err := read()
		if err != nil || first != last {
			return errors.Join(ErrUnknown, err)
		}
		if first.present {
			count = 1
		}
		return held.Err()
	})
	if err != nil || uses != 1 || c.Err() != nil {
		return 0, errors.Join(ErrUnknown, err, c.Err())
	}
	return count, nil
}

// Select by the numeric table before interpreting route payload. Foreign
// routes may have unrelated kinds/attributes; only their framing/table must
// be unambiguous. Table ambiguity cannot be filtered out as safely foreign.
func wgKernelRouteTable(frame message, family int) (uint32, error) {
	wireFamily := byte(2)
	if family == 6 {
		wireFamily = 10
	}
	if frame.kind != 24 || frame.flags != 2 || len(frame.data) < 12 || len(frame.data) > 64<<10 || frame.data[0] != wireFamily {
		return 0, ErrUnknown
	}
	header := uint32(frame.data[4])
	table := header
	found := false
	nattrs := 0
	for raw := frame.data[12:]; len(raw) > 0; {
		if len(raw) < 4 || nattrs >= 256 {
			return 0, ErrUnknown
		}
		nattrs++
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(raw) {
			return 0, ErrUnknown
		}
		kind := binary.NativeEndian.Uint16(raw[2:4])
		if kind&0x3fff == 15 {
			if kind != 15 || found || n != 8 {
				return 0, ErrUnknown
			}
			table = binary.NativeEndian.Uint32(raw[4:8])
			found = true
		}
		raw = raw[aligned:]
	}
	// Linux uses RT_TABLE_COMPAT252 for a table that does not fit rtmsg's
	// byte; VM557/firmware554 expose the actual uint32 RTA_TABLE as well.
	if found && table != header && !(header == 252 && table > 255) {
		return 0, ErrUnknown
	}
	if !found && header == 252 {
		return 0, ErrUnknown
	}
	return table, nil
}

func wgKernelServiceTable(frames []message, table uint32, family int) (wgKernelServiceRoute, error) {
	var result wgKernelServiceRoute
	if table == 0 || family != 4 && family != 6 || len(frames) > 8192 {
		return result, ErrUnknown
	}
	bytesRead := 0
	for _, frame := range frames {
		bytesRead += len(frame.data)
		if bytesRead > wgKernelRouteMaxBytes {
			return wgKernelServiceRoute{}, ErrUnknown
		}
		actual, err := wgKernelRouteTable(frame, family)
		if err != nil {
			return wgKernelServiceRoute{}, err
		}
		if actual != table {
			continue
		}
		if result.present {
			return wgKernelServiceRoute{}, ErrUnknown
		}
		data := frame.data
		scope := byte(253)
		width := 4
		if family == 6 {
			scope = 0
			width = 16
		}
		if data[1] != 0 || data[2] != 0 || data[3] != 0 || data[5] != 3 || data[6] != scope || data[7] != 1 || binary.NativeEndian.Uint32(data[8:12]) != 0 {
			return wgKernelServiceRoute{}, ErrUnknown
		}
		seen := map[uint16]bool{}
		oif, metric := uint32(0), uint32(0)
		metricPresent := false
		for raw := data[12:]; len(raw) > 0; {
			// Framing was checked before table classification. Reject all
			// unknown/duplicate/nested owned attributes and nonzero padding.
			n := int(binary.NativeEndian.Uint16(raw[:2]))
			aligned := (n + 3) &^ 3
			kind := binary.NativeEndian.Uint16(raw[2:4])
			value := raw[4:n]
			if seen[kind] || !bytes.Equal(raw[n:aligned], make([]byte, aligned-n)) {
				return wgKernelServiceRoute{}, ErrUnknown
			}
			seen[kind] = true
			switch kind {
			case 1:
				if len(value) != width || !bytes.Equal(value, make([]byte, width)) {
					return wgKernelServiceRoute{}, ErrUnknown
				}
			case 4:
				if len(value) != 4 {
					return wgKernelServiceRoute{}, ErrUnknown
				}
				oif = binary.NativeEndian.Uint32(value)
				if oif == 0 || oif > 0x7fffffff {
					return wgKernelServiceRoute{}, ErrUnknown
				}
			case 6:
				if len(value) != 4 {
					return wgKernelServiceRoute{}, ErrUnknown
				}
				metric = binary.NativeEndian.Uint32(value)
				metricPresent = true
			case 15: // Already checked the exact numeric table and uniqueness.
			case 12:
				if family != 6 || len(value) != 32 {
					return wgKernelServiceRoute{}, ErrUnknown
				} // volatile cache info, not a routing selector
			case 20:
				if family != 6 || len(value) != 1 || value[0] != 0 {
					return wgKernelServiceRoute{}, ErrUnknown
				} // medium preference
			default:
				return wgKernelServiceRoute{}, ErrUnknown
			}
			raw = raw[aligned:]
		}
		if !seen[4] || family == 4 && metric != 0 || family == 6 && (!metricPresent || metric != 1024) {
			return wgKernelServiceRoute{}, ErrUnknown
		}
		result = wgKernelServiceRoute{oif: oif, present: true}
	}
	return result, nil
}
