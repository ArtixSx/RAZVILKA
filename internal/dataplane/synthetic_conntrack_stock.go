package dataplane

import (
	"context"
	"encoding/binary"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type syntheticCTABI uint8

const (
	syntheticCTGeneric syntheticCTABI = iota
	syntheticCTStockNC1812
	syntheticCTStockScopeSHA256  = "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733"
	syntheticCTStockStatusMask   = uint32(0x01f03fff) // bits 0..13 and 20..24 only
	syntheticCTStockStatusUnsafe = uint32(0x01f00000)
)

func (a syntheticCTABI) valid() bool { return a == syntheticCTGeneric || a == syntheticCTStockNC1812 }

// The only production selections occur inside the ORIGINAL provider bracket.
// Identity selects a wire ABI, never ownership, settlement or an effect grant.
func syntheticCTABIForIdentity(actual netidentity.Identity) (syntheticCTABI, error) {
	if actual.Validate() != nil {
		return 0, syntheticCTFailure(syntheticCTScopeIdentity, nil)
	}
	switch actual.Kind {
	case netidentity.ProcNetInode:
		return syntheticCTGeneric, nil
	case netidentity.ReviewedSingleInitNet:
		if actual.PlatformReviewSHA256 == syntheticCTStockScopeSHA256 {
			return syntheticCTStockNC1812, nil
		}
	}
	return 0, syntheticCTFailure(syntheticCTScopeIdentity, nil)
}

// Keep the actual callback identity available to the read. The original
// owner's value is checked before admission; provider closing checks remain
// authoritative. There is no caller-selectable runtime ABI or profile catalog.
func syntheticCTWithOriginalIdentity(ctx context.Context, original *networkPolicyIdentity, use func(context.Context, netidentity.Identity) error) error {
	if ctx == nil || ctx.Err() != nil || original == nil || original.value.Validate() != nil || original.withCurrent == nil || use == nil {
		var cause error
		if ctx != nil {
			cause = ctx.Err()
		}
		return syntheticCTFailure(syntheticCTScopeIdentity, cause)
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return syntheticCTFailure(syntheticCTContext, nil)
	}
	expected := original.value
	calls := 0
	err := original.withCurrent(ctx, func(held context.Context, actual netidentity.Identity) error {
		calls++
		if calls != 1 || held == nil || held.Err() != nil || actual != expected {
			return syntheticCTFailure(syntheticCTScopeIdentity, nil)
		}
		if leaf, finite := held.Deadline(); !finite || leaf.After(deadline) {
			return syntheticCTFailure(syntheticCTContext, nil)
		}
		if _, err := syntheticCTABIForIdentity(actual); err != nil {
			return err
		}
		return use(held, actual)
	})
	if err != nil {
		if syntheticCTDiagnostic(err) != "unclassified" {
			return err
		}
		return syntheticCTFailure(syntheticCTScopeIdentity, err)
	}
	if calls != 1 || ctx.Err() != nil {
		return syntheticCTFailure(syntheticCTScopeIdentity, ctx.Err())
	}
	return nil
}

// Pinned producer, not the incoming request policy's CTA_NDMMARK .type=NLA_U8:
// keenetic/kernel-49@7b6c9477d429217042117fbfa3d2e9894a087607
// net/netfilter/nf_conntrack_netlink.c: ctnetlink_dump_ndmmark/ndm_ifaces/id
// net/netfilter/nf_ntce.c: nf_ntce_ctnetlink_dump
// include/uapi/linux/netfilter/nfnetlink_conntrack.h: zero-based child enums
// include/net/netlink.h: nla_put_be32 copies bytes without adding flags
// include/net/netfilter/nf_ntce.h: NTCE flags 0x1/0x2/0x4
// nf_nsc.h + xt_connndmmark.h: SC = (mark & 0x1c) >> 2
// All fields are comparable and retained in two-image comparison. Padding is
// validated, then omitted as nonsemantic. Presence, including a zero mark,
// makes the row Unsafe. No vendor field establishes a flow owner.
type syntheticCTStockObservation struct {
	NDMMarkPresent, IfacesPresent, NTCEPresent bool
	NDMMark                                    uint32 // native u32 copied without htonl, despite nla_put_be32 name
	Ifaces                                     syntheticCTStockIfaces
	NTCE                                       syntheticCTStockNTCE
}

type syntheticCTStockIfaces struct {
	WAN, LAN   int32 // native signed interface indices; no inferred direction
	MAC        [6]byte
	MACPresent bool
	Flags      uint32 // BE32 on wire; only FROM_WAN=1 is known
}

type syntheticCTStockNTCE struct {
	App, Group              uint32 // native u32
	Attributes              uint64 // native packed six attribute bytes; high 16 bits zero
	OS, Flags, ServiceClass uint8
}

// Only these two producer-specific nested containers admit child kind zero.
// The generic parser still rejects it everywhere. This is bounded by the
// largest exact NTCE container (56 bytes including its optional PAD).
func syntheticCTStockAttrs(v syntheticCTAttr, maxKind uint16, reason syntheticCTReason) (map[uint16]syntheticCTAttr, error) {
	if v.flags != 0x8000 || len(v.data) == 0 || len(v.data) > 56 {
		return nil, syntheticCTFailure(reason, nil)
	}
	out := map[uint16]syntheticCTAttr{}
	for b := v.data; len(b) != 0; {
		if len(b) < 4 {
			return nil, syntheticCTFailure(reason, nil)
		}
		n, kind := int(binary.NativeEndian.Uint16(b)), binary.NativeEndian.Uint16(b[2:])
		if n < 4 || n > len(b) || (n+3)&^3 > len(b) || kind > maxKind || !backendAllZero(b[n:(n+3)&^3]) {
			return nil, syntheticCTFailure(reason, nil)
		}
		if _, duplicate := out[kind]; duplicate {
			return nil, syntheticCTFailure(reason, nil)
		}
		out[kind] = syntheticCTAttr{data: b[4:n]} // raw kind check forbids child flags
		b = b[(n+3)&^3:]
	}
	return out, nil
}

func decodeSyntheticCTStockIfaces(v syntheticCTAttr) (syntheticCTStockIfaces, error) {
	var out syntheticCTStockIfaces
	a, err := syntheticCTStockAttrs(v, 3, syntheticCTStockIfacesShape)
	if err != nil {
		return out, err
	}
	if !a[0].scalar(4, false) || !a[1].scalar(4, false) || !a[3].scalar(4, false) {
		return out, syntheticCTFailure(syntheticCTStockIfacesShape, nil)
	}
	out.WAN, out.LAN = int32(binary.NativeEndian.Uint32(a[0].data)), int32(binary.NativeEndian.Uint32(a[1].data))
	out.Flags = binary.BigEndian.Uint32(a[3].data)
	if out.Flags&^uint32(1) != 0 {
		return out, syntheticCTFailure(syntheticCTStockIfacesShape, nil)
	}
	if mac, present := a[2]; present {
		if !mac.scalar(6, false) {
			return out, syntheticCTFailure(syntheticCTStockIfacesShape, nil)
		}
		out.MAC, out.MACPresent = [6]byte(mac.data), true
	}
	return out, nil
}

func decodeSyntheticCTStockNTCE(v syntheticCTAttr) (syntheticCTStockNTCE, error) {
	var out syntheticCTStockNTCE
	a, err := syntheticCTStockAttrs(v, 6, syntheticCTStockNTCEShape)
	if err != nil {
		return out, err
	}
	if !a[0].scalar(4, false) || !a[1].scalar(4, false) || !a[2].scalar(8, false) || !a[3].scalar(1, false) || !a[4].scalar(1, false) || !a[5].scalar(1, false) {
		return out, syntheticCTFailure(syntheticCTStockNTCEShape, nil)
	}
	if pad, present := a[6]; present && !pad.scalar(0, false) {
		return out, syntheticCTFailure(syntheticCTStockNTCEShape, nil)
	}
	out.App, out.Group, out.Attributes = binary.NativeEndian.Uint32(a[0].data), binary.NativeEndian.Uint32(a[1].data), binary.NativeEndian.Uint64(a[2].data)
	out.OS, out.Flags, out.ServiceClass = a[3].data[0], a[4].data[0], a[5].data[0]
	if out.Attributes>>48 != 0 || out.Flags&^uint8(7) != 0 || out.ServiceClass > 7 {
		return out, syntheticCTFailure(syntheticCTStockNTCEShape, nil)
	}
	return out, nil
}
