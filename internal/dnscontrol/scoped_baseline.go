package dnscontrol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// UseLocalBaseline must be called before Serve. Unselected names retain the
// router's existing DNS policy. Only the exact loopback DNS owner is queried;
// no external fallback or resolver discovered from a client packet is used.
// Selected names, including unsupported question types, NEVER use this path.
func (r *ScopedDNSResolver) UseLocalBaseline(endpoint netip.AddrPort) error {
	if !endpoint.IsValid() || !endpoint.Addr().IsLoopback() || endpoint.Addr().Is4In6() || endpoint.Port() != 53 {
		return ErrScopedDNS
	}
	r.baseline = func(ctx context.Context, query []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.String())
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		return exchangeFramedDNS(conn, query)
	}
	return nil
}

func scopedBaselineQuestion(wire []byte) (dnsmessage.Message, int, error) {
	var q dnsmessage.Message
	if len(wire) < 12 || len(wire) > 4096 || q.Unpack(wire) != nil || q.Response || q.OpCode != 0 || q.Truncated || !q.RecursionDesired || q.RCode != 0 || len(q.Questions) != 1 || len(q.Answers) != 0 || len(q.Authorities) != 0 || len(q.Additionals) > 1 || q.Questions[0].Class != dnsmessage.ClassINET {
		return q, 0, ErrScopedDNS
	}
	size := 512
	for _, rr := range q.Additionals {
		if _, ok := rr.Body.(*dnsmessage.OPTResource); !ok || rr.Header.Name.String() != "." {
			return q, 0, ErrScopedDNS
		}
		size = max(512, min(1232, int(rr.Header.Class)))
	}
	return q, size, nil
}

func (r *ScopedDNSResolver) resolveClient(ctx context.Context, client netip.Addr, query []byte) ([]byte, int, error) {
	q, size, err := scopedBaselineQuestion(query)
	if err != nil || !r.hasClient(client) {
		return nil, 0, ErrScopedDNS
	}
	key := scopedDNSKey{client, strings.ToLower(strings.TrimSuffix(q.Questions[0].Name.String(), "."))}
	if _, selected := r.choices[key]; selected || r.baseline == nil {
		wire, err := r.Resolve(ctx, client, query)
		return wire, size, err
	}
	if err := r.guard(ctx); err != nil {
		return nil, 0, err
	}
	wire, err := r.baseline(ctx, query)
	if err != nil {
		return nil, 0, err
	}
	if err := errors.Join(ctx.Err(), r.guard(ctx)); err != nil {
		return nil, 0, err
	}
	var answer dnsmessage.Message
	if len(wire) < 12 || len(wire) > 65535 || answer.Unpack(wire) != nil || !answer.Response || answer.OpCode != q.OpCode || answer.ID != q.ID || !reflect.DeepEqual(answer.Questions, q.Questions) {
		return nil, 0, errDNSAnswer
	}
	return wire, size, nil
}
