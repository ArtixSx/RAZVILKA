package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"golang.org/x/net/dns/dnsmessage"
)

// These are independent transport health targets, never a client DNS profile,
// destination exclusion, flow classifier, or fallback resolver. A network peer
// which cannot carry them cannot claim complete TCP/UDP family health.
const wgNetworkHealthVersion = 1

func wgNetworkUDPTarget(source netip.Addr) netip.AddrPort {
	if source.Is4() {
		return netip.MustParseAddrPort("1.1.1.1:53")
	}
	return netip.MustParseAddrPort("[2606:4700:4700::1111]:53")
}

func wgNetworkUDPQuestion(source netip.Addr) ([]byte, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	typ := dnsmessage.TypeA
	if source.Is6() {
		typ = dnsmessage.TypeAAAA
	}
	question := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("www.cloudflare.com."), Type: typ, Class: dnsmessage.ClassINET}},
	}
	return question.Pack()
}

func validateWGNetworkUDPAnswer(query, wire []byte) error {
	var request, reply dnsmessage.Message
	if len(query) > 4096 || request.Unpack(query) != nil || len(request.Questions) != 1 || len(wire) < 12 || len(wire) > 4096 || reply.Unpack(wire) != nil || !reply.Response || reply.Truncated || reply.OpCode != request.OpCode || reply.ID != request.ID || reply.RCode != dnsmessage.RCodeSuccess || !reflect.DeepEqual(reply.Questions, request.Questions) {
		return errors.New("WireGuard network UDP health reply identity is invalid")
	}
	for _, answer := range reply.Answers {
		if answer.Header.Class != dnsmessage.ClassINET || answer.Header.Type != request.Questions[0].Type {
			continue
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			if publicfetch.PublicAddress(netip.AddrFrom4(body.A)) {
				return nil
			}
		case *dnsmessage.AAAAResource:
			if publicfetch.PublicAddress(netip.AddrFrom16(body.AAAA)) {
				return nil
			}
		}
	}
	return errors.New("WireGuard network UDP health reply has no public address in the selected family")
}

func exchangeWGNetworkUDP(ctx context.Context, conn net.Conn, query []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if n, err := conn.Write(query); err != nil || n != len(query) {
		return errors.Join(err, errors.New("WireGuard network UDP health query was not sent completely"))
	}
	buffer := make([]byte, 4097)
	n, err := conn.Read(buffer)
	if err := errors.Join(ctx.Err(), err); err != nil {
		return err
	}
	return validateWGNetworkUDPAnswer(query, buffer[:n])
}

func sourceBoundWGNetworkUDPProbe(ctx context.Context, source netip.Addr) error {
	device, _ := ctx.Value(wgSocketInterfaceKey{}).(string)
	if !source.IsValid() || source.Is4In6() || source.Zone() != "" || !source.IsGlobalUnicast() || device == "" {
		return errors.New("WireGuard network UDP health requires its own tunnel address and device")
	}
	query, err := wgNetworkUDPQuestion(source)
	if err != nil {
		return err
	}
	family := "udp4"
	if source.Is6() {
		family = "udp6"
	}
	conn, err := wgSocketDialer(ctx, net.IP(source.AsSlice()), true).DialContext(ctx, family, wgNetworkUDPTarget(source).String())
	if err != nil {
		return err
	}
	defer conn.Close()
	return exchangeWGNetworkUDP(ctx, conn, query)
}

// Caller has already installed private source+oif health selectors. Every
// selected family needs its own TCP service evidence and independent UDP reply;
// a handshake or another family's success cannot stand in for either class.
func (a *WARPWireGuardAdapter) probeWGNetworkFamilies(ctx context.Context, plan RoutePlan, root string, sources []netip.Addr,
	tcp func(context.Context, string, string) error, udp func(context.Context, netip.Addr) error) error {
	if len(sources) == 0 || len(sources) > 2 || tcp == nil || udp == nil {
		return errors.New("WireGuard network transport health is incomplete")
	}
	seen := map[bool]bool{}
	for _, source := range sources {
		if err := checkWGNetworkReview(ctx); err != nil {
			return err
		}
		if !source.IsValid() || seen[source.Is4()] {
			return errors.New("WireGuard network health family is invalid or duplicate")
		}
		seen[source.Is4()] = true
		if err := a.probeCanaryServices(ctx, plan, root, tcp, source.String()); err != nil {
			return fmt.Errorf("WireGuard network %s TCP health: %w", canarySourceFamily(source), err)
		}
		if err := checkWGNetworkReview(ctx); err != nil {
			return err
		}
		if err := udp(ctx, source); err != nil {
			return fmt.Errorf("WireGuard network %s UDP health: %w", canarySourceFamily(source), err)
		}
		if err := checkWGNetworkReview(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}
