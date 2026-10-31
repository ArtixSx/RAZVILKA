package dataplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// Actual DNS Manager, Store negative boundaries, operation Gate and control
// epoch. Only physical LAN classification is explicitly modeled here. Call
// before Build/Bind: the original Manager must freeze this SAME DNS definition.
func domainTCPFactoryResolver(t *testing.T, ctx context.Context, manager *dnscontrol.Manager, transport *SyntheticDNSTransportPlan, domain *DomainPolicyRuntimePlan, gate *operationgate.Gate, control *operationgate.ControlEpochReview) *dnscontrol.NetworkPolicyDNSResolver {
	t.Helper()
	cfg := config.Default()
	cfg.NetworkPolicy = config.CloneNetworkPolicy(domain.Policy)
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := dnscontrol.NewNetworkPolicyDNSExclusions(ctx, store, store.Get(), func(c context.Context, name string) ([]string, error) {
		if err := control.Current(c); err != nil {
			return nil, err
		}
		var ids []string
		for _, service := range domain.Services {
			for _, exact := range service.Domains {
				if exact == name {
					ids = append(ids, service.ID)
				}
			}
		}
		return ids, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := make([]dnscontrol.ClientDNSBinding, 0, len(transport.Definition.ExactNames))
	for _, name := range transport.Definition.ExactNames {
		bindings = append(bindings, dnscontrol.ClientDNSBinding{Client: transport.Definition.Client, Domain: name, ProfileID: "private"})
	}
	transport.DNS, err = manager.FreezeNetworkPolicyDNSPlan(ctx, domain.Generation, "private", bindings, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	authority := dnscontrol.NetworkPolicyDNSAuthority{Generation: domain.Generation, ControlEpoch: control.Reference().Sequence, BindingRevision: 1, Exclusions: exclusions.Stamp()}
	resolver, err := manager.NewNetworkPolicyDNSResolverForPlanWithOperations(ctx, transport.DNS, authority, gate, control.Current, func(c context.Context, client netip.Addr, name string) (dnscontrol.NetworkPolicyDNSAdmission, error) {
		if err := control.Current(c); err != nil {
			return dnscontrol.NetworkPolicyDNSAdmission{}, err
		}
		if client != transport.Definition.Client {
			return dnscontrol.NetworkPolicyDNSAdmission{}, dnscontrol.ErrNetworkPolicyDNSOutside
		}
		kind := "managed"
		if name != "" {
			kind = "baseline"
			for _, exact := range transport.Definition.ExactNames {
				if exact == name {
					kind = "managed"
				}
			}
		}
		return dnscontrol.NetworkPolicyDNSAdmission{Authority: authority, Ingress: transport.Definition.Ingress, DeviceID: transport.Definition.DeviceID, Kind: kind}, nil
	}, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// No synthetic mapping struct, capture-ready callback or publication grant is
// fabricated. The registered adapter owns real UDP/TCP DNS sockets and its
// genuine source Reserve result remains unpublished for the caller's factory.
func domainTCPFactoryReserve(t *testing.T, ctx context.Context, binding *SyntheticDNSExecutionBinding, resolver *dnscontrol.NetworkPolicyDNSResolver, control *operationgate.ControlEpochReview) (*dnscontrol.NetworkPolicyDNSSyntheticResolver, *dnscontrol.SyntheticDNSMapping) {
	t.Helper()
	adapter := binding.adapter
	adapter.mu.Lock()
	err := adapter.startSyntheticDNSLocked(ctx, binding, resolver, control, nil)
	adapter.mu.Unlock()
	if err != nil {
		t.Fatal("original DNS session startup", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		adapter.mu.Lock()
		err := adapter.stopSyntheticDNSLocked(cleanup)
		adapter.mu.Unlock()
		if err != nil && !errors.Is(err, ErrSyntheticBaselineTransition) {
			t.Error("original DNS source cleanup", err)
		}
	})
	session, err := binding.originalSyntheticSession(control)
	if err != nil {
		t.Fatal(err)
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := session.synthetic.source.Reserve(ctx, binding.transport.Definition.Client, wire)
	if err != nil {
		t.Fatal("actual unpublished DNS Reserve", err)
	}
	observation, err := mapping.Observation(ctx)
	if err != nil || observation.PossiblyIssued || observation.QName != "service.example.com" || observation.RealIPv4 != netip.MustParseAddr("1.1.1.2") {
		t.Fatal("unexpected genuine reservation", err)
	}
	return session.synthetic.source, mapping
}

// Fresh child only: all addresses exist exclusively in its disposable network
// namespace. Real DNS bootstrap and verified TLS DoH exercise existing clients;
// test CA trust is confined to this child, never installed on the host/router.
func domainTCPFactoryLocalDoH(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getenv("RAZVILKA_DOMAIN_TCP_FACTORY_CHILD") != "1" {
		t.Fatal("local DoH fixture requires its disposable namespace child")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "1.1.1.1/32", "dev", "lo"}, {"addr", "add", "1.1.1.2/32", "dev", "lo"}, {"addr", "add", "192.168.1.1/24", "dev", "lo"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("isolated namespace setup: %v %s", err, output)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated DNS fixture"}, DNSNames: []string{"cloudflare-dns.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", roots)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", udp.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = oldResolver })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			reply, err := domainTCPFactoryDNSAnswer(buffer[:n], netip.MustParseAddr("1.1.1.1"))
			if err == nil {
				_, _ = udp.WriteTo(reply, peer)
			}
		}
	}()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(query) > 4096 {
			w.WriteHeader(400)
			return
		}
		reply, err := domainTCPFactoryDNSAnswer(query, netip.MustParseAddr("1.1.1.2"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(reply)
	}))
	server.Listener.Close()
	server.Listener, err = net.Listen("tcp4", "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
}
func domainTCPFactoryDNSAnswer(wire []byte, address netip.Addr) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(wire); err != nil {
		return nil, err
	}
	answer := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true, RecursionDesired: query.RecursionDesired}, Questions: query.Questions}
	for _, q := range query.Questions {
		if q.Type == dnsmessage.TypeA {
			answer.Answers = append(answer.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address.As4()}})
		}
	}
	return answer.Pack()
}
func TestDomainTCPFactoryOriginalDNSReserve(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_TCP_FACTORY_NATIVE") != "1" {
		t.Skip("opt-in root disposable namespace original DNS source fixture")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux network namespaces required")
	}
	if os.Getenv("RAZVILKA_DOMAIN_TCP_FACTORY_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--fork", os.Args[0], "-test.run=^TestDomainTCPFactoryOriginalDNSReserve$", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_DOMAIN_TCP_FACTORY_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated DNS factory fixture: %v %s", err, output)
		}
		t.Log(string(output))
		return
	}
	domainTCPFactoryLocalDoH(t)
	manager, adapter, plan, scope, parent := syntheticExecutionModel(t)
	dns, err := dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	adapter.DNS = dns
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err = operationgate.InitializeSelfUpdateControl(held, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	domain, transport, err := plan.FrozenDomainTransport()
	if err != nil {
		t.Fatal(err)
	}
	resolver := domainTCPFactoryResolver(t, held, dns, transport, domain, gate, control)
	_, frozenTransport, _ := plan.FrozenDomainTransport()
	if !reflect.DeepEqual(frozenTransport, transport) {
		t.Fatal("fixture must freeze the original DNS definition before binding")
	}
	original := scope.contextWith(held)
	binding, err := manager.BindSyntheticDNSExecution(original, adapter, plan)
	if err != nil {
		t.Fatal(err)
	}
	source, mapping := domainTCPFactoryReserve(t, original, binding, resolver, control)
	if _, err = source.LookupPublished(original, transport.Definition.Client, netip.MustParseAddr("198.18.0.1")); err == nil {
		t.Fatal("Reserve was mistaken for publication")
	}
	if err = mapping.Current(original); err != nil {
		t.Fatal(err)
	}
	t.Log("actual DNS Manager/Gate/control/source Reserve and registered UDP/TCP session; physical network identity remains an explicit model; no capture/publication/process/apply proof")
}
