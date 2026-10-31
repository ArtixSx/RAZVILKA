//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestMain(m *testing.M) {
	// Actual supervisor ABI dispatch, before Go's flag parser. The production
	// helper still validates protected original intent and fixed environment.
	if len(os.Args) == 3 {
		switch os.Args[1] {
		case "nfqws-compatibility-supervisor":
			os.Exit(strategylab.RunCompatibilitySupervisor(os.Args[2], os.Getenv("RAZVILKA_STRATEGY_LAB_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE")))
		case "nfqws-managed-process-supervisor":
			os.Exit(dataplane.RunNFQWSManagedProcessSupervisor(os.Args[2], filepath.Join(os.Getenv("RAZVILKA_DATAPLANE_STATE"), "runtime", "nfqws2"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE")))
		}
	}
	os.Exit(m.Run())
}

type managedProbeNativeAdmission struct {
	consumer *dataplane.ManagedNFQWSProbeConsumer
}

func (a *managedProbeNativeAdmission) WithStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	if a.consumer == nil || !a.consumer.OwnsContext(ctx) {
		return dataplane.ErrNFQWSScopedOwner
	}
	if a.consumer.ProbeCounterCommandCurrent(ctx, name, args, digest) == nil {
		return a.consumer.WithProbeCounterCommandStart(ctx, name, args, digest, begin)
	}
	return dataplane.WithNFQWSScopedCommandStart(ctx, name, args, digest, begin)
}

// Opt-in isolated ROOT experiment. Only platform/architecture classification
// and WAN ID are modeled. Artifact bytes, installer/receipt, source validation,
// held descriptor/tool graph, serial lease, socket, queue, TLS/HTTP criteria,
// actual positive+negative packets and cleanup are the production consumers.
func TestManagedStrategyProbeNativeConsumer(t *testing.T) {
	if os.Getenv("RAZVILKA_MANAGED_PROBE_NATIVE") != "1" {
		t.Skip("explicit isolated native fixture only")
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	initial, e := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || err != nil || e != nil || ns == initial {
		t.Fatal("ROOT non-init network namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := func(args ...string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput()
		if err != nil {
			t.Fatal(args, string(out), err)
		}
	}
	out, err := exec.CommandContext(ctx, "/usr/sbin/ip", "-o", "link", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.Contains(line, ": lo:") {
			t.Fatal("refusing namespace with preexisting interface", line)
		}
	}
	command("link", "set", "lo", "up")
	command("addr", "add", "8.8.8.8/32", "dev", "lo")
	// The real installer publishes immutable public-traversable generations.
	// Keep them below a new protected /var/lib leaf, since production source
	// guards deliberately refuse public payload directories below sticky /tmp.
	root, err := os.MkdirTemp("/var/lib", "razvilka-probe-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	serveManagedProbeNativeTLS(t, root)
	provider := netidentity.NewProcProvider()
	tools, err := startuptools.AcquireNativeFixturePolicy(ctx, provider, os.Getenv("RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW"))
	if err != nil {
		managedProbeNativeErrorChain(t, err, 0)
		t.Fatal("actual protected tool closure", err)
	}
	defer tools.Close()
	descriptor, err := tools.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := dataplane.NewBackendInventory(provider, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readEmpty := func(c context.Context) error {
		view, err := inventory.Read(c, identity)
		if err != nil {
			return err
		}
		if err := view.RequireComplete(); err != nil {
			return err
		}
		for _, row := range view.Rows {
			for _, token := range row.Tokens {
				if token == "NFQUEUE" || token == "QUEUE" || strings.HasPrefix(token, "RZP_") {
					return dataplane.ErrNFQWSScopedOwner
				}
			}
		}
		return nil
	}
	if err := readEmpty(ctx); err != nil {
		managedProbeNativeErrorChain(t, err, 0)
		t.Fatal("native empty packet namespace", err)
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	lab, err := strategylab.New(filepath.Join(root, "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	lab.Validator, lab.Executor = strategylab.CompatibleValidator{}, nil
	controlRoot := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, StrategyLab: lab, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: controlRoot}, FreshProfile: func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }}
	original, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := a.Operations.ReviewControlEpoch(original, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err := lab.InitializeManagedCompatibilitySource(original, control); err != nil {
		t.Fatal(err)
	}
	inactive, err := lab.ReviewManagedCompatibilityInactive(original, control)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	ref := control.Reference()
	revision := store.Get().Revision
	check := func(c context.Context, id string, seq, rev uint64, reader int) error {
		if id != ref.InstallationID || seq != ref.Sequence || rev != revision || reader != 3 {
			return components.ErrRecoveryAuthority
		}
		return control.Current(c)
	}
	owner, err := components.InstallNativeFixtureManagedNFQWS(original, bundle, os.Getenv("RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW"), revision, components.ManagedNFQWSBundleAuthority{InstallationID: ref.InstallationID, Sequence: ref.Sequence, ReaderVersion: 3, Check: check,
		Admit: func(c context.Context, tx, id string, seq, rev uint64, effect string, begin func() error) error {
			if err := check(c, id, seq, rev, 3); err != nil {
				return err
			}
			return control.WithStart(c, begin)
		},
		Inactive: func(c context.Context) error { return errors.Join(inactive.Current(c), readEmpty(c)) }})
	if err != nil {
		t.Fatal("actual artifact installation", err)
	}
	a.Components = owner
	bootstrap, err := owner.AcquireCurrentManagedNFQWSRuntime(original)
	if err != nil {
		t.Fatal(err)
	}
	p, v, err := strategylab.NewManagedSupervisedCompatibilityProvider(original, lab, bootstrap, control, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.InstallManagedCompatibilityValidator(original, control, p, v, inactive); err != nil {
		t.Fatal(err)
	}
	_ = inactive.Close()
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	candidate, err := lab.AddCandidate("tcp-tls", "native isolated original candidate", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	validationRuntime, err := owner.AcquireCurrentManagedNFQWSRuntime(original)
	if err != nil {
		t.Fatal(err)
	}
	validated, completion, err := lab.ValidateManagedCandidate(original, candidate.ID, validationRuntime)
	if err != nil || completion == nil || !validated.Validation.OK || !validated.Validation.Native {
		t.Fatal("actual managed validation", validated.Validation, err)
	}
	if err := completion.RetireKnown(original); err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(filepath.Join(root, "dataplane"))
	manager.FreshProfile = a.FreshProfile
	a.Dataplane = manager
	adapter := dataplane.NewNFQWS2Adapter()
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	policyTools, runner, err := tools.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	admission := &managedProbeNativeAdmission{}
	current := func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
		if admission.consumer == nil || p != nil {
			return dataplane.ErrNFQWSScopedOwner
		}
		return admission.consumer.ScopeCurrent(c, "")
	}
	denyEffect := func(context.Context, *dataplane.LANPolicyRuntimePlan, dataplane.LANPolicyEffect) error {
		return dataplane.ErrNFQWSScopedOwner
	}
	gate, err := dataplane.NewNetworkPolicyAdapter(original, dataplane.NetworkPolicyAssemblyOptions{Mode: dataplane.LANPolicyManagedListMode, Provider: provider, Binding: &dataplane.LANPolicyReceiptBinding{Runtime: &dataplane.LANPolicyRuntime{Runner: runner, IP: policyTools.IP, IPTables: policyTools.IPTables, IP6Tables: policyTools.IP6Tables, ScopeCheck: current}, ApplyGuard: denyEffect, CleanupGuard: denyEffect, RetireCheck: current}, InventoryCheck: func(c context.Context, id netidentity.Identity, p *dataplane.LANPolicyRuntimePlan) error {
		if id != identity {
			return dataplane.ErrNetworkPolicyIdentity
		}
		view, err := inventory.Read(c, id)
		if err != nil {
			return err
		}
		return view.RequireComplete()
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(gate); err != nil {
		t.Fatal(err)
	}
	consumer, err := dataplane.NewManagedNFQWSProbeConsumer(manager, gate, inventory, control, controlRoot, provider, ctx)
	if err != nil {
		t.Fatal(err)
	}
	admission.consumer = consumer
	service := catalog.Service{ID: "native", Name: "Native isolated TLS", Domains: []string{"managed-probe.example"}, ProbeURL: "https://managed-probe.example/", Probes: []catalog.Probe{{ID: "primary", URL: "https://managed-probe.example/", Required: true, Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, BodyContains: []string{"owned-native-service"}}}}}
	a.Catalog = catalog.Catalog{Services: []catalog.Service{service}}
	criteria, err := strategylab.ManagedProbeCriteriaDigest(service)
	if err != nil {
		t.Fatal(err)
	}
	scope := strategylab.CandidateProbeScope{Target: strategylab.ProbeTarget{ServiceID: service.ID, ProbeURL: service.ProbeURL, Protocol: "tcp", IPFamily: "ipv4"}, Address: netip.MustParseAddr("8.8.8.8"), CriteriaDigest: criteria}
	runtime, err := owner.AcquireCurrentManagedNFQWSRuntime(original)
	if err != nil {
		t.Fatal(err)
	}
	source, err := lab.RetainCandidateProbeReview(original, candidate.ID, scope, runtime)
	if err != nil {
		t.Fatal(err)
	}
	env, err := newManagedStrategyProbeEnvironment(original, a, control, runtime, service, scope)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := lab.BeginManagedProbe(original, source, env, env.networkID, env.policyHash)
	if err != nil {
		t.Fatal(err)
	}
	probeCtx, probeCancel := context.WithTimeout(original, 14*time.Second)
	defer probeCancel()
	probeCtx = startuptools.WithCommandAdmission(probeCtx, admission)
	evidence, cleaned, err := consumer.Execute(probeCtx, source, epoch, runtime, service, revision, env.Current)
	if err != nil || cleaned == nil {
		t.Fatal("actual managed kernel/flow consumer", evidence, err)
	}
	if !evidence.Success || !evidence.RouteConfirmed || evidence.HTTPStatus != 200 {
		t.Fatal("native flow not confirmed", evidence)
	}
	if err := epoch.Finish(original, &evidence, nil); err != nil {
		t.Fatal(err)
	}
	if err := cleaned.CloseRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := env.runtimeRetired(); err != nil {
		t.Fatal(err)
	}
	if err := readEmpty(original); err != nil {
		t.Fatal("actual cleanup retained queue/rules", err)
	}
	snapshot := lab.SnapshotWithContext(original)
	if len(snapshot.Evidence) != 1 || snapshot.QuiescenceUnknown {
		t.Fatal("native publication missing or fenced", snapshot)
	}
	t.Log("actual isolated consumer: managed native validation + held source socket + queue200 + wrong-source negative + exact counters + TLS/catalogue predicates + soleWait/ACK + COMMON cleanup; platform/WAN classification modeled; no router/LAN acceptance")
}

func managedProbeNativeErrorChain(t *testing.T, err error, depth int) {
	if err == nil || depth > 12 {
		return
	}
	t.Logf("native diagnostic[%d] %T: %v", depth, err, err)
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range many.Unwrap() {
			managedProbeNativeErrorChain(t, child, depth+1)
		}
	} else if one, ok := err.(interface{ Unwrap() error }); ok {
		managedProbeNativeErrorChain(t, one.Unwrap(), depth+1)
	}
}

func serveManagedProbeNativeTLS(t *testing.T, root string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "managed-probe.example"}, DNSNames: []string{"managed-probe.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "native-ca.pem")
	if err := os.WriteFile(path, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	listener, err := net.Listen("tcp4", "8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("owned-native-service"))
	}), ReadHeaderTimeout: 2 * time.Second}
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() { _ = server.Close() })
}
