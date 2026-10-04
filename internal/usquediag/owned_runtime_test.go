package usquediag

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// These fixtures never use production observers, sockets, processes or procfs.
// Reads return copies because the observer erases private input buffers.
type ownedRuntimeFixture struct {
	request                                                OwnedRuntimeRequest
	files                                                  map[string][]byte
	io                                                     ownedRuntimeIO
	passport                                               routeidentity.Passport
	owners                                                 []string
	readCalls, fdCalls, verifyCalls, hashCalls, epochCalls int
}

const ownedFixtureExecutableSHA = "a3ad4dce52cc33825fd8bfab520bb2a03f80891b69920819aa391d6a42c6bf10"

func newOwnedRuntimeFixture(t *testing.T, transport string) *ownedRuntimeFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "canary")
	f := &ownedRuntimeFixture{files: map[string][]byte{}, owners: []string{"5:900", "6:901"}}
	f.request = OwnedRuntimeRequest{Root: root, Binary: filepath.Join(filepath.Dir(root), "usque"), SOCKSAddress: "127.0.0.1:18081", Transport: transport, Endpoint: netip.MustParseAddrPort("162.159.193.10:443")}
	f.request.Environment = func(context.Context) (string, error) {
		f.epochCalls++
		return routeidentity.Hash([]byte("current-trusted-wan-epoch")), nil
	}
	config, err := json.Marshal(map[string]string{"private_key": "PRIVATE-KEY-FIXTURE", "endpoint_pub_key": "PRIVATE-PUBKEY-FIXTURE", "id": "PRIVATE-ID-FIXTURE", "access_token": "PRIVATE-TOKEN-FIXTURE", "endpoint_v4": f.request.Endpoint.Addr().String(), "endpoint_h2_v4": f.request.Endpoint.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	f.files[filepath.Join(root, "engine.json")] = config
	args := []string{f.request.Binary, "-c", filepath.Join(root, "engine.json"), "socks", "-b", "127.0.0.1", "-p", "18081", "--always-reconnect", "-S", "-s", "cloudflareclient.com"}
	if transport == "HTTP/2" {
		args = append(args, "--http2")
	}
	f.files["/proc/42/cmdline"] = []byte(strings.Join(args, "\x00") + "\x00")
	f.files["/proc/42/environ"] = []byte("LANG=C\x00HOME=/inert-fixture\x00HTTPS_PROXY=\x00")
	f.passport = routeidentity.Passport{ID: "managed:usque:" + routeidentity.Hash([]byte("launch-receipt-and-listener-900")), Outbound: "masque", PID: 42, ConfigHash: routeidentity.Hash(config)}
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f.files["/proc/42/net/"+table] = []byte(ownedFixtureTableHeader)
	}
	f.files["/proc/42/net/tcp"] = append(f.files["/proc/42/net/tcp"], []byte(ownedFixtureSocketRow("127.0.0.1:18081", "0.0.0.0:0", "0A", "900", true))...)
	if transport == "HTTP/2" {
		f.files["/proc/42/net/tcp"] = append(f.files["/proc/42/net/tcp"], []byte(ownedFixtureSocketRow("192.0.2.10:51900", f.request.Endpoint.String(), "01", "901", true))...)
	} else {
		f.files["/proc/42/net/udp"] = append(f.files["/proc/42/net/udp"], []byte(ownedFixtureSocketRow("192.0.2.10:51900", "0.0.0.0:0", "07", "901", true))...)
	}
	f.io = ownedRuntimeIO{
		read: func(path string, limit int64) ([]byte, error) {
			f.readCalls++
			data, ok := f.files[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			if int64(len(data)) > limit {
				return nil, errors.New("fixture-read-limit")
			}
			return append([]byte(nil), data...), nil
		},
		fds: func(pid int) ([]string, error) {
			f.fdCalls++
			if pid != 42 {
				return nil, errors.New("fixture-wrong-pid")
			}
			return append([]string(nil), f.owners...), nil
		},
		verify: func(gotRoot, engine, listener string) (routeidentity.Passport, error) {
			f.verifyCalls++
			if gotRoot != root || engine != "usque" || listener != f.request.SOCKSAddress {
				return routeidentity.Passport{}, errors.New("fixture-wrong-runtime")
			}
			return f.passport, nil
		},
		hash: func(pid int, binary string) (string, error) {
			f.hashCalls++
			if pid != 42 || binary != f.request.Binary {
				return "", errors.New("fixture-wrong-executable")
			}
			return ownedFixtureExecutableSHA, nil
		},
		little: true,
	}
	return f
}

const ownedFixtureTableHeader = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func ownedFixtureSocketRow(local, remote, state, inode string, little bool) string {
	return fmt.Sprintf("0: %s %s %s 00000000:00000000 00:00000000 00000000 0 0 %s\n", ownedFixtureProcAddress(netip.MustParseAddrPort(local), little), ownedFixtureProcAddress(netip.MustParseAddrPort(remote), little), state, inode)
}

func ownedFixtureProcAddress(address netip.AddrPort, little bool) string {
	var order binary.ByteOrder = binary.BigEndian
	if little {
		order = binary.LittleEndian
	}
	data := address.Addr().AsSlice()
	var encoded strings.Builder
	for i := 0; i < len(data); i += 4 {
		fmt.Fprintf(&encoded, "%08X", order.Uint32(data[i:i+4]))
	}
	return fmt.Sprintf("%s:%04X", encoded.String(), address.Port())
}

func ownedFixtureIdentity() OwnedRuntimeIdentity {
	i := OwnedRuntimeIdentity{RuntimeID: "managed:usque:" + routeidentity.Hash([]byte("launch-and-listener")), BinarySHA256: ownedFixtureExecutableSHA, SessionSHA256: routeidentity.Hash([]byte("actual-runtime-session")), ArgsSHA256: routeidentity.Hash([]byte("actual-exact-argv")), EnvironmentID: routeidentity.Hash([]byte("trusted-current-epoch")), Transport: "HTTP/2", Endpoint: "162.159.193.10:443", PeerObservation: "tcp-established-peer", SocketBinding: routeidentity.Hash([]byte("tcp|901|192.0.2.10:51900|162.159.193.10:443")), SourceCommit: ownedUSQUESource}
	i.BindingID = ownedIdentityBinding(i)
	return i
}

func ownedFixtureOptions(t *testing.T) OwnedProbeOptions {
	t.Helper()
	f := newOwnedRuntimeFixture(t, "HTTP/2")
	return OwnedProbeOptions{Enabled: true, Runtime: f.request, Network: OwnedNetworkRequest{SOCKSAddress: f.request.SOCKSAddress, Services: []OwnedServiceProbe{{ID: "fixture-service", URL: "https://example.com/probe"}}}, Authority: func(context.Context) error { return nil }}
}

func requireOwnedRuntimeError(t *testing.T, got OwnedRuntimeIdentity, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != code || got != (OwnedRuntimeIdentity{}) {
		t.Fatalf("identity=%+v err=%v want=%s", got, err, code)
	}
}

func requireOwnedProbeError(t *testing.T, got OwnedRuntimeEvidence, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != code || got.Origin != "" || got.Identity != (OwnedRuntimeIdentity{}) || len(got.ConfirmedRoutes) != 0 {
		t.Fatalf("evidence=%+v err=%v want=%s", got, err, code)
	}
}

func TestOwnedProducerPreflightHasNoCallbacksOrIO(t *testing.T) {
	for _, name := range []string{"disabled", "no-authority", "relative-root", "relative-binary", "no-epoch", "private-pin", "bad-listener", "different-listeners", "invalid-service", "canceled"} {
		t.Run(name, func(t *testing.T) {
			o := ownedFixtureOptions(t)
			ctx := context.Background()
			calls := 0
			o.Authority = func(context.Context) error { calls++; return nil }
			o.Runtime.Environment = func(context.Context) (string, error) { calls++; return "", nil }
			want := "owned-runtime-options-invalid"
			switch name {
			case "disabled":
				o.Enabled = false
				want = "owned-probe-admission-required"
			case "no-authority":
				o.Authority = nil
				want = "owned-probe-admission-required"
			case "relative-root":
				o.Runtime.Root = "relative"
			case "relative-binary":
				o.Runtime.Binary = "usque"
			case "no-epoch":
				o.Runtime.Environment = nil
			case "private-pin":
				o.Runtime.Endpoint = netip.MustParseAddrPort("192.168.1.1:443")
			case "bad-listener":
				o.Runtime.SOCKSAddress = "127.0.0.1:80"
				want = "owned-runtime-listener-invalid"
			case "different-listeners":
				o.Network.SOCKSAddress = "127.0.0.1:18082"
				want = "owned-probe-listener-mismatch"
			case "invalid-service":
				o.Network.Services[0].URL = "http://example.com/probe"
				want = "owned-network-request-invalid"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = "owned-probe-canceled"
			}
			observe := func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				calls++
				return ownedFixtureIdentity(), nil
			}
			probe := func(context.Context, OwnedNetworkRequest) (OwnedApplicationProof, error) {
				calls++
				return OwnedApplicationProof{Warp: "on"}, nil
			}
			got, err := probeOwnedUSQUE(ctx, o, observe, probe, func() time.Time { calls++; return time.Now() })
			requireOwnedProbeError(t, got, err, want)
			if calls != 0 {
				t.Fatalf("preflight executed %d callbacks", calls)
			}
		})
	}
}

func TestOwnedProducerRereadsAdmission(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("refusal-%d", failAt), func(t *testing.T) {
			o := ownedFixtureOptions(t)
			authorities, observations, probes := 0, 0, 0
			o.Authority = func(context.Context) error {
				authorities++
				if authorities == failAt {
					return errors.New("revoked")
				}
				return nil
			}
			observe := func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				observations++
				return ownedFixtureIdentity(), nil
			}
			probe := func(context.Context, OwnedNetworkRequest) (OwnedApplicationProof, error) {
				probes++
				return OwnedApplicationProof{Warp: "on"}, nil
			}
			got, err := probeOwnedUSQUE(context.Background(), o, observe, probe, func() time.Time { return time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC) })
			requireOwnedProbeError(t, got, err, "owned-probe-admission-refused")
			wantObservations, wantProbes := failAt-1, 0
			if failAt == 3 {
				wantProbes = 1
			}
			if authorities != failAt || observations != wantObservations || probes != wantProbes {
				t.Fatalf("authority=%d observe=%d probe=%d", authorities, observations, probes)
			}
		})
	}
}

func TestOwnedProducerRejectsBeforeAfterDrift(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*OwnedRuntimeIdentity)
	}{
		{"runtime-listener", func(i *OwnedRuntimeIdentity) { i.RuntimeID += "-changed" }},
		{"epoch", func(i *OwnedRuntimeIdentity) { i.EnvironmentID = routeidentity.Hash([]byte("new-wan")) }},
		{"binary", func(i *OwnedRuntimeIdentity) { i.BinarySHA256 = ownedUSQUEArm64SHAForFixture() }},
		{"config-session", func(i *OwnedRuntimeIdentity) { i.SessionSHA256 = routeidentity.Hash([]byte("new-session")) }},
		{"args", func(i *OwnedRuntimeIdentity) { i.ArgsSHA256 = routeidentity.Hash([]byte("new-args")) }},
		{"socket", func(i *OwnedRuntimeIdentity) { i.SocketBinding = routeidentity.Hash([]byte("new-socket")) }},
		{"peer", func(i *OwnedRuntimeIdentity) { i.Endpoint = "162.159.193.11:443" }},
		{"peer-kind", func(i *OwnedRuntimeIdentity) { i.PeerObservation = "udp-connected-default-peer" }},
		{"transport", func(i *OwnedRuntimeIdentity) { i.Transport = "QUIC" }},
		{"source", func(i *OwnedRuntimeIdentity) { i.SourceCommit = strings.Repeat("1", 40) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			count := 0
			observe := func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				count++
				i := ownedFixtureIdentity()
				if count == 2 {
					tt.change(&i)
					i.BindingID = ownedIdentityBinding(i)
				}
				return i, nil
			}
			got, err := probeOwnedUSQUE(context.Background(), ownedFixtureOptions(t), observe, func(context.Context, OwnedNetworkRequest) (OwnedApplicationProof, error) {
				return OwnedApplicationProof{Warp: "plus"}, nil
			}, func() time.Time { return time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC) })
			requireOwnedProbeError(t, got, err, "owned-probe-runtime-changed")
		})
	}
}

func ownedUSQUEArm64SHAForFixture() string {
	return "8e8b0e141b59088eb1331876ad67a24e7ed4eb23ea6174bf63452d7545e2d002"
}

func TestOwnedProducerPathInferenceAndUDPForwardingAreSeparate(t *testing.T) {
	for _, transport := range []string{"HTTP/2", "QUIC"} {
		for _, udp := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/udp-%t", transport, udp), func(t *testing.T) {
				o := ownedFixtureOptions(t)
				o.Runtime.Transport = transport
				if udp {
					o.Network.UDP = &OwnedUDPProbe{Target: netip.MustParseAddrPort("8.8.8.8:9999")}
				}
				i := ownedFixtureIdentity()
				i.Transport = transport
				if transport == "QUIC" {
					i.PeerObservation = "udp-unconnected-exclusive-config-inference"
				}
				i.BindingID = ownedIdentityBinding(i)
				checked := time.Date(2026, 10, 4, 0, 0, 0, 123, time.UTC)
				proof := OwnedApplicationProof{Warp: "plus", ConfirmedRoutes: []string{"fixture-service"}, UDPConfirmed: udp}
				got, err := probeOwnedUSQUE(context.Background(), o, func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) { return i, nil }, func(_ context.Context, request OwnedNetworkRequest) (OwnedApplicationProof, error) {
					if (request.UDP != nil) != udp {
						t.Fatal("UDP challenge request lost")
					}
					return proof, nil
				}, func() time.Time { return checked })
				if err != nil {
					t.Fatal(err)
				}
				if got.Negotiated || got.ProofBasis != ownedPathBasis || got.ProtocolPath != transport || got.UDPForwarding != udp || got.Identity != i {
					t.Fatalf("incorrect proof semantics: %+v", got)
				}
				if !OwnedEvidenceFresh(got, i, checked) || OwnedEvidenceFresh(got, i, checked.Add(MaxCanaryAge)) {
					t.Fatalf("incorrect freshness: %+v", got)
				}
				proof.ConfirmedRoutes[0] = "changed-after-return"
				if len(got.ConfirmedRoutes) != 1 || got.ConfirmedRoutes[0] != "fixture-service" {
					t.Fatal("returned routes alias callback buffer")
				}
			})
		}
	}
}

func TestOwnedProducerRejectsInvalidWindowAndWARP(t *testing.T) {
	for _, name := range []string{"clock-backward", "too-long", "warp-off", "warp-missing", "canceled-during-probe"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
			end := started
			warp := "on"
			switch name {
			case "clock-backward":
				end = started.Add(-time.Nanosecond)
			case "too-long":
				end = started.Add(30*time.Second + time.Nanosecond)
			case "warp-off":
				warp = "off"
			case "warp-missing":
				warp = ""
			}
			clocks := 0
			got, err := probeOwnedUSQUE(ctx, ownedFixtureOptions(t), func(context.Context, OwnedRuntimeRequest) (OwnedRuntimeIdentity, error) {
				return ownedFixtureIdentity(), nil
			}, func(context.Context, OwnedNetworkRequest) (OwnedApplicationProof, error) {
				if name == "canceled-during-probe" {
					cancel()
				}
				return OwnedApplicationProof{Warp: warp}, nil
			}, func() time.Time {
				clocks++
				if clocks == 1 {
					return started
				}
				return end
			})
			requireOwnedProbeError(t, got, err, "owned-probe-window-invalid")
		})
	}
}

func TestOwnedEvidenceFreshnessRejectsStaleAndCurrentMismatch(t *testing.T) {
	checked := time.Date(2026, 10, 4, 0, 0, 0, 123, time.UTC)
	identity := ownedFixtureIdentity()
	base := OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: checked.Format(time.RFC3339Nano), ValidUntil: checked.Add(MaxCanaryAge).Format(time.RFC3339Nano), Identity: identity, ProofBasis: ownedPathBasis, ProtocolPath: "HTTP/2", Warp: "on"}
	if !OwnedEvidenceFresh(base, identity, checked.Add(time.Nanosecond)) {
		t.Fatal("valid current receipt refused")
	}
	for _, tt := range []struct {
		name   string
		change func(*OwnedRuntimeEvidence, *OwnedRuntimeIdentity, *time.Time)
	}{
		{"expired", func(_ *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, n *time.Time) { *n = checked.Add(MaxCanaryAge) }},
		{"future", func(_ *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, n *time.Time) {
			*n = checked.Add(-time.Nanosecond)
		}},
		{"invalid-time", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) { e.CheckedAt = "invalid" }},
		{"empty-window", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) { e.ValidUntil = e.CheckedAt }},
		{"long-window", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) {
			e.ValidUntil = checked.Add(MaxCanaryAge + time.Nanosecond).Format(time.RFC3339Nano)
		}},
		{"wrong-origin", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) { e.Origin = "external-ui" }},
		{"wrong-basis", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) { e.ProofBasis = "argv-only" }},
		{"negotiated-claim", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) { e.Negotiated = true }},
		{"warp-off", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) { e.Warp = "off" }},
		{"wrong-protocol", func(e *OwnedRuntimeEvidence, _ *OwnedRuntimeIdentity, _ *time.Time) { e.ProtocolPath = "QUIC" }},
		{"current-epoch", func(_ *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.EnvironmentID = routeidentity.Hash([]byte("new-epoch"))
			i.BindingID = ownedIdentityBinding(*i)
		}},
		{"current-runtime", func(_ *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.RuntimeID += "-restart"
			i.BindingID = ownedIdentityBinding(*i)
		}},
		{"current-binary", func(_ *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.BinarySHA256 = ownedUSQUEArm64SHAForFixture()
			i.BindingID = ownedIdentityBinding(*i)
		}},
		{"current-session", func(_ *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.SessionSHA256 = routeidentity.Hash([]byte("new-session"))
			i.BindingID = ownedIdentityBinding(*i)
		}},
		{"current-args", func(_ *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.ArgsSHA256 = routeidentity.Hash([]byte("new-args"))
			i.BindingID = ownedIdentityBinding(*i)
		}},
		{"current-socket", func(_ *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.SocketBinding = routeidentity.Hash([]byte("new-socket"))
			i.BindingID = ownedIdentityBinding(*i)
		}},
		{"current-endpoint", func(_ *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.Endpoint = "162.159.193.11:443"
			i.BindingID = ownedIdentityBinding(*i)
		}},
		{"invalid-binding", func(e *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.BindingID = "not-a-digest"
			e.Identity = *i
		}},
		{"forged-binding", func(e *OwnedRuntimeEvidence, i *OwnedRuntimeIdentity, _ *time.Time) {
			i.BindingID = routeidentity.Hash([]byte("unrelated"))
			e.Identity = *i
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			evidence, current, now := base, identity, checked
			tt.change(&evidence, &current, &now)
			if OwnedEvidenceFresh(evidence, current, now) {
				t.Fatal("stale or mismatched receipt accepted")
			}
		})
	}
}

func TestOwnedCaptureBindsSourceSessionArgsEpochAndSocket(t *testing.T) {
	for _, transport := range []string{"HTTP/2", "QUIC"} {
		t.Run(transport, func(t *testing.T) {
			f := newOwnedRuntimeFixture(t, transport)
			got, err := captureOwnedUSQUE(context.Background(), f.request, f.io)
			if err != nil {
				t.Fatal(err)
			}
			wantPeer := "tcp-established-peer"
			if transport == "QUIC" {
				wantPeer = "udp-unconnected-exclusive-config-inference"
			}
			if got.RuntimeID != f.passport.ID || got.BinarySHA256 != ownedFixtureExecutableSHA || got.SessionSHA256 != f.passport.ConfigHash || got.ArgsSHA256 != routeidentity.Hash(f.files["/proc/42/cmdline"]) || got.Transport != transport || got.Endpoint != f.request.Endpoint.String() || got.PeerObservation != wantPeer || got.SourceCommit != ownedUSQUESource || got.BindingID != ownedIdentityBinding(got) {
				t.Fatalf("identity=%+v", got)
			}
			if f.verifyCalls != 2 || f.hashCalls != 2 || f.fdCalls != 2 || f.epochCalls != 2 {
				t.Fatalf("before/after checks: verify=%d hash=%d fd=%d epoch=%d", f.verifyCalls, f.hashCalls, f.fdCalls, f.epochCalls)
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"PRIVATE-KEY", "PRIVATE-PUBKEY", "PRIVATE-ID", "PRIVATE-TOKEN", f.request.Binary, f.request.Root, "cloudflareclient.com"} {
				if strings.Contains(string(data), secret) {
					t.Fatalf("private fixture material leaked: %s", secret)
				}
			}
		})
	}
}

func TestOwnedCaptureRefusesUntrustedPathAndDrift(t *testing.T) {
	for _, tt := range []struct {
		name, want string
		change     func(*ownedRuntimeFixture)
	}{
		{"proxy-environment", "owned-runtime-session-or-path-unverified", func(f *ownedRuntimeFixture) {
			f.files["/proc/42/environ"] = []byte("https_proxy=http://proxy.invalid\x00")
		}},
		{"proxy-added-after", "owned-runtime-environment-changed", func(f *ownedRuntimeFixture) {
			read := f.io.read
			count := 0
			f.io.read = func(p string, n int64) ([]byte, error) {
				if p == "/proc/42/environ" {
					count++
					if count == 2 {
						return []byte("ALL_PROXY=socks5://proxy.invalid\x00"), nil
					}
				}
				return read(p, n)
			}
		}},
		{"h2-default-not-pinned", "owned-runtime-session-or-path-unverified", func(f *ownedRuntimeFixture) {
			var c map[string]string
			_ = json.Unmarshal(f.files[filepath.Join(f.request.Root, "engine.json")], &c)
			delete(c, "endpoint_h2_v4")
			data, _ := json.Marshal(c)
			f.files[filepath.Join(f.request.Root, "engine.json")] = data
			f.passport.ConfigHash = routeidentity.Hash(data)
		}},
		{"config-hash-mismatch", "owned-runtime-session-or-path-unverified", func(f *ownedRuntimeFixture) { f.passport.ConfigHash = routeidentity.Hash([]byte("other-session")) }},
		{"wrong-endpoint", "owned-runtime-session-or-path-unverified", func(f *ownedRuntimeFixture) { f.request.Endpoint = netip.MustParseAddrPort("162.159.193.11:443") }},
		{"unknown-source-hash", "owned-runtime-binary-not-audited", func(f *ownedRuntimeFixture) {
			f.io.hash = func(int, string) (string, error) { return routeidentity.Hash([]byte("untrusted-executable")), nil }
		}},
		{"binary-read-failure", "owned-runtime-binary-not-audited", func(f *ownedRuntimeFixture) {
			f.io.hash = func(int, string) (string, error) { return "", errors.New("unavailable") }
		}},
		{"binary-changed-after", "owned-runtime-binary-changed", func(f *ownedRuntimeFixture) {
			hash := f.io.hash
			count := 0
			f.io.hash = func(pid int, binary string) (string, error) {
				count++
				if count == 2 {
					return ownedUSQUEArm64SHAForFixture(), nil
				}
				return hash(pid, binary)
			}
		}},
		{"epoch-invalid", "owned-runtime-epoch-unavailable", func(f *ownedRuntimeFixture) {
			f.request.Environment = func(context.Context) (string, error) { return "UI-derived", nil }
		}},
		{"epoch-changed-after", "owned-runtime-environment-changed", func(f *ownedRuntimeFixture) {
			epoch := f.request.Environment
			count := 0
			f.request.Environment = func(ctx context.Context) (string, error) {
				count++
				if count == 2 {
					return routeidentity.Hash([]byte("next-epoch")), nil
				}
				return epoch(ctx)
			}
		}},
		{"unmanaged-process", "owned-runtime-identity-unavailable", func(f *ownedRuntimeFixture) { f.passport.ID = "external:usque" }},
		{"pid-invalid", "owned-runtime-identity-unavailable", func(f *ownedRuntimeFixture) { f.passport.PID = 1 }},
		{"listener-changed-after", "owned-runtime-identity-changed", func(f *ownedRuntimeFixture) {
			verify := f.io.verify
			count := 0
			f.io.verify = func(root, engine, listener string) (routeidentity.Passport, error) {
				count++
				p, err := verify(root, engine, listener)
				if count == 2 {
					p.ID += "-listener901"
				}
				return p, err
			}
		}},
		{"session-changed-after", "owned-runtime-identity-changed", func(f *ownedRuntimeFixture) {
			verify := f.io.verify
			count := 0
			f.io.verify = func(root, engine, listener string) (routeidentity.Passport, error) {
				count++
				p, err := verify(root, engine, listener)
				if count == 2 {
					p.ConfigHash = routeidentity.Hash([]byte("replacement-session"))
				}
				return p, err
			}
		}},
		{"fd-owner-drift", "owned-runtime-socket-owner-changed", func(f *ownedRuntimeFixture) {
			fd := f.io.fds
			count := 0
			f.io.fds = func(pid int) ([]string, error) {
				count++
				if count == 2 {
					return []string{"5:900", "6:902"}, nil
				}
				return fd(pid)
			}
		}},
		{"fd-number-drift", "owned-runtime-socket-owner-changed", func(f *ownedRuntimeFixture) {
			fd := f.io.fds
			count := 0
			f.io.fds = func(pid int) ([]string, error) {
				count++
				if count == 2 {
					return []string{"5:900", "7:901"}, nil
				}
				return fd(pid)
			}
		}},
		{"socket-table-missing", "owned-runtime-socket-table-unavailable", func(f *ownedRuntimeFixture) { delete(f.files, "/proc/42/net/tcp") }},
		{"socket-table-malformed", "owned-runtime-socket-table-invalid", func(f *ownedRuntimeFixture) { f.files["/proc/42/net/udp"] = []byte("broken row\n") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newOwnedRuntimeFixture(t, "HTTP/2")
			tt.change(f)
			got, err := captureOwnedUSQUE(context.Background(), f.request, f.io)
			requireOwnedRuntimeError(t, got, err, tt.want)
		})
	}
	t.Run("canceled-no-io", func(t *testing.T) {
		f := newOwnedRuntimeFixture(t, "HTTP/2")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := captureOwnedUSQUE(ctx, f.request, f.io)
		requireOwnedRuntimeError(t, got, err, "owned-runtime-canceled")
		if f.readCalls+f.fdCalls+f.verifyCalls+f.hashCalls+f.epochCalls != 0 {
			t.Fatal("canceled capture inspected runtime")
		}
	})
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Run(key, func(t *testing.T) {
			if ownedProxyEnvironmentClear([]byte("LANG=C\x00" + key + "=http://proxy.invalid\x00")) {
				t.Fatal("proxy environment accepted")
			}
		})
	}
}

func TestOwnedCaptureRequiresExactAuditedArgs(t *testing.T) {
	for _, name := range []string{"missing-http2", "duplicate-http2", "unexpected-flag", "insecure", "ipv6", "missing-nul", "other-binary", "other-config", "other-listener", "duplicate-sni", "invalid-sni"} {
		t.Run(name, func(t *testing.T) {
			f := newOwnedRuntimeFixture(t, "HTTP/2")
			args := strings.Split(strings.TrimSuffix(string(f.files["/proc/42/cmdline"]), "\x00"), "\x00")
			switch name {
			case "missing-http2":
				args = args[:len(args)-1]
			case "duplicate-http2":
				args = append(args, "--http2")
			case "unexpected-flag":
				args = append(args, "--user-extra")
			case "insecure":
				args = append(args, "--insecure")
			case "ipv6":
				args = append(args, "--ipv6")
			case "other-binary":
				args[0] = filepath.Join(filepath.Dir(f.request.Binary), "other-usque")
			case "other-config":
				args[2] = filepath.Join(f.request.Root, "other.json")
			case "other-listener":
				args[5] = "0.0.0.0"
			case "duplicate-sni":
				args = append(args, "-s", "other.example")
			case "invalid-sni":
				args[11] = "user@host.example"
			}
			raw := strings.Join(args, "\x00") + "\x00"
			if name == "missing-nul" {
				raw = strings.TrimSuffix(raw, "\x00")
			}
			f.files["/proc/42/cmdline"] = []byte(raw)
			got, err := captureOwnedUSQUE(context.Background(), f.request, f.io)
			requireOwnedRuntimeError(t, got, err, "owned-runtime-session-or-path-unverified")
		})
	}
}

func TestOwnedCaptureRejectsCaseAliasEndpoint(t *testing.T) {
	for _, transport := range []string{"HTTP/2", "QUIC"} {
		t.Run(transport, func(t *testing.T) {
			f := newOwnedRuntimeFixture(t, transport)
			path := filepath.Join(f.request.Root, "engine.json")
			key := "Endpoint_v4"
			if transport == "HTTP/2" {
				key = "Endpoint_h2_v4"
			}
			base := f.files[path]
			raw := append(append([]byte(nil), base[:len(base)-1]...), []byte(`,"`+key+`":"162.159.193.11"}`)...)
			var upstream struct {
				V4   string `json:"endpoint_v4"`
				H2V4 string `json:"endpoint_h2_v4"`
			}
			if err := json.Unmarshal(raw, &upstream); err != nil {
				t.Fatal(err)
			}
			selected := upstream.V4
			if transport == "HTTP/2" {
				selected = upstream.H2V4
			}
			if selected != "162.159.193.11" {
				t.Fatal("fixture did not reproduce upstream struct decoding")
			}
			f.files[path] = raw
			f.passport.ConfigHash = routeidentity.Hash(raw)
			got, err := captureOwnedUSQUE(context.Background(), f.request, f.io)
			requireOwnedRuntimeError(t, got, err, "owned-runtime-session-or-path-unverified")
		})
	}
}

func TestOwnedCaptureSocketOwnershipAndStates(t *testing.T) {
	for _, tt := range []struct {
		name, transport, state, remote, wantPeer string
		extra, unowned, missingPeer, missingIPv6 bool
	}{
		{name: "tcp-established", transport: "HTTP/2", state: "01", remote: "162.159.193.10:443", wantPeer: "tcp-established-peer"},
		{name: "tcp-syn", transport: "HTTP/2", state: "02", remote: "162.159.193.10:443"},
		{name: "tcp-timewait", transport: "HTTP/2", state: "06", remote: "162.159.193.10:443"},
		{name: "tcp-listener", transport: "HTTP/2", state: "0A", remote: "0.0.0.0:0"},
		{name: "unowned-peer-only", transport: "HTTP/2", state: "01", remote: "162.159.193.10:443", missingPeer: true},
		{name: "unowned-peer-ignored", transport: "HTTP/2", state: "01", remote: "162.159.193.10:443", wantPeer: "tcp-established-peer", unowned: true},
		{name: "tcp-multiple-peers", transport: "HTTP/2", state: "01", remote: "162.159.193.10:443", extra: true},
		{name: "ipv6-facility-absent", transport: "HTTP/2", state: "01", remote: "162.159.193.10:443", wantPeer: "tcp-established-peer", missingIPv6: true},
		{name: "udp-wildcard-inference", transport: "QUIC", state: "07", remote: "0.0.0.0:0", wantPeer: "udp-unconnected-exclusive-config-inference"},
		{name: "udp-connected-default-only", transport: "QUIC", state: "01", remote: "162.159.193.10:443", wantPeer: "udp-connected-default-peer"},
		{name: "udp-other-default", transport: "QUIC", state: "01", remote: "162.159.193.11:443"},
		{name: "udp-wildcard-wrong-state", transport: "QUIC", state: "01", remote: "0.0.0.0:0"},
		{name: "udp-multiple-peers", transport: "QUIC", state: "07", remote: "0.0.0.0:0", extra: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newOwnedRuntimeFixture(t, tt.transport)
			table := "tcp"
			if tt.transport == "QUIC" {
				table = "udp"
			}
			data := ownedFixtureTableHeader
			if table == "tcp" {
				data += ownedFixtureSocketRow("127.0.0.1:18081", "0.0.0.0:0", "0A", "900", true)
			}
			data += ownedFixtureSocketRow("192.0.2.10:51900", tt.remote, tt.state, "901", true)
			if tt.missingPeer {
				f.owners = []string{"5:900"}
			}
			if tt.unowned {
				data += ownedFixtureSocketRow("192.0.2.10:51902", "8.8.8.8:443", "01", "999", true)
			}
			if tt.extra {
				f.owners = append(f.owners, "7:902")
				data += ownedFixtureSocketRow("192.0.2.10:51901", tt.remote, tt.state, "902", true)
			}
			f.files["/proc/42/net/"+table] = []byte(data)
			if tt.missingIPv6 {
				delete(f.files, "/proc/42/net/tcp6")
				delete(f.files, "/proc/42/net/udp6")
			}
			got, err := captureOwnedUSQUE(context.Background(), f.request, f.io)
			if tt.wantPeer == "" {
				requireOwnedRuntimeError(t, got, err, "owned-runtime-underlay-ambiguous")
				return
			}
			if err != nil || got.PeerObservation != tt.wantPeer {
				t.Fatalf("identity=%+v err=%v", got, err)
			}
		})
	}
}

func TestOwnedProcAddressEndiannessAndMappedIPv4(t *testing.T) {
	for _, tt := range []struct {
		name, raw, want string
		little          bool
	}{
		{"ipv4-le", "04030201:01BB", "1.2.3.4:443", true},
		{"ipv4-be", "01020304:01BB", "1.2.3.4:443", false},
		{"ipv6-le", "B80D0120000000000000000001000000:01BB", "[2001:db8::1]:443", true},
		{"ipv6-be", "20010DB8000000000000000000000001:01BB", "[2001:db8::1]:443", false},
		{"mapped-le", "0000000000000000FFFF00000AC19FA2:01BB", "162.159.193.10:443", true},
		{"mapped-be", "00000000000000000000FFFFA29FC10A:01BB", "162.159.193.10:443", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOwnedProcAddress(tt.raw, tt.little)
			if err != nil || got.String() != tt.want {
				t.Fatalf("address=%s err=%v want=%s", got, err, tt.want)
			}
		})
	}
	for _, raw := range []string{"", "010203:01BB", "GG020304:01BB", "01020304:10000", "01020304:-1", "01020304:01BB:extra"} {
		t.Run("invalid-"+raw, func(t *testing.T) {
			if _, err := parseOwnedProcAddress(raw, true); err == nil {
				t.Fatal("malformed address accepted")
			}
		})
	}
}

func TestOwnedSocketTableMatchesOnlyOwnedInodes(t *testing.T) {
	for _, little := range []bool{false, true} {
		for _, family := range []string{"tcp", "tcp6", "udp", "udp6"} {
			t.Run(fmt.Sprintf("%s/little-%t", family, little), func(t *testing.T) {
				local, remote := "192.0.2.10:51900", "162.159.193.10:443"
				if strings.HasSuffix(family, "6") {
					local, remote = "[2001:db8::2]:51900", "[2606:4700:4700::1111]:443"
				}
				raw := ownedFixtureTableHeader + ownedFixtureSocketRow(local, remote, "01", "901", little) + ownedFixtureSocketRow(local, remote, "01", "999", little)
				got, err := parseOwnedSocketTable([]byte(raw), family, []string{"6:901", "7:901"}, little)
				if err != nil || len(got) != 1 || got[0].inode != "901" || got[0].table != family || got[0].local.String() != local || got[0].remote.String() != remote {
					t.Fatalf("sockets=%+v err=%v", got, err)
				}
				if _, err := parseOwnedSocketTable([]byte(raw+ownedFixtureSocketRow(local, remote, "01", "901", little)), family, []string{"6:901"}, little); err == nil {
					t.Fatal("duplicate owned inode accepted")
				}
			})
		}
	}
}

func TestOwnedOfficialExecutableDigestsAreExecutableHashes(t *testing.T) {
	want := map[string]string{ownedFixtureExecutableSHA: "amd64", ownedUSQUEArm64SHAForFixture(): "arm64", "c7dd8a80eca37e5e5770073d72c85630d671e6d288214185c2f9bf246f01f59d": "mips", "2b466b9595704c6741472d1ffd17ef004d676871005504401105b5cd277c0dbf": "mipsle"}
	if len(ownedUSQUE421) != len(want) || ownedUSQUESource != "6aa03fc97d12848dce34eedbd187fb1077b5d1ea" {
		t.Fatal("unexpected official release profile")
	}
	for digest, arch := range want {
		if ownedUSQUE421[digest] != arch || !canaryDigest(digest) {
			t.Fatalf("release executable digest %s: got %q want %q", digest, ownedUSQUE421[digest], arch)
		}
	}
	if ownedUSQUE421["4117e20695078af9c11edecd1a826c009bbc7ea0b7f64458612b4198910bc313"] != "" {
		t.Fatal("ZIP digest accepted as executable provenance")
	}
}

func TestOwnedEvidenceRequiresValidCurrentRuntimeEvenWithMatchingBinding(t *testing.T) {
	checked := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name   string
		change func(*OwnedRuntimeIdentity)
	}{
		{"missing-runtime", func(i *OwnedRuntimeIdentity) { i.RuntimeID = "" }},
		{"external-runtime", func(i *OwnedRuntimeIdentity) {
			i.RuntimeID = "external:usque:" + routeidentity.Hash([]byte("external"))
		}},
		{"invalid-runtime-digest", func(i *OwnedRuntimeIdentity) { i.RuntimeID = "managed:usque:invalid" }},
		{"unknown-release", func(i *OwnedRuntimeIdentity) { i.BinarySHA256 = routeidentity.Hash([]byte("untrusted-release")) }},
		{"archive-hash", func(i *OwnedRuntimeIdentity) {
			i.BinarySHA256 = "4117e20695078af9c11edecd1a826c009bbc7ea0b7f64458612b4198910bc313"
		}},
		{"source-commit", func(i *OwnedRuntimeIdentity) { i.SourceCommit = strings.Repeat("1", 40) }},
		{"session-digest", func(i *OwnedRuntimeIdentity) { i.SessionSHA256 = "private-session-text" }},
		{"args-digest", func(i *OwnedRuntimeIdentity) { i.ArgsSHA256 = "private-argv-text" }},
		{"environment-digest", func(i *OwnedRuntimeIdentity) { i.EnvironmentID = "untrusted-ui-profile" }},
		{"socket-digest", func(i *OwnedRuntimeIdentity) { i.SocketBinding = "socket:901" }},
		{"private-endpoint", func(i *OwnedRuntimeIdentity) { i.Endpoint = "192.168.1.1:443" }},
		{"mapped-endpoint", func(i *OwnedRuntimeIdentity) { i.Endpoint = "[::ffff:162.159.193.10]:443" }},
		{"unsupported-ipv6-endpoint", func(i *OwnedRuntimeIdentity) { i.Endpoint = "[2606:4700:4700::1111]:443" }},
		{"wrong-endpoint-port", func(i *OwnedRuntimeIdentity) { i.Endpoint = "162.159.193.10:8443" }},
		{"unsupported-transport", func(i *OwnedRuntimeIdentity) { i.Transport = "HTTP/3" }},
		{"h2-udp-observation", func(i *OwnedRuntimeIdentity) { i.PeerObservation = "udp-connected-default-peer" }},
		{"quic-tcp-observation", func(i *OwnedRuntimeIdentity) { i.Transport = "QUIC" }},
		{"claimed-alpn-observation", func(i *OwnedRuntimeIdentity) { i.PeerObservation = "negotiated-h2" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			i := ownedFixtureIdentity()
			tt.change(&i)
			i.BindingID = ownedIdentityBinding(i)
			e := OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: checked.Format(time.RFC3339Nano), ValidUntil: checked.Add(MaxCanaryAge).Format(time.RFC3339Nano), Identity: i, ProofBasis: ownedPathBasis, ProtocolPath: i.Transport, Warp: "on"}
			if OwnedEvidenceFresh(e, i, checked) || safeOwnedEvidence(e) {
				t.Fatal("invalid identity accepted solely because binding matches")
			}
		})
	}
}

func TestOwnedEvidenceConversionCannotPromoteLegacyCapabilities(t *testing.T) {
	checked := time.Date(2026, 10, 4, 0, 0, 0, 1, time.UTC)
	for _, transport := range []string{"HTTP/2", "QUIC"} {
		t.Run(transport, func(t *testing.T) {
			i := ownedFixtureIdentity()
			i.Transport = transport
			if transport == "QUIC" {
				i.PeerObservation = "udp-unconnected-exclusive-config-inference"
			}
			i.BindingID = ownedIdentityBinding(i)
			e := OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: checked.Format(time.RFC3339Nano), ValidUntil: checked.Add(MaxCanaryAge).Format(time.RFC3339Nano), Identity: i, ProofBasis: ownedPathBasis, ProtocolPath: transport, Warp: "on", ConfirmedRoutes: []string{"fixture-service"}}
			if !safeOwnedEvidence(e) {
				t.Fatal("valid typed evidence refused")
			}
			receipt := e.CanaryEvidence()
			if receipt.BindingID != "" || receipt.Owned == nil || receipt.Owned.Negotiated || !OwnedEvidenceFresh(*receipt.Owned, i, checked) {
				t.Fatalf("unsafe conversion: %+v", receipt)
			}
			legacyBinding := CanaryBinding(i.SessionSHA256, i.SessionSHA256, i.BinarySHA256, i.EnvironmentID)
			capabilities := EvaluateCanaryCapabilities(receipt, Endpoints{IPv4: i.Endpoint[:strings.LastIndex(i.Endpoint, ":")], H2IPv4: i.Endpoint[:strings.LastIndex(i.Endpoint, ":")]}, legacyBinding, checked)
			if capabilities.Fresh || capabilities.HTTP2 != "unknown" || capabilities.HTTP3 != "unknown" || capabilities.UDP != "unknown" {
				t.Fatalf("inferred path promoted to negotiated capability: %+v", capabilities)
			}
			encoded, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			var restored CanaryEvidence
			if err := json.Unmarshal(encoded, &restored); err != nil || restored.Owned == nil || !safeOwnedEvidence(*restored.Owned) || !OwnedEvidenceFresh(*restored.Owned, i, checked) {
				t.Fatalf("typed receipt roundtrip failed: %v", err)
			}
			e.ConfirmedRoutes[0] = "mutated-source"
			if receipt.ConfirmedRoutes[0] != "fixture-service" || receipt.Owned.ConfirmedRoutes[0] != "fixture-service" {
				t.Fatal("receipt aliases source routes")
			}
			receipt.Owned.ConfirmedRoutes[0] = "mutated-owned-copy"
			if receipt.ConfirmedRoutes[0] != "fixture-service" {
				t.Fatal("legacy and owned route slices alias")
			}
		})
	}
}

func TestOwnedSelectedEndpointRequiresExplicitIPv4Pin(t *testing.T) {
	for _, transport := range []string{"HTTP/2", "QUIC"} {
		got, err := SelectedOwnedUSQUEEndpoint([]byte(`{"endpoint_v4":"162.159.193.10","endpoint_h2_v4":"162.159.198.3"}`), transport)
		want := "162.159.193.10:443"
		if transport == "HTTP/2" {
			want = "162.159.198.3:443"
		}
		if err != nil || got.String() != want {
			t.Fatalf("transport=%s endpoint=%s err=%v", transport, got, err)
		}
	}
	for _, tt := range []struct{ name, raw, transport string }{
		{"implicit-h2-default", `{"endpoint_v4":"162.159.193.10"}`, "HTTP/2"},
		{"dns-name", `{"endpoint_v4":"example.com"}`, "QUIC"},
		{"with-port", `{"endpoint_v4":"162.159.193.10:443"}`, "QUIC"},
		{"private", `{"endpoint_v4":"10.0.0.1"}`, "QUIC"},
		{"ipv6", `{"endpoint_v4":"2606:4700:4700::1111"}`, "QUIC"},
		{"mapped", `{"endpoint_v4":"::ffff:162.159.193.10"}`, "QUIC"},
		{"wrong-type", `{"endpoint_v4":123}`, "QUIC"},
		{"missing", `{}`, "QUIC"},
		{"malformed", `{`, "QUIC"},
		{"null", `null`, "QUIC"},
		{"array", `[{"endpoint_v4":"162.159.193.10"}]`, "QUIC"},
		{"string", `"endpoint_v4"`, "QUIC"},
		{"number", `42`, "QUIC"},
		{"duplicate-v4", `{"endpoint_v4":"162.159.193.11","endpoint_v4":"162.159.193.10"}`, "QUIC"},
		{"duplicate-escaped-v4", `{"endpoint_v4":"162.159.193.11","\u0065ndpoint_v4":"162.159.193.10"}`, "QUIC"},
		{"trailing-object", `{"endpoint_v4":"162.159.193.10"}{}`, "QUIC"},
		{"trailing-null", `{"endpoint_v4":"162.159.193.10"}null`, "QUIC"},
		{"trailing-garbage", `{"endpoint_v4":"162.159.193.10"}invalid`, "QUIC"},
		{"case-alias-v4", `{"endpoint_v4":"162.159.193.10","Endpoint_v4":"162.159.193.11"}`, "QUIC"},
		{"case-alias-h2", `{"endpoint_h2_v4":"162.159.198.3","Endpoint_h2_v4":"162.159.198.2"}`, "HTTP/2"},
		{"unknown-transport", `{"endpoint_v4":"162.159.193.10"}`, "HTTP/3"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectedOwnedUSQUEEndpoint([]byte(tt.raw), tt.transport)
			if err == nil || got.IsValid() {
				t.Fatalf("invalid pin accepted: %s %v", got, err)
			}
		})
	}
}

func TestOwnedCaptureRejectsAmbiguousOrNonObjectConfig(t *testing.T) {
	for _, name := range []string{"duplicate-pin", "duplicate-credential", "trailing-object", "trailing-null", "null", "array"} {
		t.Run(name, func(t *testing.T) {
			f := newOwnedRuntimeFixture(t, "QUIC")
			path := filepath.Join(f.request.Root, "engine.json")
			base := append([]byte(nil), f.files[path]...)
			raw := base
			switch name {
			case "duplicate-pin":
				raw = append(base[:len(base)-1], []byte(`,"endpoint_v4":"162.159.193.10"}`)...)
			case "duplicate-credential":
				raw = append(base[:len(base)-1], []byte(`,"access_token":"REPLACEMENT-PRIVATE-TOKEN"}`)...)
			case "trailing-object":
				raw = append(base, []byte(`{}`)...)
			case "trailing-null":
				raw = append(base, []byte(`null`)...)
			case "null":
				raw = []byte(`null`)
			case "array":
				raw = append(append([]byte{'['}, base...), ']')
			}
			f.files[path] = raw
			f.passport.ConfigHash = routeidentity.Hash(raw)
			got, err := captureOwnedUSQUE(context.Background(), f.request, f.io)
			requireOwnedRuntimeError(t, got, err, "owned-runtime-session-or-path-unverified")
		})
	}
}

func TestOwnedEnvironmentRequiresFreshTrustedWANToken(t *testing.T) {
	if _, err := OwnedUSQUEEnvironment(nil)(context.Background()); err == nil {
		t.Fatal("missing fresh callback accepted")
	}
	for _, token := range []string{"", "unknown", "wan-unknown", "wan-123456789ABC", "wan-123456789ab", "legacy-profile"} {
		t.Run(token, func(t *testing.T) {
			calls := 0
			got, err := OwnedUSQUEEnvironment(func(context.Context) (string, error) { calls++; return token, nil })(context.Background())
			if err == nil || got != "" || calls != 1 {
				t.Fatalf("environment=%q err=%v calls=%d", got, err, calls)
			}
		})
	}
	if got, err := OwnedUSQUEEnvironment(func(context.Context) (string, error) {
		return "wan-123456789abc", errors.New("fresh observation failed")
	})(context.Background()); err == nil || got != "" {
		t.Fatal("failed fresh observation accepted")
	}
	sequence := []string{"wan-123456789abc", "wan-abcdef123456"}
	calls := 0
	observe := OwnedUSQUEEnvironment(func(context.Context) (string, error) { token := sequence[calls]; calls++; return token, nil })
	first, err := observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != routeidentity.Hash([]byte(`["usque-environment-v1","wan-123456789abc"]`)) || second != routeidentity.Hash([]byte(`["usque-environment-v1","wan-abcdef123456"]`)) || first == second || calls != 2 {
		t.Fatalf("fresh epoch was cached or incorrectly bound: %s %s calls=%d", first, second, calls)
	}
}

func TestOwnedEvidenceReadbackExpiresDuringCallbacksAndRefusesCancellation(t *testing.T) {
	// Only the receipt is an inert file fixture. Runtime observation and time
	// are callbacks; all executable paths are absent and HTTP/DNS are disabled.
	for _, name := range []string{"fresh", "expires-during-callbacks", "canceled-during-callbacks", "clock-backward", "runtime-drift", "missing-callback", "first-callback-error", "second-callback-error"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := func(name string) string { return filepath.Join(root, name) }
			checked := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
			clock := checked.Add(time.Minute)
			identity := ownedFixtureIdentity()
			evidence := OwnedRuntimeEvidence{Origin: "managed-usque-canary", CheckedAt: checked.Format(time.RFC3339Nano), ValidUntil: checked.Add(MaxCanaryAge).Format(time.RFC3339Nano), Identity: identity, ProofBasis: ownedPathBasis, ProtocolPath: identity.Transport, Warp: "on", ConfirmedRoutes: []string{"fixture-service"}}
			data, err := json.Marshal(evidence.CanaryEvidence())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path("evidence.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := &fakeRunner{}
			m := &Manager{Runner: runner, Architecture: "arm64", ConfigPath: path("absent-usque.conf"), SessionPath: path("absent-session.conf"), InitPath: path("absent-init"), NDMCPath: path("absent-ndmc"), BinaryCandidates: []string{path("absent-usque")}, IPCandidates: []string{path("absent-ip")}, EvidencePath: path("evidence.json"), Now: func() time.Time { return clock }}
			calls := 0
			m.EvidenceRuntime = func(gotCtx context.Context) (OwnedRuntimeIdentity, error) {
				if gotCtx != ctx {
					t.Fatal("readback lost request context")
				}
				calls++
				if name == "first-callback-error" && calls == 1 || name == "second-callback-error" && calls == 2 {
					return OwnedRuntimeIdentity{}, errors.New("fixture-runtime-unavailable")
				}
				current := identity
				if calls == 2 {
					switch name {
					case "expires-during-callbacks":
						clock = checked.Add(MaxCanaryAge)
					case "canceled-during-callbacks":
						cancel()
					case "clock-backward":
						clock = checked.Add(30 * time.Second)
					case "runtime-drift":
						current.RuntimeID = "managed:usque:" + routeidentity.Hash([]byte("restarted-runtime"))
						current.BindingID = ownedIdentityBinding(current)
					}
				}
				return current, nil
			}
			wantCalls := 2
			if name == "missing-callback" {
				m.EvidenceRuntime = nil
				wantCalls = 0
			}
			if name == "first-callback-error" {
				wantCalls = 1
			}
			report := m.Check(ctx)
			if report.OwnedFresh != (name == "fresh") || report.OwnedEvidence == nil || calls != wantCalls {
				t.Fatalf("fresh=%t evidence=%+v calls=%d wantCalls=%d", report.OwnedFresh, report.OwnedEvidence, calls, wantCalls)
			}
			if len(runner.calls) != 0 {
				t.Fatal("inert readback fixture invoked a command")
			}
			if report.Capabilities.Fresh || report.Capabilities.HTTP2 != "unknown" || report.Capabilities.HTTP3 != "unknown" || report.Capabilities.UDP != "unknown" {
				t.Fatalf("typed inference promoted legacy capabilities: %+v", report.Capabilities)
			}
			wantStatus := "warning"
			if name == "fresh" {
				wantStatus = "pass"
			}
			assertCheckStatus(t, report, "warp-evidence", wantStatus)
			assertCheckStatus(t, report, "service-evidence", wantStatus)
		})
	}
}
