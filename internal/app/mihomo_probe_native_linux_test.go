//go:build linux && razvilka_native_fixture

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type mihomoServiceArchiveTransport func(*http.Request) (*http.Response, error)

func (f mihomoServiceArchiveTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestMihomoOriginalNativeServiceAndCommonCleanup(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_SERVICE_NATIVE") != "1" {
		t.Skip("requires isolated native peers and installed official asset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	peers := domainOriginalPeers(t, ctx)
	archive, err := os.ReadFile(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	controlRoot := filepath.Join(peers.root, "mihomo-control")
	if _, err := operationgate.InitializeSelfUpdateControl(held, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	guard := func(c context.Context, effect func() error) error {
		if err := control.Current(c); err != nil {
			return err
		}
		return errors.Join(effect(), control.Current(c))
	}
	cm := components.New()
	cm.Client = &http.Client{Transport: mihomoServiceArchiveTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz" {
			return nil, errors.New("unreviewed archive source")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
	})}
	componentsHistory := updatecheck.NewComponentHistoryAdmission(components.MihomoReleaseReadVersion)
	if err := componentsHistory.CheckWrite(held, components.MihomoReleaseReadVersion); err != nil {
		t.Fatal("original component fleet", err)
	}
	if result, err := cm.ApplyMihomoGuarded(held, guard, control.WithRename, control.WithStart); err != nil || !result.OK {
		t.Fatal("actual official install", result, err)
	}
	m := dataplane.New(filepath.Join(installpath.State, "dataplane"))
	m.FreshProfile = func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() } // WAN label only is modeled; socket/netns/process/peer are real.
	a := dataplane.NewMihomoProbeAdapter(cm, netidentity.NewProcProvider())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	history := updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion)
	for i, scenario := range []string{"complete", "required-semantic-failure", "excluded-required-scenario", "panic-after-listener"} {
		t.Run(scenario, func(t *testing.T) {
			probeCtx, finish := context.WithTimeout(held, 40*time.Second)
			defer finish()
			probeCtx = dataplane.WithReviewGuard(probeCtx, func(c context.Context) error {
				if scenario == "panic-after-listener" {
					data, _ := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
					var e dataplane.Execution
					if json.Unmarshal(data, &e) == nil && len(e.Resources) == 1 && e.Resources[0].MihomoProbe != nil && e.Resources[0].MihomoProbe.Source.SOCKSPort == 29400+i && e.Resources[0].Phase == "listener-ready" {
						panic("fixture observer panic")
					}
				}
				return control.Current(c)
			})
			probeCtx = dataplane.WithNodeResourceGuard(probeCtx, func(c context.Context, host string, address netip.Addr) error {
				if host != domainOriginalServer && host != "service.example.com" && host != "unknown.example.com" {
					return dataplane.ErrNodeResourceDenied
				}
				if scenario == "excluded-required-scenario" && host == "unknown.example.com" {
					return dataplane.ErrNodeResourceDenied
				}
				if address.IsValid() && address.String() != domainOriginalServer {
					return dataplane.ErrNodeResourceDenied
				}
				return c.Err()
			})
			options := backendprofile.MihomoOptions{SOCKSPort: 29400 + i}
			raw := fmt.Sprintf("vless://%s@%s:10443?security=tls&sni=front.example", domainOriginalUUID, domainOriginalServer)
			profile, err := backendprofile.Mihomo(raw, options)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256([]byte(profile.Config))
			source, err := cm.ReviewMihomoProbe(probeCtx, raw, options, hex.EncodeToString(hash[:]), domainOriginalServer, netip.MustParseAddr(domainOriginalServer), guard)
			if err != nil {
				t.Fatal("original installed source", err)
			}
			defer source.Close()
			service := domainOriginalNativeService()
			service.Probes[0].Expect.BodyContains = append(service.Probes[0].Expect.BodyContains, `"Source":"1.1.1.2"`)
			service.Probes = append(service.Probes, catalog.Probe{ID: "second", Label: "Required second actual TLS request", URL: "https://unknown.example.com/", Required: true, Expect: catalog.ProbeExpectation{BodyContains: []string{"native-domain-service"}}})
			service.Domains = append(service.Domains, "unknown.example.com")
			if scenario == "required-semantic-failure" {
				service.Probes[1].Expect.BodyContains = []string{"must-not-be-accepted"}
			}
			started := time.Now()
			var result dataplane.MihomoServiceProbe
			panicked := false
			func() {
				defer func() {
					if value := recover(); value != nil {
						if value != "fixture observer panic" {
							panic(value)
						}
						panicked = true
					}
				}()
				result, err = a.Check(probeCtx, m, source, service, 1, "wan-0123456789ab", componentsHistory, history, control)
			}()
			if scenario == "panic-after-listener" {
				if !panicked || !a.Pending() {
					t.Fatal("exceptional unwind lost original cleanup owner")
				}
				cleanupCtx, done := context.WithTimeout(held, 15*time.Second)
				defer done()
				if err := a.RetryCleanup(cleanupCtx); err != nil {
					t.Fatal("same-owner panic cleanup", err)
				}
				err = errors.New("fixture observer panic")
			}
			t.Logf("actual service probe scenario=%s elapsed=%s result=%+v err=%v", scenario, time.Since(started), result, err)
			if a.Pending() {
				t.Fatal("original COMMON/process cleanup remains pending", err)
			}
			if scenario == "complete" {
				if err != nil || !result.ServiceVerified || !result.CleanupVerified || result.LiveApplied || result.ServiceID != service.ID || result.ReviewSHA256 != hex.EncodeToString(hash[:]) {
					t.Fatal("actual routed HTTPS not confirmed", result, err)
				}
			} else if err == nil || result.ServiceVerified {
				t.Fatal("required scenario failure published success", result)
			}
			if err := source.Close(); err != nil {
				t.Fatal("source custody not released", err)
			}
			if err := m.CheckExecutionRecovery(probeCtx); err != nil {
				t.Fatal("terminal COMMON still fenced", err)
			}
			data, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
			if err != nil {
				t.Fatal(err)
			}
			var execution dataplane.Execution
			if json.Unmarshal(data, &execution) != nil || execution.State != "temporary-complete" || len(execution.Resources) != 1 || execution.Resources[0].Kind != "mihomo-probe" || execution.Resources[0].Phase != "removed" {
				t.Fatal("actual terminal COMMON missing")
			}
			if scenario != "complete" && (len(execution.Steps) != 1 || execution.Steps[0].State != "failed") {
				t.Fatal("failed/exceptional check became successful metadata")
			}
		})
	}
}
