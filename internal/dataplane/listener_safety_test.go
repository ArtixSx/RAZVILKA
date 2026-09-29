package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const xrayRemoteExit = `{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"edge.example","port":443,"users":[{"id":"123e4567-e89b-12d3-a456-426614174000","encryption":"none"}]}]}}`

func TestCandidateRemovesImportedListeners(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		outbounds := "[]"
		if engine == "xray" {
			outbounds = "[" + xrayRemoteExit + "]"
		}
		// Sing-box-only control objects are stripped for Sing-box; for Xray
		// they are not part of the format and would be refused as dynamic.
		singBoxOnly := `"services":[{"type":"ssm-api","listen":"::"}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}},`
		if engine == "xray" {
			singBoxOnly = ""
		}
		data, _, err := buildProxyCandidate(engine, []byte(`{"inbounds":[{"listen":"0.0.0.0"},{"listen":"::"}],"api":{"listen":"0.0.0.0:10085"},"metrics":{"listen":"0.0.0.0:11111"},"log":{"output":"/outside/secret","error":"/outside/secret","access":"/outside/secret"},`+singBoxOnly+`"outbounds":`+outbounds+`}`), 19080)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		inbounds := document["inbounds"].([]any)
		if len(inbounds) != 1 || inbounds[0].(map[string]any)["listen"] != "127.0.0.1" {
			t.Fatalf("unsafe %s listener: %s", engine, data)
		}
		if engine == "xray" && (document["api"] != nil || document["metrics"] != nil) || engine == "sing-box" && (document["services"] != nil || document["experimental"] != nil) {
			t.Fatalf("additional API listener survived: %s", data)
		}
		log := document["log"].(map[string]any)
		if log["output"] != nil || log["error"] != nil || log["access"] == "/outside/secret" {
			t.Fatal("imported log destination survived")
		}
	}
	if _, _, err := buildProxyCandidate("sing-box", []byte(`{"outbounds":[],"endpoints":[{"type":"wireguard","system":true}]}`), 19080); err == nil {
		t.Fatal("system endpoint was accepted by proxy-only canary")
	}
	for _, port := range []int{-1, 0, 80, 65536} {
		if _, _, err := buildProxyCandidate("sing-box", []byte(`{"outbounds":[]}`), port); err == nil {
			t.Fatalf("invalid port %d", port)
		}
	}
}

func TestSOCKSReadinessHandlesSplitGreetingAndCancellation(t *testing.T) {
	for _, cancelProbe := range []bool{false, true} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			greeting := make([]byte, 3)
			if _, err := io.ReadFull(conn, greeting); err != nil {
				return
			}
			_, _ = conn.Write([]byte{5})
			if cancelProbe {
				cancel()
			} else {
				time.Sleep(40 * time.Millisecond)
				_, _ = conn.Write([]byte{0})
			}
			_, _ = conn.Read(make([]byte, 1))
		}()
		started := time.Now()
		err = probeSOCKS5(ctx, listener.Addr().String())
		cancel()
		_ = listener.Close()
		<-done
		if cancelProbe && !errors.Is(err, context.Canceled) || !cancelProbe && err != nil {
			t.Fatalf("cancel=%t err=%v", cancelProbe, err)
		}
		if time.Since(started) > time.Second {
			t.Fatal("cancelled readiness check did not close connection promptly")
		}
	}
}

// X02: Xray sends unmatched traffic to its first outbound. A managed service
// route must reach one static remote exit; anything that could turn it into a
// direct connection is refused before staging, not discovered by a canary.
func TestXrayCandidateRequiresSingleRemoteExit(t *testing.T) {
	freedom := `{"tag":"direct","protocol":"freedom"}`
	for name, source := range map[string]string{
		"freedom first":    `{"outbounds":[` + freedom + `,` + xrayRemoteExit + `]}`,
		"routing rules":    `{"outbounds":[` + xrayRemoteExit + `,` + freedom + `],"routing":{"rules":[{"type":"field","domain":["geosite:ru"],"outboundTag":"direct"}]}}`,
		"balancer":         `{"outbounds":[` + xrayRemoteExit + `],"routing":{"balancers":[{"tag":"b","selector":["proxy"]}]}}`,
		"dialer chain":     `{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"edge.example","port":443,"users":[{"id":"123e4567-e89b-12d3-a456-426614174000"}]}]},"streamSettings":{"sockopt":{"dialerProxy":"other"}}}]}`,
		"private endpoint": `{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"192.168.1.10","port":443,"users":[{"id":"123e4567-e89b-12d3-a456-426614174000"}]}]}}]}`,
		"no outbound":      `{"outbounds":[]}`,
	} {
		if _, _, err := buildProxyCandidate("xray", []byte(source), 19080); err == nil {
			t.Fatalf("%s accepted as a managed Xray route", name)
		}
	}
	// An unused DIRECT entry after the remote exit is allowed.
	if _, _, err := buildProxyCandidate("xray", []byte(`{"outbounds":[`+xrayRemoteExit+`,`+freedom+`]}`), 19080); err != nil {
		t.Fatalf("remote exit with unused direct refused: %v", err)
	}
}
