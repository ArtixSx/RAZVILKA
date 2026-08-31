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

func TestCandidateRemovesImportedListeners(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		data, _, err := buildProxyCandidate(engine, []byte(`{"inbounds":[{"listen":"0.0.0.0"},{"listen":"::"}],"api":{"listen":"0.0.0.0:10085"},"metrics":{"listen":"0.0.0.0:11111"},"log":{"output":"/outside/secret","error":"/outside/secret","access":"/outside/secret"},"services":[{"type":"ssm-api","listen":"::"}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}},"outbounds":[]}`), 19080)
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
