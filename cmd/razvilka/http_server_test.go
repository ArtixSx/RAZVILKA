package main

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/telemetry"
)

func TestPanelServerShutdownClosesAuthenticatedTelemetryWithoutWaitingForHeartbeat(t *testing.T) {
	const token = "shutdown-test-token-01234567890123456789"
	gate, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{Security: gate, Telemetry: telemetry.NewStore()}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewUnstartedServer(nil)
	server.Config = newPanelHTTPServer(ctx, "", a.Handler(http.NotFoundHandler()))
	server.Start()
	defer server.Close()
	client := server.Client()
	client.Timeout = 2 * time.Second
	req, _ := http.NewRequest("GET", server.URL+"/api/v1/connections/stream", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
	reader := bufio.NewReader(response.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\n" {
			break
		}
	}
	cancel()
	grace, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := server.Config.Shutdown(grace); err != nil {
		t.Fatal("SSE retained shutdown", err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatal("stream forcibly closed", err)
	}
	if !a.Operations.Snapshot().Exclusive {
		t.Fatal("shutdown stole worker admission")
	}
}

func TestPanelServerShutdownWaitsForHandlerCleanupAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup, finish := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	server := httptest.NewUnstartedServer(nil)
	server.Config = newPanelHTTPServer(ctx, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(cleanup)
		<-finish
	}))
	server.Start()
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	cancel()
	select {
	case <-cleanup:
	case <-time.After(time.Second):
		t.Fatal("request not canceled")
	}
	grace, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	stopped := make(chan error, 1)
	go func() { stopped <- server.Config.Shutdown(grace) }()
	select {
	case err := <-stopped:
		t.Fatal("shutdown skipped cleanup", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(finish)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
}
