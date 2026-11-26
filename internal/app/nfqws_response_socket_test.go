package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Exercise a real TCP response through the production audit wrapper. The
// ordinary server deadline is shortened only in this test; no runtime caller
// budget, native permission, or production server default is replaced.
func TestManagedNFQResponseDeadlineTraversesAuditWriterOnActualSocket(t *testing.T) {
	for _, extend := range []bool{false, true} {
		name := "ordinary_deadline_expires"
		if extend {
			name = "managed_reply_survives_original_deadline"
		}
		t.Run(name, func(t *testing.T) {
			handlerErr := make(chan error, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writer := &auditResponseWriter{ResponseWriter: w}
				ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
				defer cancel()
				if extend {
					if err := managedNFQResponseDeadline(writer, ctx); err != nil {
						handlerErr <- err
						http.Error(writer, "response deadline unavailable", http.StatusServiceUnavailable)
						return
					}
				}
				time.Sleep(250 * time.Millisecond)
				_, err := io.WriteString(writer, "bounded reply")
				handlerErr <- err
			}))
			server.Config.WriteTimeout = 75 * time.Millisecond
			server.Start()
			defer server.Close()
			client := server.Client()
			client.Timeout = 3 * time.Second
			response, err := client.Post(server.URL, "application/json", nil)
			if !extend {
				if response != nil {
					response.Body.Close()
				}
				if err == nil {
					t.Fatal("expired ordinary socket unexpectedly delivered a response")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "bounded reply" {
				t.Fatalf("managed response: status=%d body=%q error=%v", response.StatusCode, body, err)
			}
			if err := <-handlerErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}
