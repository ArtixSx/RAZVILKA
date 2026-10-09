package main

import (
	"context"
	"net"
	"net/http"
	"time"
)

func newPanelHTTPServer(ctx context.Context, addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: handler,
		// Shutdown alone does not cancel requests (especially telemetry SSE).
		// Signal cancellation stops streams/probes, while Shutdown still waits
		// for handlers to finish their bounded, cancellation-independent cleanup.
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		// Validated managed NFQ launch/review handlers set their own finite
		// response deadline; ordinary requests retain this default.
		WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}
