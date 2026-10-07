//go:build linux

package nativeowner

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Local IPC only; no child, account, process identity or network probe is used.
func TestOwnerChannelCancelJoinsBeforeCleanupDeadlineReset(t *testing.T) {
	deadline := time.Now().Add(5 * time.Second)
	parent, endpoint, err := channelPair(deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	defer endpoint.Close()
	peer, err := openChannel(endpoint, os.Getpid(), deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.close()
	forward, cancel := context.WithDeadline(context.Background(), deadline)
	endForward, err := parent.withContext(forward)
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { _, err := parent.receive(); waited <- err }()
	cancel()
	endForward() // must join the deadline callback before cleanup can reset it
	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("canceled forward socket wait continued")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not promptly interrupt the socket wait")
	}
	cleanup, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	endCleanup, err := parent.withContext(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	defer endCleanup()
	want := frame{Version: 1, Kind: "stop", Binding: strings.Repeat("a", 64)}
	if peer.send(want) != nil {
		t.Fatal("same retained channel lost")
	}
	got, err := parent.receive()
	if err != nil || got != want {
		t.Fatal("joined cancellation poisoned the cleanup deadline")
	}
}
