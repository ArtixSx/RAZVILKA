package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNodeEgressPairStartsBothPathsBeforeEitherCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan string, 2)
	release := make(chan struct{})
	finished := make(chan nodeEgressPair, 1)
	go func() {
		finished <- probeNodeEgressPair(ctx, "127.0.0.1:19181", func(ctx context.Context, endpoint nodeEgressEndpoint, proxy string) (string, error) {
			if !endpoint.trace {
				return "", errors.New("unexpected fallback")
			}
			started <- proxy
			select {
			case <-release:
			case <-ctx.Done():
				return "", ctx.Err()
			}
			if proxy == "" {
				return "8.8.8.8", nil
			}
			return "9.9.9.9", nil
		})
	}()
	paths := make(map[string]bool)
	for len(paths) < 2 {
		select {
		case path := <-started:
			paths[path] = true
		case <-time.After(time.Second):
			cancel()
			close(release)
			<-finished
			t.Fatal("one egress path waited for the other path to complete")
		}
	}
	close(release)
	result := <-finished
	if !paths[""] || !paths["127.0.0.1:19181"] || result.directIP != "8.8.8.8" || result.proxyIP != "9.9.9.9" || result.directErr != nil || result.proxyErr != nil {
		t.Fatalf("parallel pair lost its direct/proxy observations: %+v", result)
	}
}

func TestNodeEgressPairRefusalCancelsAndJoinsTheOtherPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxyStarted := make(chan struct{})
	proxyFinished := make(chan struct{})
	result := probeNodeEgressPair(ctx, "127.0.0.1:19181", func(ctx context.Context, endpoint nodeEgressEndpoint, proxy string) (string, error) {
		if !endpoint.trace {
			return "", errors.New("refusal must not retry another provider")
		}
		if proxy == "" {
			select {
			case <-proxyStarted:
				return "", ErrNodeResourceDenied
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		close(proxyStarted)
		<-ctx.Done()
		close(proxyFinished)
		return "", ctx.Err()
	})
	if !errors.Is(result.directErr, ErrNodeResourceDenied) || !errors.Is(result.proxyErr, ErrNodeResourceDenied) || result.directIP != "" || result.proxyIP != "" {
		t.Fatalf("refusal was lost or exposed a partial observation: %+v", result)
	}
	select {
	case <-proxyFinished:
	default:
		t.Fatal("pair returned before its other request finished")
	}
	if ctx.Err() != nil {
		t.Fatal("refusal waited for the parent's deadline")
	}
}
