package dataplane

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

func exactSingBoxTransportSupported(raw []byte) bool {
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		// Other malformed legacy materials retain their existing validation.
		return true
	}
	return providerprofile.SingBoxSupportsOutbound(out)
}

func (c *ExactNodeChecker) requireXHTTPRuntime(ctx context.Context, binary string) error {
	probe := c.xhttpRuntime
	if probe == nil {
		probe = exactXHTTPRuntimeVersion
	}
	supported, err := probe(ctx, binary)
	if err != nil {
		return ErrExactNodeRuntime
	}
	if !supported {
		return ErrExactNodeUnsupported
	}
	return nil
}

func exactXHTTPRuntimeVersion(parent context.Context, binary string) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "version").Output()
	defer clear(output)
	return err == nil && exactXHTTPVersionOutput(output), err
}

func exactXHTTPVersionOutput(output []byte) bool {
	return len(output) <= 4096 && strings.HasPrefix(string(output), "Xray "+providerprofile.XHTTPXrayVersion+" ")
}

func exactNodeProofEngine(observed, expected string) bool {
	// Historical Sing-box proofs used an implicit engine. New Xray paths
	// require it explicitly, and a supplied foreign engine is never accepted.
	return observed == expected || observed == "" && expected == "sing-box"
}
