//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

const backendNFTNativeObservationOptIn = "RAZVILKA_BACKEND_NFT_OBSERVE_NATIVE"

// Explicit platform evidence only. No namespace provider/capability/owner
// receipt is constructed here. GET may trigger kernel request_module; this
// test sends no batch, mutation, group join, module command or setns call.
func TestBackendNFTNativeObservation(t *testing.T) {
	if os.Getenv(backendNFTNativeObservationOptIn) != "1" {
		t.Skip("NFT packet observation QA opt-in disabled")
	}
	if os.Geteuid() != 0 {
		t.Fatal("NFT packet observation requires root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var kernel unix.Utsname
	if unix.Uname(&kernel) != nil {
		t.Fatal("nft observation: request=UNAME outcome=generic-unknown capability=ungranted")
	}
	var release []byte
	terminated := false
	for _, c := range kernel.Release {
		if c == 0 {
			terminated = true
			break
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '+' || c == '-') {
			t.Fatal("nft observation: request=UNAME outcome=generic-unknown capability=ungranted")
		}
		release = append(release, byte(c))
	}
	if !terminated || len(release) == 0 {
		t.Fatal("nft observation: request=UNAME outcome=generic-unknown capability=ungranted")
	}
	// Static wire contract; socket-assigned port/sequence, packet contents,
	// actual generations, table names and process/namespace identity stay private.
	const contract = "UNSPEC_REQUEST_ACK_GETGEN_DUMP_GETTABLE_GETGEN_LINUX49"
	ctx, cancel := context.WithTimeout(context.Background(), backendInventoryTimeout)
	defer cancel()
	socket, err := openBackendNFTSocket(ctx)
	if err != nil || socket == nil {
		t.Fatalf("nft observation: kernel=%s request=OPEN contract=%s outcome=generic-unknown capability=ungranted", release, contract)
	}
	defer func() {
		if socket.Close() != nil {
			t.Errorf("nft observation: kernel=%s request=CLOSE contract=%s outcome=generic-unknown capability=ungranted", release, contract)
		}
	}()
	// Only the existing decoder can produce this typed error after validating
	// kernel sender, destination port/sequence, flags and the exact echoed GET.
	// A bare syscall errno, decoder Unknown, cancellation or timeout cannot PASS.
	negativeACK := func(request string, err error, generations, tables int) {
		var ack *backendNFTKernelError
		if ctx.Err() == nil && errors.As(err, &ack) && ack != nil && ack.Code >= 1 && ack.Code <= 4095 && errors.Is(err, errBackendInventory) {
			t.Logf("nft observation: kernel=%s request=%s contract=%s outcome=validated-negative-kernel-ACK code=%d complete-gen-reads=%d complete-table-count=%d capability=ungranted", release, request, contract, ack.Code, generations, tables)
			return // PASS observes the refusal; it does not grant absence.
		}
		t.Fatalf("nft observation: kernel=%s request=%s contract=%s outcome=generic-unknown capability=ungranted", release, request, contract)
	}
	first, err := socket.Generation(ctx)
	if err != nil {
		negativeACK("GETGEN_A", err, 0, 0)
		return
	}
	tables, err := socket.Tables(ctx, first)
	if err != nil {
		negativeACK("GETTABLE", err, 1, 0)
		return
	}
	last, err := socket.Generation(ctx)
	if err != nil {
		negativeACK("GETGEN_B", err, 1, len(tables))
		return
	}
	if ctx.Err() != nil || first != last {
		t.Fatalf("nft observation: kernel=%s request=GETGEN_BRACKET contract=%s outcome=generic-unknown capability=ungranted", release, contract)
	}
	t.Logf("nft observation: kernel=%s request=GETGEN_GETTABLE_GETGEN contract=%s outcome=validated-complete complete-gen-reads=2 complete-table-count=%d generation-stable=true capability=ungranted", release, contract, len(tables))
}
