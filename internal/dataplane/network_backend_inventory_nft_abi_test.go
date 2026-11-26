package dataplane

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Source-shaped fixtures only; no socket, native observation or new decoder.
// Upstream sources and the nft95 evidence boundary are in
// docs/delivery-2026-10-03/handoffs/NFQWS_NFT_VM_ABI_DIAGNOSTIC_RU.md.
func TestBackendNFTLinux49ABIPositiveControl(t *testing.T) {
	request, err := backendNFTRequest(backendNFTGetGen, 19, 2345)
	if err != nil {
		t.Fatal("control request construction failed")
	}
	d, err := newBackendNFTDecoder(request, 0, &backendNFTBudget{})
	if err != nil {
		t.Fatal("control decoder construction failed")
	}
	if err := d.consume(backendNFTTestPacket(backendNFTTestGen())); err != nil || d.finish() == nil {
		t.Fatal("Linux 4.9 GEN failed or completed without ACK")
	}
	if err := d.consume(backendNFTTestPacket(backendNFTTestACK(request, 0))); err != nil || d.finish() != nil || !d.genSeen || !d.ackSeen || !d.done || d.failed || d.generation != 23 {
		t.Fatal("Linux 4.9 GEN and exact success ACK did not complete")
	}
	t.Log("nft ABI fixture: source=upstream-v4.9 outcome=validated-generation capability=ungranted")
}

func TestBackendNFTLinux70ABIRefusal(t *testing.T) {
	for _, shape := range []string{"NEWGEN_PROCESS_ATTRIBUTES", "SUCCESS_ACK_CAPPED"} {
		t.Run(shape, func(t *testing.T) {
			request, err := backendNFTRequest(backendNFTGetGen, 19, 2345)
			if err != nil {
				t.Fatal("fixture request construction failed")
			}
			d, err := newBackendNFTDecoder(request, 0, &backendNFTBudget{})
			if err != nil {
				t.Fatal("fixture decoder construction failed")
			}
			var packet []byte
			wantGenSeen := false
			reason := "GEN_ATTRIBUTES_OUTSIDE_LINUX49_ABI"
			if shape == "NEWGEN_PROCESS_ATTRIBUTES" {
				// v7.0 nf_tables_fill_gen_info: ID, PROC_PID, PROC_NAME.
				// Values are synthetic and never emitted, including on failure.
				body := append([]byte(nil), backendNFTTestGen()[16:]...)
				body = append(body, backendNFTTestAttr(2, backendNFTTestU32(4242))...)
				body = append(body, backendNFTTestAttr(3, []byte("qa-nft\x00"))...)
				packet = backendNFTTestFrame(backendNFTNewGen, 0, body)
			} else {
				// Isolate the independent ACK mismatch after a valid old GEN.
				if err := d.consume(backendNFTTestPacket(backendNFTTestGen())); err != nil || d.finish() == nil {
					t.Fatal("ACK fixture prerequisite GEN failed")
				}
				packet = backendNFTTestACK(request, 0)
				// v7.0 netlink_ack caps every successful ACK, even without
				// NETLINK_CAP_ACK. Body remains error=0 plus request header.
				binary.NativeEndian.PutUint16(packet[6:], 0x100) // NLM_F_CAPPED
				wantGenSeen = true
				reason = "ACK_FLAGS_OUTSIDE_LINUX49_ABI"
			}
			err = d.consume(backendNFTTestPacket(packet))
			var kernelError *backendNFTKernelError
			if !errors.Is(err, errBackendInventory) || errors.As(err, &kernelError) || !d.failed || d.done || d.genSeen != wantGenSeen || d.ackSeen || !errors.Is(d.finish(), errBackendInventory) {
				t.Fatal("upstream v7.0 shape did not produce sealed current-ABI Unknown")
			}
			// A rejected modern response cannot be repaired by later old frames.
			oldComplete := append(backendNFTTestGen(), backendNFTTestACK(request, 0)...)
			if !errors.Is(d.consume(backendNFTTestPacket(oldComplete)), errBackendInventory) || !errors.Is(d.finish(), errBackendInventory) || !d.failed || d.done {
				t.Fatal("failed ABI exchange was repaired by later frames")
			}
			t.Logf("nft ABI fixture: source=upstream-v7.0 shape=%s reason=%s outcome=current-ABI-refusal capability=ungranted", shape, reason)
		})
	}
}
