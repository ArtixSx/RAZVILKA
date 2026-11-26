package updatecheck

import (
	"testing"
)

func TestFileCommandReceiptRequiresCoherentKernelEvidence(t *testing.T) {
	p := fileProcess{Boot: "01234567-89ab-cdef-0123-456789abcdef", PID: 20, Start: "123", ExecutableSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Inode: 5}
	r := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: "0123456789abcdef0123456789abcdef", Command: "quiesce-old-runtime", State: "reaped", Parent: p, Supervisor: p, DirectPID: 22, Reaped: 2, WaitECHILD: true}
	if !validFileCommandReceipt(r) {
		t.Fatal("coherent completed receipt refused")
	}
	for _, mutate := range []func(*fileCommandReceipt){
		func(r *fileCommandReceipt) { r.WaitECHILD = false }, func(r *fileCommandReceipt) { r.DirectPID = 0 }, func(r *fileCommandReceipt) { r.Reaped = 0 }, func(r *fileCommandReceipt) { r.Cancelled = true }, func(r *fileCommandReceipt) { r.State = "intent" }, func(r *fileCommandReceipt) { r.Supervisor.Boot = "11234567-89ab-cdef-0123-456789abcdef" }, func(r *fileCommandReceipt) { r.State = "future-state" }, func(r *fileCommandReceipt) { r.Runtime = p },
	} {
		next := r
		mutate(&next)
		// A retained runtime identity is valid only for a start command.
		if next.Runtime != (fileProcess{}) && next.Command != "start-candidate-panel" && next.Command != "start-rollback-panel" {
			next.State = "runtime-ready"
		}
		if validFileCommandReceipt(next) {
			t.Fatal("incoherent receipt supplied completion", next.State)
		}
	}
	r.Cancelled, r.ExitCode = true, 125
	if !validFileCommandReceipt(r) {
		t.Fatal("cancelled known ECHILD refused")
	}
}
