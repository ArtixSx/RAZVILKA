//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Negative-only producer witness in an explicitly isolated native build. The
// real source, sidecar and all policy adds have already ACKed. Do not return a
// health PASS or promote the candidate: the supervisor kills this ORIGINAL
// controller while the actual applying/policy-pending intent is still durable.
func mihomoSameBootNativeProducerPolicyACK(ctx context.Context, r *mihomoLiveResource, root string) (resultErr error) {
	if os.Getenv("RAZVILKA_MIHOMO_SAME_BOOT_PRODUCER") != "1" {
		return nil
	}
	if ctx == nil || r == nil || r.self != r || r.scope == nil || r.scope.manager == nil || r.scope.manager.StateRoot != "/opt/razvilka/state/dataplane" || root != filepath.Join(r.scope.root, "mihomo") {
		return errMihomoLiveMaterial
	}
	for _, kind := range []string{"net", "mnt"} {
		self, e1 := os.Readlink("/proc/self/ns/" + kind)
		host, e2 := os.Readlink("/proc/1/ns/" + kind)
		if os.Geteuid() != 0 || e1 != nil || e2 != nil || self == host {
			return errMihomoLiveMaterial
		}
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	receipt, err := r.proxy.readCandidatePolicyReceipt(root, r.definition.Policy)
	if err != nil || receipt.Phase != "complete" || receipt.Generation != "" {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	status, err := r.proxy.additionStatus(ctx, r.definition.Policy, root)
	if err != nil || !status.Complete || status.Unknown {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	if err := r.proxy.verifyForwarding(ctx, r.definition.Policy); err != nil {
		return err
	}
	r.scope.mu.Lock()
	valid := r.scope.execution != nil && r.scope.execution.State == "applying"
	if valid {
		for _, row := range r.scope.execution.Resources {
			if row.MihomoLive != nil {
				valid = valid && row.MihomoLive != nil && row.Phase == "policy-pending" && row.State == "prepared"
			} else if row.State != "removed" {
				valid = false
			}
		}
	}
	r.scope.mu.Unlock()
	if !valid {
		return errMihomoLiveMaterial
	}
	parent, err := openBootRetirementRoot(r.scope.manager.StateRoot)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	file, err := parent.OpenFile(".same-boot-native-ready.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	data, err := json.Marshal(struct{ PlanID, Digest string }{r.definition.Plan.PlanID, r.definition.Plan.Digest})
	if err == nil {
		var n int
		n, err = file.Write(data)
		if n != len(data) && err == nil {
			err = errMihomoLiveMaterial
		}
	}
	err = errors.Join(err, file.Sync(), file.Close(), syncBootRetirementDirectory(parent, "."))
	if err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}
