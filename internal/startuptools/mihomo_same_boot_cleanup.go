package startuptools

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// The cold read ABI remains read-only. Native deletion requires a distinct
// sealed per-invocation CORE issuer and the original held-FD policy executor.
func (l *Lease) RunMihomoSameBootCleanup(ctx context.Context, admission dataplane.MihomoSameBootCommandAdmission, name string, args ...string) ([]byte, error) {
	if l == nil || admission == nil || !dataplane.OriginalMihomoSameBootCommand(ctx, admission, name, args, l.digest) {
		return nil, at("MIHOMO_SAME_BOOT_UNISSUED", nil)
	}
	return l.runPolicy(WithCommandAdmission(ctx, admission), name, args...)
}

func mihomoSameBootImplicitIPv4Delete(ctx context.Context, name, review string, index int, args []string) bool {
	if ctx == nil || index != 2 || len(args) < 3 || args[0] != "route" && args[0] != "rule" || args[1] != "del" || !effectArguments(2, append([]string{"-4"}, args...)) {
		return false
	}
	binding, ok := ctx.Value(admissionKey{}).(commandAdmission)
	if !ok {
		return false
	}
	admission, ok := binding.owner.(dataplane.MihomoSameBootCommandAdmission)
	return ok && dataplane.OriginalMihomoSameBootCommand(ctx, admission, name, args, review)
}
