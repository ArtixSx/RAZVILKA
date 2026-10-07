package startuptools

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// CommandAdmission is implemented by the trusted CORE owner. WithStart checks
// the original operation/control/review under its already-held exclusive lease,
// compares the exact command and tools digest, and synchronously calls begin
// once. Its presence alone is not an admission grant. Do not reenter Operations.
type CommandAdmission interface {
	WithStart(context.Context, string, []string, string, func() error) error
}

type admissionKey struct{}
type commandAdmission struct{ owner CommandAdmission }

// WithCommandAdmission preserves the original context and stores the actual
// CORE start barrier. It does not manufacture operation or command authority.
func WithCommandAdmission(ctx context.Context, owner CommandAdmission) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, admissionKey{}, commandAdmission{owner})
}

func AcquireUbuntuLegacyPolicy(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquire(ctx, provider, ubuntuPolicyProfile())
}

func AcquireReviewedStockNC1812Policy(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquire(ctx, provider, stockPolicyProfile())
}

type policyRunner struct{ lease *Lease }

// PolicyRuntimeTools requires the separately issued IP + xtables policy lease.
// The returned runner reads only the fixed inspection ABI without admission;
// effects consume CommandAdmission at the actual process-start boundary.
func (l *Lease) PolicyRuntimeTools() (dataplane.PolicyEffectTools, dataplane.NFQWS2Runner, error) {
	if l == nil || l.lifetime == nil {
		return dataplane.PolicyEffectTools{}, nil, at("LIFETIME", nil)
	}
	c, cancel := context.WithTimeout(l.lifetime, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return dataplane.PolicyEffectTools{}, nil, err
	}
	defer l.unlock()
	if l.review == nil || l.review.ipEntry == nil || l.profile.ipAlias == "" || l.digest == "" || l.provider == nil || l.identity.Validate() != nil {
		return dataplane.PolicyEffectTools{}, nil, at("POLICY_UNISSUED", nil)
	}
	return dataplane.PolicyEffectTools{IP: l.profile.ipAlias, IPTables: l.profile.aliases[0], IP6Tables: l.profile.aliases[1]}, &policyRunner{l}, nil
}

func (r *policyRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r == nil || r.lease == nil {
		return nil, at("POLICY_UNISSUED", nil)
	}
	return r.lease.runPolicy(ctx, name, args...)
}

func ipReadArguments(args []string) bool {
	return len(args) == 4 && (args[0] == "-4" || args[0] == "-6") && args[1] == "-N" && args[2] == "rule" && args[3] == "show"
}

// This bounds the direct command ABI; CORE still compares it with the private
// compiled plan. No shell, file batch/restore, flush or policy-wide command ABI.
func effectArguments(index int, args []string) bool {
	if len(args) < 4 || !boundedArguments(args) {
		return false
	}
	if index == 2 {
		return (args[0] == "-4" || args[0] == "-6") && (args[1] == "rule" || args[1] == "route") && (args[2] == "add" || args[2] == "del" || args[1] == "route" && args[2] == "replace")
	}
	if index < 0 || index > 1 || args[0] != "-t" || !readArguments([]string{"-t", args[1], "-S"}) {
		return false
	}
	return args[2] == "-A" || args[2] == "-D" || args[2] == "-I" || args[2] == "-N" || args[2] == "-X"
}

func boundedArguments(args []string) bool {
	if len(args) == 0 || len(args) > 128 {
		return false
	}
	bytes := 0
	for _, arg := range args {
		bytes += len(arg)
		if arg == "" || len(arg) > 1024 || bytes > 32<<10 || !utf8.ValidString(arg) || strings.ContainsAny(arg, "\x00\r\n") {
			return false
		}
	}
	return true
}

// invokeAdmission has no executor injection in the public API. The private
// begin belongs to the retained production runner. sameThread is the locked
// calling OS thread, preventing asynchronous use even before owner returns.
func invokeAdmission(ctx context.Context, name string, args []string, digest string, sameThread func() bool, begin func() error) error {
	if ctx == nil || ctx.Err() != nil || sameThread == nil || begin == nil {
		return at("ADMISSION_SCOPE", nil)
	}
	binding, ok := ctx.Value(admissionKey{}).(commandAdmission)
	if !ok || binding.owner == nil {
		return at("ADMISSION_MISSING", nil)
	}
	var mu sync.Mutex
	active, completed, invalid, calls := true, false, false, 0
	var startErr error
	once := func() error {
		mu.Lock()
		calls++
		if !active || calls != 1 || !sameThread() || ctx.Err() != nil {
			invalid = true
			mu.Unlock()
			return at("ADMISSION_BEGIN", nil)
		}
		mu.Unlock()
		err := begin()
		mu.Lock()
		completed, startErr = true, err
		mu.Unlock()
		return err
	}
	// The owner cannot mutate the command that the runner actually executes.
	ownerErr := callAdmissionOwner(binding.owner, ctx, name, append([]string(nil), args...), digest, once)
	mu.Lock()
	active = false
	valid := calls == 1 && completed && !invalid
	err := startErr
	mu.Unlock()
	if !valid || ownerErr != nil || err != nil {
		return at("ADMISSION_RESULT", errors.Join(ownerErr, err))
	}
	return nil
}

func callAdmissionOwner(owner CommandAdmission, ctx context.Context, name string, args []string, digest string, begin func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = at("ADMISSION_PANIC", nil)
		}
	}()
	return owner.WithStart(ctx, name, args, digest, begin)
}
