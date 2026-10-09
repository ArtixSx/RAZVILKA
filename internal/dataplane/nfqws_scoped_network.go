package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type nfqwsScopedNetworkBinding struct {
	provider  *netidentity.Provider
	inventory BackendInventory
}

// NewTypedNFQWSScopedBinding freezes existing owner guards and the held tool
// collector. It issues no reservation, tool lease, process or effect grant.
// The caller retains its admitted tool descriptor for this binding's lifetime.
// Legacy namespace callbacks cannot supply typed queue/backend observations.
func NewTypedNFQWSScopedBinding(provider *netidentity.Provider, inventory *BackendInventory, binding NFQWSScopedBinding) (*NFQWSScopedBinding, error) {
	if provider == nil || inventory == nil || inventory.reader.Provider != provider || inventory.reader.Runner == nil || inventory.reader.CheckTools == nil ||
		binding.network != nil || binding.Runner == nil || binding.ApplyGuard == nil || binding.CleanupGuard == nil || binding.VerifyLAN == nil ||
		binding.ProcessRunning == nil || binding.ProcessInactive == nil || binding.AdditionalReadback == nil ||
		binding.Tools.IPTables != inventory.reader.IPTables || binding.Tools.IP6Tables != inventory.reader.IP6Tables {
		return nil, ErrNFQWSScopedOwner
	}
	if _, ok := inventory.reader.Runner.(backendInventoryBoundedRunner); !ok {
		return nil, ErrNFQWSScopedOwner
	}
	binding.network = &nfqwsScopedNetworkBinding{provider: provider, inventory: *inventory}
	binding.QueueCheck, binding.queueReadiness = nil, nil
	return &binding, nil
}

func nfqwsScopedTypedNetwork(p *NFQWSScopedPlan) (netidentity.Identity, error) {
	if p == nil || p.resources.NetworkIdentity == nil || p.spec.NetworkIdentity == nil ||
		!nfqwsScopedSpecNetworkValid(p.spec) || *p.resources.NetworkIdentity != *p.spec.NetworkIdentity {
		return netidentity.Identity{}, ErrNFQWSScopedOwner
	}
	return *p.resources.NetworkIdentity, nil
}

func (b *NFQWSScopedBinding) checkQueue(ctx context.Context, p *NFQWSScopedPlan, child *components.NFQWSRuntimeProcessIdentity) error {
	if b == nil || p == nil {
		return ErrNFQWSScopedOwner
	}
	if b.network == nil {
		if p.resources.NetworkIdentity != nil || b.QueueCheck == nil {
			return ErrNFQWSScopedOwner
		}
		return b.QueueCheck(ctx, p.resources.NetNamespace, p.resources.Queue, child)
	}
	identity, err := nfqwsScopedTypedNetwork(p)
	if err != nil {
		return err
	}
	if p.lan != nil && p.lan.Mode == LANPolicyNFQWSDirectMode {
		proof, err := b.stockQueueProof(ctx, p)
		if err != nil {
			return err
		}
		ready, err := nfqwsScopedTypedStockQueueObserve(ctx, proof, child)
		if err != nil || ready != (child != nil) {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		return nil
	}
	return CheckTypedNFQWSScopedQueue(ctx, b.network.provider, identity, p.resources.Queue, child)
}

func (b *NFQWSScopedBinding) checkQueueReadiness(ctx context.Context, p *NFQWSScopedPlan, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	if b == nil || p == nil {
		return false, ErrNFQWSScopedOwner
	}
	if b.network == nil {
		if p.resources.NetworkIdentity != nil || b.queueReadiness == nil {
			return false, ErrNFQWSScopedOwner
		}
		return b.queueReadiness(ctx, p.resources.NetNamespace, p.resources.Queue, child)
	}
	identity, err := nfqwsScopedTypedNetwork(p)
	if err != nil {
		return false, err
	}
	if p.lan != nil && p.lan.Mode == LANPolicyNFQWSDirectMode {
		if child == nil {
			return false, ErrNFQWSScopedOwner
		}
		proof, err := b.stockQueueProof(ctx, p)
		if err != nil {
			return false, err
		}
		return nfqwsScopedTypedStockQueueObserve(ctx, proof, child)
	}
	return nfqwsScopedTypedQueueReadiness(ctx, b.network.provider, identity, p.resources.Queue, child)
}

func (n *nfqwsScopedNetworkBinding) rules(ctx context.Context, p *NFQWSScopedPlan) (nfqwsScopedReadImage, error) {
	identity, err := nfqwsScopedTypedNetwork(p)
	if n == nil || err != nil {
		return nfqwsScopedReadImage{}, errors.Join(ErrNFQWSScopedOwner, err)
	}
	snapshot, err := n.inventory.Read(ctx, identity)
	if err != nil || snapshot.RequireComplete() != nil || snapshot.Scope.Network != identity {
		return nfqwsScopedReadImage{}, errors.Join(ErrNFQWSScopedOwner, err)
	}
	rules, err := nfqwsScopedInventoryRules(snapshot)
	if err != nil {
		return nfqwsScopedReadImage{}, err
	}
	return nfqwsScopedReadImage{rules: rules, capture: &nfqwsScopedReadCapture{source: n, plan: p, snapshot: snapshot}}, nil
}

func (b *NFQWSScopedBinding) stockComparisonRows(p *NFQWSScopedPlan, image nfqwsScopedReadImage) ([]BackendInventoryRow, error) {
	if b == nil || p == nil {
		return nil, ErrNFQWSScopedOwner
	}
	if image.capture == nil {
		if b.network != nil || p.resources.NetworkIdentity != nil || p.spec.NetworkIdentity != nil {
			return nil, ErrNFQWSScopedOwner
		}
		return nil, nil // Bare/untyped rule maps retain the global strict policy.
	}
	c := image.capture
	identity, err := nfqwsScopedTypedNetwork(p)
	if err != nil || b.network == nil || c.source != b.network || c.plan != p || p.resources.Queue == 0 || p.resources.Queue != p.spec.Queue {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	n := b.network
	if n.provider == nil || n.inventory.reader.Provider != n.provider || n.inventory.reader.Runner == nil || n.inventory.reader.CheckTools == nil ||
		b.Tools.IPTables != n.inventory.reader.IPTables || b.Tools.IP6Tables != n.inventory.reader.IP6Tables ||
		c.snapshot.Scope.Network != identity || c.snapshot.Scope.ToolReviewID != n.inventory.review ||
		c.snapshot.IPTables != n.inventory.reader.IPTables || c.snapshot.IP6Tables != n.inventory.reader.IP6Tables {
		return nil, ErrNFQWSScopedOwner
	}
	if len(c.snapshot.Rows) > backendClassicRows {
		return nil, ErrNFQWSScopedOwner
	}
	var budget nfqwsDirectStockBudget
	for _, row := range c.snapshot.Rows {
		if !budget.add(row) {
			return nil, ErrNFQWSScopedOwner
		}
	}
	projection, err := nfqwsScopedInventoryRules(c.snapshot)
	if err != nil || !reflect.DeepEqual(projection, image.rules) {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if p.lan == nil || p.lan.Mode != LANPolicyNFQWSDirectMode {
		return nil, nil
	}
	ownedKeys := map[PolicyEffectTool]map[string]bool{}
	for _, effect := range p.mixed.Effects {
		if len(effect.Add) < 4 || effect.Add[0] != "-t" || effect.Add[1] != "mangle" || effect.Tool != PolicyEffectIPTables && effect.Tool != PolicyEffectIP6Tables {
			return nil, ErrNFQWSScopedOwner
		}
		if ownedKeys[effect.Tool] == nil {
			ownedKeys[effect.Tool] = map[string]bool{}
		}
		ownedKeys[effect.Tool][nfqwsScopedRuleKey(effect.Add[2:])] = true
	}
	var exactOwned []BackendInventoryRow
	for _, row := range c.snapshot.Rows {
		if row.Table != "mangle" {
			continue
		}
		tool := PolicyEffectIPTables
		if row.Family == 6 {
			tool = PolicyEffectIP6Tables
		}
		if ownedKeys[tool][nfqwsScopedRuleKey(row.Tokens)] {
			exactOwned = append(exactOwned, row)
		}
	}
	comparison, err := inspectNFQWSDirectStockQueuesWithOwned(c.snapshot, p.resources.Queue, exactOwned)
	if err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return comparison, nil
}

func (b *NFQWSScopedBinding) ruleCountsImage(p *NFQWSScopedPlan, image nfqwsScopedReadImage, mode nfqwsScopedReadMode) ([]int, error) {
	comparison, err := b.stockComparisonRows(p, image)
	if err != nil {
		return nil, err
	}
	return p.ruleCountsCompared(image.rules, mode, comparison)
}

func (b *NFQWSScopedBinding) scopedRowCountsImage(p *NFQWSScopedPlan, image nfqwsScopedReadImage) ([]int, error) {
	comparison, err := b.stockComparisonRows(p, image)
	if err != nil {
		return nil, err
	}
	return p.scopedRowCountsCompared(image.rules, comparison)
}

// Post-RPC typed observations use a fresh original whole capture. A legacy
// target-table image cannot manufacture coverage or borrow an earlier proof.
func (b *NFQWSScopedBinding) readEffectImage(ctx context.Context, p *NFQWSScopedPlan, tool PolicyEffectTool) (nfqwsScopedReadImage, error) {
	if b.network != nil {
		return b.readClassicRules(ctx, p)
	}
	out, err := b.readTargetRules(ctx, p, tool)
	if err != nil || ctx.Err() != nil || len(out) > 1<<20 || !utf8.Valid(out) {
		return nfqwsScopedReadImage{}, errors.Join(ErrNFQWSScopedOwner, err, ctx.Err())
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 8192 {
		return nfqwsScopedReadImage{}, ErrNFQWSScopedOwner
	}
	var rows [][]string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields, err := backendXTablesRowTokens(line)
		if err != nil {
			return nfqwsScopedReadImage{}, ErrNFQWSScopedOwner
		}
		rows = append(rows, fields)
	}
	return nfqwsScopedReadImage{rules: nfqwsScopedRules{tool: {"mangle": rows}}}, nil
}

func nfqwsScopedInventoryRules(snapshot BackendInventorySnapshot) (nfqwsScopedRules, error) {
	if err := snapshot.RequireComplete(); err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	rules := nfqwsScopedRules{PolicyEffectIPTables: {}, PolicyEffectIP6Tables: {}}
	for _, row := range snapshot.Rows {
		tool := PolicyEffectIPTables
		if row.Family == 6 {
			tool = PolicyEffectIP6Tables
		} else if row.Family != 4 {
			return nil, ErrNFQWSScopedOwner
		}
		if !backendClassicTableName(row.Table) || len(row.Tokens) == 0 {
			return nil, ErrNFQWSScopedOwner
		}
		rules[tool][row.Table] = append(rules[tool][row.Table], slices.Clone(row.Tokens))
	}
	return rules, nil
}

func (b *NFQWSScopedBinding) readTargetRules(ctx context.Context, p *NFQWSScopedPlan, tool PolicyEffectTool) ([]byte, error) {
	if b == nil || p == nil || (tool != PolicyEffectIPTables && tool != PolicyEffectIP6Tables) {
		return nil, ErrNFQWSScopedOwner
	}
	if b.network == nil {
		if p.resources.NetworkIdentity != nil {
			return nil, ErrNFQWSScopedOwner
		}
		return b.Runner.Run(ctx, b.Tools.command(tool), "-t", "mangle", "-S")
	}
	r := nfqwsScopedTypedRunner{base: b.Runner, network: b.network, plan: p}
	return r.RunBounded(ctx, b.Tools.command(tool), 1<<20, "-t", "mangle", "-S")
}

// Only the original admitted runner performs Cmd.Start. The typed provider
// brackets this exact CLI, and the existing held descriptor checks its files.
type nfqwsScopedTypedRunner struct {
	base    NFQWS2Runner
	network *nfqwsScopedNetworkBinding
	plan    *NFQWSScopedPlan
}

func (r nfqwsScopedTypedRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.run(ctx, name, 0, args)
}
func (r nfqwsScopedTypedRunner) RunBounded(ctx context.Context, name string, limit int, args ...string) ([]byte, error) {
	if limit <= 0 {
		return nil, ErrNFQWSScopedOwner
	}
	return r.run(ctx, name, limit, args)
}
func (r nfqwsScopedTypedRunner) run(ctx context.Context, name string, limit int, args []string) ([]byte, error) {
	identity, err := nfqwsScopedTypedNetwork(r.plan)
	if err != nil || r.network == nil || r.base == nil ||
		(name != r.network.inventory.reader.IPTables && name != r.network.inventory.reader.IP6Tables) {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	var output []byte
	err = r.network.provider.WithCurrent(ctx, func(c context.Context, current netidentity.Identity) error {
		if current != identity {
			return ErrNFQWSScopedOwner
		}
		if err := r.network.inventory.reader.CheckTools(c, backendInventoryScope{Network: identity, ToolReviewID: r.network.inventory.review}); err != nil {
			return err
		}
		var err error
		if limit != 0 {
			// The frozen policy runner consumes effect admission. Inspection
			// uses only the SAME retained inventory's bounded read producer.
			bounded, ok := r.network.inventory.reader.Runner.(backendInventoryBoundedRunner)
			if !ok {
				return ErrNFQWSScopedOwner
			}
			output, err = bounded.RunBounded(c, name, limit, slices.Clone(args)...)
		} else {
			output, err = r.base.Run(c, name, slices.Clone(args)...)
		}
		return err
	})
	if err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return output, nil
}
