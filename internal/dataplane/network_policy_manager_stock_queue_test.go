package dataplane

import (
	"context"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"
)

// Original compiler/COMMON writer and pure complete-capture models. These tests
// establish comparison and refusal behavior, not a native provider or runtime.
func TestNetworkPolicyStockQueueComparisonConsumesActualCOMMONReceipt(t *testing.T) {
	b, model, root := nfqwsScopedBindingFixture(t)
	plan, spec, _ := nfqwsScopedDirectFixture(t, "ipv4")
	p, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	model.p = p
	b.ApplyGuard = func(_ context.Context, got *NFQWSScopedPlan, _ PolicyEffect) error {
		if got != model.p || model.stopped {
			return ErrReviewChanged
		}
		return nil
	}
	b.VerifyLAN = func(_ context.Context, got *LANPolicyRuntimePlan) error {
		if !reflect.DeepEqual(got, model.p.lan) {
			return ErrLANPolicyRuntime
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.Apply(ctx, p, root); err != nil {
		t.Fatal(err)
	}
	receipt, err := observeNetworkPolicyEffects(ctx, p.mixed, root, b.options)
	if err != nil || !receipt.status.Complete || receipt.status.Removed || receipt.status.Unknown {
		t.Fatal("actual original complete receipt refused", err)
	}
	defer receipt.close()
	states := make([]string, len(p.mixed.Effects))
	for i := range states {
		states[i] = "added"
	}
	rows, required, err := networkPolicyNFQReceiptRows(p, states, false)
	if err != nil {
		t.Fatal(err)
	}
	e := &nfqws2ActiveExecution{} // Comparison identity only, no issuer/provider.
	consumer := networkPolicyNFQObservation{execution: e, rows: rows, required: required}
	snapshot := nfqwsDirectStockQueueFixture()
	identity := snapshot.Scope.Network
	for _, row := range rows {
		snapshot.Rows = append(snapshot.Rows, BackendInventoryRow{Family: row.Family, Table: row.Table, Tokens: slices.Clone(row.Tokens)})
	}
	before := nfqwsDirectStockTestClone(snapshot)
	stock, err := networkPolicyStockQueueRows(snapshot, spec.Queue, e, []networkPolicyNFQObservation{consumer})
	if err != nil || len(stock) != 2 {
		t.Fatal("exact original owned body blocked stock OUTPUT comparison", err)
	}
	if err := checkNetworkPolicyInventoryWithStock(snapshot, identity, plan.LAN, LANPolicyNFQWSDirectMode, nil, stock, consumer); err != nil {
		t.Fatal("original complete predicate refused comparison", err)
	}
	if err := CheckLANPolicyInventory(snapshot, identity, plan.LAN); err == nil {
		t.Fatal("standalone predicate borrowed original receipt/queue context")
	}
	if !reflect.DeepEqual(snapshot, before) || receipt.current() != nil {
		t.Fatal("comparison changed the actual capture or COMMON receipt")
	}
	for _, failure := range []string{"missing-required", "foreign-ref", "duplicate", "wrong-owner", "managed-collision", "other-hook", "raw-queue", "missing-stock-row", "foreign-owned-body"} {
		t.Run(failure, func(t *testing.T) {
			image := nfqwsDirectStockTestClone(snapshot)
			observation := consumer
			comparison := stock
			switch failure {
			case "missing-required":
				image.Rows = slices.Delete(image.Rows, len(image.Rows)-1, len(image.Rows))
			case "foreign-ref":
				image.Rows = append(image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "OUTPUT", "-j", p.resources.Chains[0]))
			case "duplicate":
				image.Rows = append(image.Rows, image.Rows[len(image.Rows)-1])
			case "wrong-owner":
				observation.execution = &nfqws2ActiveExecution{}
			case "managed-collision":
				index := nfqwsDirectStockTestQueueIndex(image, 4)
				image.Rows[index].Tokens[len(image.Rows[index].Tokens)-1] = strconv.Itoa(int(spec.Queue))
			case "other-hook":
				image.Rows = append(image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", "FORWARD", "-j", "local_delay"))
			case "raw-queue":
				image.Rows = append(image.Rows, nfqwsDirectStockTestRow(6, "raw", "-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1234"))
			case "missing-stock-row":
				index := nfqwsDirectStockTestQueueIndex(image, 4)
				image.Rows = slices.Delete(image.Rows, index, index+1)
			case "foreign-owned-body":
				image.Rows = append(image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-A", p.resources.Chains[0], "-j", "RETURN"))
			}
			var graphErr error
			if failure != "missing-stock-row" {
				comparison, graphErr = networkPolicyStockQueueRows(image, spec.Queue, e, []networkPolicyNFQObservation{observation})
			}
			if graphErr == nil && checkNetworkPolicyInventoryWithStock(image, identity, plan.LAN, LANPolicyNFQWSDirectMode, nil, comparison, observation) == nil {
				t.Fatal("changed graph/receipt passed comparison", failure)
			}
		})
	}
}

func TestNetworkPolicyStockQueueMissingOriginalContextStaysStrict(t *testing.T) {
	c := &NetworkPolicyChecks{}
	ctx := context.Background()
	if o, err := c.stockQueueExecution(ctx); err != nil || o != nil {
		t.Fatal("missing context minted a stock comparison", err)
	}
	for _, value := range []any{uint16(200), &nfqws2ActiveExecution{}, "saved-queue"} {
		if o, err := c.stockQueueExecution(context.WithValue(ctx, nfqws2ActiveExecutionKey{}, value)); err == nil || o != nil {
			t.Fatal("cold/decoded context became original ownership", value)
		}
	}
	snapshot := nfqwsDirectStockQueueFixture()
	if err := checkNetworkPolicyInventoryForMode(snapshot, snapshot.Scope.Network, nil, LANPolicyNFQWSDirectMode, nil); err == nil {
		t.Fatal("direct mode alone allowed foreign queues")
	}
}

func TestNetworkPolicyStockQueueOptionalOwnedRowsAreOnlyActualRows(t *testing.T) {
	_, p, image := nfqwsScopedStockImageFixture(t, false)
	e := &nfqws2ActiveExecution{}
	states := make([]string, len(p.mixed.Effects))
	for i := range states {
		states[i] = "planned"
	}
	states[0] = "intent"
	rows, required, err := networkPolicyNFQReceiptRows(p, states, true)
	if err != nil {
		t.Fatal(err)
	}
	o := networkPolicyNFQObservation{execution: e, rows: rows, required: required}
	stock, err := networkPolicyStockQueueRows(image.capture.snapshot, p.spec.Queue, e, []networkPolicyNFQObservation{o})
	if err != nil || checkNetworkPolicyInventoryWithStock(image.capture.snapshot, image.capture.snapshot.Scope.Network, p.lan, LANPolicyNFQWSDirectMode, nil, stock, o) != nil {
		t.Fatal("missing optional intent row was invented or required", err)
	}
}
