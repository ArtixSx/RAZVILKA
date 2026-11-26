package dataplane

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// Optional local read-only diagnosis of a retained token image. Its modeled
// coverage/profile are comparison inputs, never native observation proof. The
// path, raw rows, identifiers and error details never enter test output.
func TestExecutionAttemptIDPrivateStockImageDiagnosis(t *testing.T) {
	path := os.Getenv("RAZVILKA_PRIVATE_STOCK_IMAGE_DIAGNOSTIC")
	if path == "" {
		t.Skip("optional retained local image was not provided")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("retained local image could not be read")
	}
	defer clear(data)
	var tables []struct {
		Family int        `json:"family"`
		Table  string     `json:"table"`
		Rows   [][]string `json:"rows"`
	}
	if json.Unmarshal(data, &tables) != nil || len(tables) == 0 {
		t.Fatal("retained local image shape refused")
	}
	s := nfqwsDirectStockReviewedVendorFixture()
	s.Rows = nil
	for _, table := range tables {
		for _, tokens := range table.Rows {
			s.Rows = append(s.Rows, BackendInventoryRow{Family: table.Family, Table: table.Table, Tokens: tokens})
		}
	}
	stock, err := inspectXrayStockOutputQueues(s)
	if err != nil || len(stock) != 2 {
		t.Fatal("retained token image refused by original stock graph comparison")
	}
	strict := checkNetworkPolicyInventoryWithStock(s, s.Scope.Network, nil, LANPolicyManagedListMode, nil, nil)
	if !errors.Is(strict, ErrLANPolicyRuntime) || LANPolicyPreflightFailureStage(strict) != "inventory-row-unallowed" {
		t.Fatal("cold comparison did not identify the closed unallowed-row stage")
	}
	if checkNetworkPolicyInventoryWithStock(s, s.Scope.Network, nil, LANPolicyManagedListMode, nil, stock) != nil {
		t.Fatal("stock comparison did not account for the complete retained token image")
	}
	t.Log("retained token grammar accepted; cold comparison refused at inventory-row-unallowed; exact original stock comparison accepted")
}
