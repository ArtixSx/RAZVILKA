package dataplane

import (
	"errors"
	"strings"
)

var errXrayStockOutputQueue = errors.New("Xray stock OUTPUT queue graph refused")

// Pure detached comparison only. The caller authenticates its original Xray
// selected-TCP execution, identity and held tool review before supplying this
// SAME fresh whole snapshot. Xray owns no NFQ queue; every NFQUEUE row remains
// foreign, including queue zero and any number used by an unrelated consumer.
// Reserved mangle rows remain closed. Original NAT/COMMON receipt predicates,
// capture bookends and runtime authority remain with the original caller.
func inspectXrayStockOutputQueues(actualComplete BackendInventorySnapshot) ([]BackendInventoryRow, error) {
	rows, err := inspectStockOutputQueueGraph(actualComplete, nil, nil)
	if err != nil {
		return nil, errors.Join(errXrayStockOutputQueue, err)
	}
	for _, row := range actualComplete.Rows {
		if row.Table == "mangle" && (strings.HasPrefix(row.Tokens[1], "RZX_") || networkPolicyReferencesPrefix(row.Tokens, "RZX_")) {
			return nil, errXrayStockOutputQueue
		}
	}
	return rows, nil
}
