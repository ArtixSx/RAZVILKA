package app

import (
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodequality"
)

// Full App read-model regression. NOT run by the isolated harness.
func TestResearchNodeMeasurementAPIIsMemoryOnlyAndDefensive(t *testing.T) {
	a := &App{}
	now := time.Now().UTC()
	a.rememberNodeMeasurement(dataplane.NodeCheckResult{NodeID: "node-a", ServiceID: "telegram", NetworkProfile: "wan-one", RoutePathID: "sing-box:node-a", ProbeID: "probe-one", StartedAt: now.Add(-time.Second), FinishedAt: now, ExpiresAt: now.Add(time.Minute), Stages: []dataplane.NodeCheckStage{{ID: "tcp_connect", Status: "passed", Duration: 18}}})
	rows, ok := a.nodeCheckSnapshot()["node_measurements"].([]nodequality.Observation)
	if !ok || len(rows) != 1 || rows[0].TCPConnectMS == nil || *rows[0].TCPConnectMS != 18 {
		t.Fatal("measurement absent from read-model")
	}
	*rows[0].TCPConnectMS = 999
	again := a.nodeCheckSnapshot()["node_measurements"].([]nodequality.Observation)
	if *again[0].TCPConnectMS != 18 {
		t.Fatal("API response changed shared state")
	}
}
