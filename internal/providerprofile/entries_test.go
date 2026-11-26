package providerprofile

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const entryGood = "vless://123e4567-e89b-12d3-a456-426614174000@good.example:443?security=tls#First"
const entryBad = "vless://123e4567-e89b-12d3-a456-426614174999@rejected.example:443?type=xhttp#REJECTED_SECRET"

func TestMixedEntriesKeepSupportedNodesOnly(t *testing.T) {
	array, _ := json.Marshal([]string{entryBad, entryGood})
	text := entryBad + "\n" + entryGood
	for name, input := range map[string]string{
		"text":   text,
		"base64": base64.StdEncoding.EncodeToString([]byte(text)),
		"json":   string(array),
		"native": `{"outbounds":[{"type":"vless","server":"rejected.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174999","transport":{"type":"xhttp"}},` + string(mustJSON(t, entryGood)) + `]}`,
		"yaml":   "proxies:\n  - {type: vless, name: REJECTED_SECRET, server: rejected.example, port: 443, uuid: 123e4567-e89b-12d3-a456-426614174999, network: xhttp}\n  - {type: vless, name: First, server: good.example, port: 443, uuid: 123e4567-e89b-12d3-a456-426614174000, tls: true}\n",
	} {
		t.Run(name, func(t *testing.T) {
			result, err := ParseProfile(input)
			if err != nil {
				t.Fatal(err)
			}
			p := result.Preview
			if p.NodeCount != 1 || p.Nodes[0].SourceIndex != 2 || len(p.Rejected) != 1 || p.Rejected[0].Index != 1 || p.Rejected[0].Code != "UNSUPPORTED_TRANSPORT" {
				t.Fatalf("wrong entry accounting: %+v", p)
			}
			public := string(mustJSON(t, p))
			for _, secret := range []string{"426614174999", "REJECTED_SECRET", "rejected.example", "vless://"} {
				if strings.Contains(public, secret) || strings.Contains(string(result.Config), secret) {
					t.Fatal("rejected entry leaked")
				}
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEntryDedupAndSelectionUseAcceptedIndexes(t *testing.T) {
	otherCredential := strings.Replace(entryGood, "426614174000", "426614174001", 1)
	input := strings.Join([]string{entryBad, entryGood, strings.Replace(entryGood, "#First", "#Duplicate", 1), otherCredential}, "\n")
	result, err := ParseProfileWithSelection(input, 1)
	if err != nil {
		t.Fatal(err)
	}
	p := result.Preview
	if p.NodeCount != 2 || p.SelectedIndex != 1 || p.Nodes[1].SourceIndex != 4 || len(p.Skipped) != 1 || p.Skipped[0].Index != 3 || p.Skipped[0].Code != "DUPLICATE_ENTRY" {
		t.Fatalf("wrong indexes: %+v", p)
	}
	var config map[string]any
	if err := json.Unmarshal(result.Config, &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range config["outbounds"].([]any) {
		node := v.(map[string]any)
		if node["type"] == "urltest" {
			found = true
			if node["outbounds"].([]any)[0] != "node-02" {
				t.Fatal("wrong initial node")
			}
		}
	}
	if !found {
		t.Fatal("missing pool")
	}
	if _, err := ParseProfileWithSelection(input, 3); err == nil {
		t.Fatal("source index accepted as selection")
	}
}

func TestAllRejectedAndMalformedEnvelopeNeverProduceConfig(t *testing.T) {
	result, err := ParseProfile(entryBad + "\n" + entryBad)
	if err == nil || ErrorCode(err) != "UNSUPPORTED_TRANSPORT" || len(result.Config) != 0 || len(result.Preview.Rejected) != 2 {
		t.Fatal("all-invalid bundle accepted or diagnostics lost")
	}
	for _, input := range []string{
		`[` + string(mustJSON(t, entryGood)) + `,`,
		`[` + string(mustJSON(t, entryGood)) + `] {}`,
		strings.Repeat(entryGood+"\n", MaxNodes+1),
		entryGood + "\x00",
	} {
		result, err := ParseProfile(input)
		if err == nil || len(result.Config) != 0 || result.Preview.NodeCount != 0 {
			t.Fatal("malformed envelope partially accepted")
		}
	}
}
