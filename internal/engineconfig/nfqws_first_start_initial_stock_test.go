package engineconfig

import (
	"bytes"
	"strings"
	"testing"
)

func TestNFQWSFirstStartPinnedUniversalStockVariant(t *testing.T) {
	stock := bytes.Replace(firstStartStock(t), []byte(`NFQWS_BASE_ARGS="--lua-init=`), []byte("NFQWS_BASE_ARGS=\"--fastpath-workaround=auto\n                 --lua-init="), 1)
	fields, err := parseShellAssignments(string(stock))
	if err != nil {
		t.Fatal(err)
	}
	var seal strings.Builder
	for _, key := range nfqwsFirstStartStockFields {
		seal.WriteString(key + "\x00" + fields[key] + "\x00")
	}
	t.Log("universal static SHA", nfqwsFirstStartDigest([]byte(seal.String())))
	if err := NFQWSFirstStartStockConfig(stock); err != nil {
		t.Fatal(err)
	}
	closed, err := NFQWSFirstStartConfig(stock, "0123456789abcdef01234567", []string{"selected.example"}, []string{"bank.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := NFQWSFirstStartEffectiveConfig(closed, "0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(effective, "--fastpath-workaround=0") || strings.Contains(effective, "--fastpath-workaround=auto") {
		t.Fatal("closed profile retained broad upstream base", effective)
	}
	foreign := bytes.Replace(stock, []byte("--fastpath-workaround=auto"), []byte("--fastpath-workaround=1"), 1)
	if NFQWSFirstStartStockConfig(foreign) == nil {
		t.Fatal("unreviewed base variant admitted")
	}
}
