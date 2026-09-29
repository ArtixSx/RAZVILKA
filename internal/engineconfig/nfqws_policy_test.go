package engineconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNFQWSPolicySettingsAndRuntime(t *testing.T) {
	v, err := nfqwsModeView([]byte("MODE_LIST=\"--hostlist=x\"\nNFQWS_EXTRA_ARGS=\"$MODE_LIST\"\nPOLICY_NAME=\"nfqws\"\nPOLICY_EXCLUDE=1\n"), "live")
	if err != nil || v.PolicyName != "nfqws" || !v.PolicyExclude {
		t.Fatalf("policy settings: %+v %v", v, err)
	}
	config := filepath.Join(t.TempDir(), "nfqws2.conf")
	if nfqwsPolicyRuntime(config) != nil {
		t.Fatal("runtime reported without nfqws2.conf.run")
	}
	// The owner's router: the policy does not exist, so no mark was found and
	// every device is processed.
	if err := os.WriteFile(config+".run", []byte("POLICY_NAME=\"nfqws\"\nPOLICY_EXCLUDE=0\nPOLICY_MARK=\"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := nfqwsPolicyRuntime(config); r == nil || r.Name != "nfqws" || r.Exclude || r.Found {
		t.Fatalf("missing policy: %+v", r)
	}
	if err := os.WriteFile(config+".run", []byte("POLICY_NAME=\"nfqws\"\nPOLICY_EXCLUDE=1\nPOLICY_MARK=\"0xffffaab/0x0fffffff\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := nfqwsPolicyRuntime(config); r == nil || !r.Exclude || !r.Found {
		t.Fatalf("found policy: %+v", r)
	}
}
