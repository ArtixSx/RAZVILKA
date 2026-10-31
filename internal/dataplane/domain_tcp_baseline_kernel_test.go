package dataplane

import (
	"bytes"
	"strings"
	"testing"
)

// Comparison model only. Native source, actual accepted socket and typed
// receipts are separate constructor requirements and cannot be minted here.
func domainTCPBaselineKernelModel(t *testing.T) (DomainTCPBaselineReadImage, DomainPolicyTCPCaptureSpec) {
	t.Helper()
	spec := xrayDomainExecutionDefinitionFixture(t).Capture
	image := DomainTCPBaselineReadImage{
		Rules:  []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`),
		Links:  []byte(`[{"ifindex":1,"ifname":"lo","qdisc":"noqueue","flags":["UP","LOWER_UP"]},{"ifindex":2,"ifname":"` + spec.Client.Interface + `","qdisc":"noqueue","flags":["UP","LOWER_UP"]},{"ifindex":3,"ifname":"wan0","qdisc":"fq_codel","flags":["UP","LOWER_UP"]}]`),
		Routes: []byte(`[{"dst":"default","dev":"wan0","gateway":"1.1.1.254"},{"type":"local","dst":"` + spec.Listen.Addr().String() + `","dev":"` + spec.Client.Interface + `","table":"local"}]`),
		Lookup: []byte(`[{"dst":"` + spec.Xray.RealIP.String() + `","from":"` + spec.Client.Address.String() + `","iif":"` + spec.Client.Interface + `","dev":"wan0","gateway":"1.1.1.254","cache":[]}]`),
	}
	return image, spec
}

func TestDomainTCPBaselineKernelContractRejectsUnsupportedPolicyWithoutGrant(t *testing.T) {
	image, spec := domainTCPBaselineKernelModel(t)
	if path, err := domainTCPBaselineKernelContract(image, spec); err != nil || path.Ingress != spec.Client.Interface || path.Egress != "wan0" {
		t.Fatal(path, err)
	}
	for _, change := range []string{"fwmark-rule", "extra-rule", "foreign-table", "encap", "classful-qdisc", "XDP", "unknown-link-field", "down-egress", "wrong-source", "wrong-ingress", "local-egress", "nonempty-cache", "duplicate-json", "trailing-json"} {
		t.Run(change, func(t *testing.T) {
			altered := image
			switch change {
			case "fwmark-rule":
				altered.Rules = bytes.Replace(image.Rules, []byte(`"priority":32766`), []byte(`"fwmark":"0x1","priority":32766`), 1)
			case "extra-rule":
				altered.Rules = append([]byte(`[{"priority":100,"src":"all","table":100},`), image.Rules[1:]...)
			case "foreign-table":
				altered.Routes = bytes.Replace(image.Routes, []byte(`"table":"local"`), []byte(`"table":100`), 1)
			case "encap":
				altered.Routes = bytes.Replace(image.Routes, []byte(`"dst":"default"`), []byte(`"encap":{},"dst":"default"`), 1)
			case "classful-qdisc":
				altered.Links = bytes.ReplaceAll(image.Links, []byte(`"fq_codel"`), []byte(`"clsact"`))
			case "XDP":
				altered.Links = bytes.Replace(image.Links, []byte(`"ifindex":1`), []byte(`"xdp":{"attached":"generic"},"ifindex":1`), 1)
			case "unknown-link-field":
				altered.Links = bytes.Replace(image.Links, []byte(`"ifindex":1`), []byte(`"future":true,"ifindex":1`), 1)
			case "down-egress":
				altered.Links = bytes.ReplaceAll(image.Links, []byte(`"flags":["UP","LOWER_UP"]`), []byte(`"flags":[]`))
			case "wrong-source":
				altered.Lookup = bytes.Replace(image.Lookup, []byte(spec.Client.Address.String()), []byte("192.168.1.99"), 1)
			case "wrong-ingress":
				altered.Lookup = bytes.Replace(image.Lookup, []byte(`"iif":"`+spec.Client.Interface+`"`), []byte(`"iif":"wan0"`), 1)
			case "local-egress":
				altered.Lookup = bytes.Replace(image.Lookup, []byte(`"dev":"wan0"`), []byte(`"dev":"lo"`), 1)
			case "nonempty-cache":
				altered.Lookup = bytes.Replace(image.Lookup, []byte(`"cache":[]`), []byte(`"cache":["local"]`), 1)
			case "duplicate-json":
				altered.Rules = bytes.Replace(image.Rules, []byte(`"priority":0`), []byte(`"priority":100,"priority":0`), 1)
			case "trailing-json":
				altered.Lookup = append([]byte(strings.TrimSpace(string(image.Lookup))), []byte(` []`)...)
			}
			if _, err := domainTCPBaselineKernelContract(altered, spec); err == nil {
				t.Fatal("unsupported kernel policy passed", change)
			}
		})
	}
	if _, err := newDomainTCPBaselineKernelOwner(nil, nil, nil); err == nil {
		t.Fatal("comparison DTO issued owner")
	}
}
