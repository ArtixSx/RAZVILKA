package dataplane

import (
	"slices"
	"strings"
	"testing"
)

func TestNFQWSScopedDirectReadbackCanonicalMACAndClosedVocabulary(t *testing.T) {
	compiler := []string{"-i", "br0", "-s", "192.168.1.0/24", "-m", "mac", "--mac-source", "02:AB:CD:EF:00:11", "-d", "8.8.8.8/32", "-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "40321"}
	canonical := []string{"-s", "192.168.1.0/24", "-d", "8.8.8.8/32", "-i", "br0", "-p", "tcp", "-m", "mac", "--mac-source", "02:ab:cd:ef:00:11", "-m", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "40321"}
	if !nfqwsScopedRuleEqual(compiler, canonical) {
		t.Fatal("kernel MAC case/order changed exact predicates")
	}
	for _, kind := range []string{"other MAC", "missing selector", "missing module", "duplicate module", "duplicate selector", "negation", "multicast", "zero", "EUI64", "alternate spelling", "unknown extension"} {
		t.Run(kind, func(t *testing.T) {
			changed := slices.Clone(canonical)
			macIndex := slices.Index(changed, "--mac-source")
			moduleIndex := slices.Index(changed, "mac") - 1
			switch kind {
			case "other MAC":
				changed[macIndex+1] = "02:ab:cd:ef:00:22"
			case "missing selector":
				changed = slices.Delete(changed, macIndex, macIndex+2)
			case "missing module":
				changed = slices.Delete(changed, moduleIndex, moduleIndex+2)
			case "duplicate module":
				changed = append(changed, "-m", "mac")
			case "duplicate selector":
				changed = append(changed, "--mac-source", changed[macIndex+1])
			case "negation":
				changed = slices.Insert(changed, macIndex, "!")
			case "multicast":
				changed[macIndex+1] = "03:ab:cd:ef:00:11"
			case "zero":
				changed[macIndex+1] = "00:00:00:00:00:00"
			case "EUI64":
				changed[macIndex+1] = "02:ab:cd:ef:00:11:22:33"
			case "alternate spelling":
				changed[macIndex+1] = "02-ab-cd-ef-00-11"
			case "unknown extension":
				changed = append(changed, "-m", "owner")
			}
			if nfqwsScopedRuleEqual(compiler, changed) {
				t.Fatal("foreign MAC predicate became the same receipt-owned rule")
			}
		})
	}
}

func TestNFQWSScopedDirectReadbackRequiresExactOrderedNegativesAndAttachment(t *testing.T) {
	_, _, p := nfqwsScopedDirectFixture(t, "ipv4")
	for _, cut := range []string{"complete", "late negative", "missing MAC", "unscoped jump", "foreign reference"} {
		t.Run(cut, func(t *testing.T) {
			effects, err := p.Effects()
			if err != nil {
				t.Fatal(err)
			}
			rules := nfqwsScopedRules{PolicyEffectIPTables: {"mangle": nil}}
			for _, effect := range effects.Effects {
				rules[effect.Tool]["mangle"] = append(rules[effect.Tool]["mangle"], slices.Clone(effect.Add[2:]))
			}
			rows := rules[PolicyEffectIPTables]["mangle"]
			switch cut {
			case "late negative":
				rows[1], rows[3] = rows[3], rows[1]
			case "missing MAC":
				for rowIndex, row := range rows {
					if slices.Contains(row, "NFQUEUE") {
						i := slices.Index(row, "--mac-source")
						rows[rowIndex] = slices.Delete(row, i-2, i+2)
						break
					}
				}
			case "unscoped jump":
				rows[len(rows)-1] = []string{"-A", "FORWARD", "-j", p.chains[0].name}
			case "foreign reference":
				rows = append(rows, []string{"-A", "OUTPUT", "-j", p.chains[0].name})
			}
			rules[PolicyEffectIPTables]["mangle"] = rows
			_, err = p.ruleCounts(rules, nfqwsScopedComplete)
			if cut == "complete" && err != nil || cut != "complete" && err == nil {
				t.Fatal("readback promoted a changed physical boundary", cut, err)
			}
		})
	}
}

func TestNFQWSScopedDirectLegacyCompilerImage(t *testing.T) {
	// Measured against the pre-direct compiler at c60b1a805542 with Go overlay,
	// rather than computed from the implementation under test.
	_, _, p := nfqwsScopedFixture(t)
	if p.Digest() != "004e6c7b34693a0a16a85715fc128630ff7666ea1637e97e1555db906d92e8e2" || strings.Join(p.Resources().Chains, ",") != "RZQ_ae529fd78981948312_4,RZQ_ae529fd78981948312_6" {
		t.Fatal("legacy compiler bytes or chain identity changed")
	}
	plan, spec := nfqwsScopedSelectedFixture(t)
	selected, err := CompileNFQWSScopedPlan(plan, spec)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Digest() != "b103c9c50d1851f7cdbc93078339bf4ded2aca2cd17032c0ecf36a1813f715f9" || strings.Join(selected.Resources().Chains, ",") != "RZQ_f71b6d7688d872a424_4" {
		t.Fatal("legacy exact-tuple compiler bytes or chain identity changed")
	}
}
