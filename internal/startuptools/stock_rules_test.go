package startuptools

import (
	"errors"
	"strings"
	"testing"
)

func TestStockRuleAdapterNormalizesOnlyVerifiedBuiltinsInTheirFields(t *testing.T) {
	raw := "0:\tfrom all lookup local \n" +
		"32766:\tfrom all lookup main \n" +
		"32767:\tfrom all lookup default \n" +
		"100:\tfrom 192.168.77.0/24 to 93.184.216.34 tos 0x10 fwmark 0x20000000/0x28000000 iif local oif main lookup 201 suppress_prefixlength 0 suppress_ifgroup default realms unknown/7 \n" +
		"53:\tfrom all goto 73\n73:\tfrom all nop\n"
	want := "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n" +
		"100: from 192.168.77.0/24 to 93.184.216.34 tos 0x10 fwmark 0x20000000/0x28000000 iif local oif main lookup 201 suppress_prefixlength 0 suppress_ifgroup 0 realms 0/7\n" +
		"53: from all goto 73\n73: from all nop\n"
	got, err := stockNumericRules([]byte(raw))
	if err != nil || string(got) != want {
		t.Fatal("builtin/field normalization lost an actual row or changed another selector", string(got), err)
	}
}

func TestStockRuleAdapterRefusesCustomNamesUnknownFieldsAndPartialEvidence(t *testing.T) {
	for _, suffix := range []string{
		"100: from all lookup rz-wg\n", "100: from all lookup 0\n", "100: from all lookup 0201\n",
		"100: from all lookup 4294967296\n", "100: from all tos af11 lookup 201\n",
		"100: from all realms custom/7 lookup 201\n", "100: from all suppress_ifgroup custom lookup 201\n",
		"100: from all lookup 201 proto custom\n", "100: from all iif br-lan [detached] lookup 201\n",
		"100: from all lookup\n", "100: from all lookup 201", "100: from all lookup 201\x00\n",
		"100: from all lookup 201\r\n", "bad: from all lookup 201\n",
	} {
		got, err := stockNumericRules([]byte("0: from all lookup local\n" + suffix))
		if !errors.Is(err, ErrUnknown) || len(got) != 0 {
			t.Fatal("partial/guessed namespace evidence escaped refusal", string(got), err)
		}
	}
	if got, err := stockNumericRules([]byte(strings.Repeat("0: from all lookup local\n", 8193))); err == nil || len(got) != 0 {
		t.Fatal("row cap lost")
	}
	if got, err := stockNumericRules(nil); err != nil || len(got) != 0 {
		t.Fatal("actual empty EOF rejected", err)
	}
}
