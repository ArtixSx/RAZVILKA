package dataplane

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestRecordedDefaultNumericAliasesRetainCanonicalReceiptSelector(t *testing.T) {
	state := PolicyState{Interface: "rz-xray", Table: 204}
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"boot", "3"} {
			for _, scope := range []string{"link", "253"} {
				metric, preference := "0", ""
				if family == 6 {
					metric, preference = "1024", " pref medium"
				}
				line := "default dev rz-xray proto " + protocol + " scope " + scope + " metric " + metric + preference
				runner := numericPolicyReadRunner{base: networkCleanupRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
					if !strings.Contains(strings.Join(args, " "), "route show table 204") || !strings.Contains(strings.Join(args, " "), "-N") {
						t.Fatal("numeric default read attempted mutation or lost table", args)
					}
					return []byte(line), nil
				})}
				got, err := recordedDefaultRoute(context.Background(), runner, "ip", state, family)
				want := []string{"route", "del", "default", "dev", "rz-xray", "table", "204", "proto", "boot", "scope", "link", "metric", metric}
				if family == 6 {
					want = append([]string{"-6"}, want...)
				}
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("numeric alias changed canonical receipt", family, line, got, err)
				}
			}
		}
	}
}

func TestRecordedDefaultNumericAliasesRefuseForeignOrAmbiguousAttributes(t *testing.T) {
	state := PolicyState{Interface: "rz-xray", Table: 204}
	for _, family := range []int{4, 6} {
		good := "default dev rz-xray proto 3 scope 253 metric 0"
		for _, line := range []string{
			strings.Replace(good, "proto 3", "proto 03", 1),
			strings.Replace(good, "proto 3", "proto 4", 1),
			strings.Replace(good, "proto 3", "proto BOOT", 1),
			strings.Replace(good, "scope 253", "scope 0253", 1),
			strings.Replace(good, "scope 253", "scope 0", 1),
			strings.Replace(good, "scope 253", "scope global", 1),
			good + " proto boot", good + " scope link", good + " via 192.0.2.1", good + " unknown 0",
			good + "\n" + good,
		} {
			runner := networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) { return []byte(line), nil })
			if _, err := recordedDefaultRoute(context.Background(), runner, "ip", state, family); err == nil {
				t.Fatal("foreign/ambiguous default gained cleanup selector", family, line)
			}
		}
	}
}
