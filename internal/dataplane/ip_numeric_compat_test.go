package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The RPDB of the owner's NC1812 (firmware 5.01.C.6.0-1) as printed by
// Entware ip-full 4.4, which refuses -N.
const keeneticRuleShow = "0:\tfrom all lookup local \n100:\tfrom all fwmark 0xffffaaa lookup 4096 \n101:\tfrom all fwmark 0xffffaaa blackhole\n102:\tfrom all fwmark 0xffffaab lookup 4097 \n1154:\tfrom 100.64.181.129 lookup 16386 \n32766:\tfrom all lookup main \n32767:\tfrom all lookup default \n"

type ip44Runner struct{ calls [][]string }

func (r *ip44Runner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	for _, arg := range args {
		if arg == "-N" {
			return []byte("Option \"-N\" is unknown, try \"ip -help\".\n"), errors.New("exit status 255")
		}
	}
	return []byte(keeneticRuleShow), nil
}

func TestPlainNumericReadbackOnlyRewritesIPReadbacks(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"-N", "rule", "show"}, []string{"rule", "show"}},
		{[]string{"-4", "-N", "rule", "show"}, []string{"-4", "rule", "show"}},
		{[]string{"-6", "-N", "route", "show", "table", "100"}, []string{"-6", "route", "show", "table", "100"}},
		{[]string{"-t", "mangle", "-N", "RZ_CHAIN"}, nil},
		{[]string{"-N", "rule", "add", "pref", "100"}, nil},
		{[]string{"-N", "-N", "rule", "show"}, nil},
		{[]string{"rule", "show"}, nil},
	} {
		got, ok := plainNumericReadback(tc.args)
		if ok != (tc.want != nil) || ok && !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%v -> %v %v, want %v", tc.args, got, ok, tc.want)
		}
	}
}

func TestNumericReservedTablesTranslatesOnlyReservedNames(t *testing.T) {
	got := string(numericReservedTables([]byte(keeneticRuleShow + "200:\tfrom all lookup vpn \nlocal 10.0.0.1 dev lo table local proto kernel\n")))
	for _, want := range []string{"from all lookup 255 ", "from all lookup 254 ", "from all lookup 253 ", "lookup 4096 ", "lookup 16386 ", "lookup vpn ", "table 255 proto"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "lookup main") || strings.Contains(got, "lookup local") {
		t.Fatalf("reserved names remain:\n%s", got)
	}
}

func TestRunIPNumericFallsBackOnlyForRefusedNumericReadback(t *testing.T) {
	runner := &ip44Runner{}
	out, err := runIPNumeric(context.Background(), runner, "ip", "-4", "-N", "rule", "show")
	if err != nil || !strings.Contains(string(out), "lookup 254") || len(runner.calls) != 2 || !reflect.DeepEqual(runner.calls[1], []string{"-4", "rule", "show"}) {
		t.Fatalf("fallback: %q %v %v", out, err, runner.calls)
	}
	failing := runnerFunc(func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("timeout") })
	if _, err := runIPNumeric(context.Background(), failing, "ip", "-N", "rule", "show"); err == nil || err.Error() != "timeout" {
		t.Fatal("a failed fallback hid the original error", err)
	}
	// Policy readers read the router's RPDB through the numeric wrapper.
	lines, err := readPolicyRules(context.Background(), numericPolicyReadRunner{base: &ip44Runner{}}, "ip", 4)
	if err != nil || len(lines) != 7 || !strings.Contains(lines[0], "lookup 255") {
		t.Fatalf("policy rules on ip 4.4: %v %v", lines, err)
	}
}

type runnerFunc func(context.Context, string, ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}
