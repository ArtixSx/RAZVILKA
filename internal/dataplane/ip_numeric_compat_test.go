package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The RPDB of the owner's NC1812 (firmware 5.01.C.6.0-1) as printed by
// Entware ip-full 4.4, which refuses -N.
const keeneticRuleShow = "0:\tfrom all lookup local \n100:\tfrom all fwmark 0xffffaaa lookup 4096 \n101:\tfrom all fwmark 0xffffaaa blackhole\n102:\tfrom all fwmark 0xffffaab lookup 4097 \n1154:\tfrom 100.64.181.129 lookup 16386 \n32766:\tfrom all lookup main \n32767:\tfrom all lookup default \n"

const keeneticRuleShow6 = "0:\tfrom all lookup local \n100:\tfrom all fwmark 0xffffaac lookup 4096 \n1172:\tfrom all oif nwg0 lookup 16395 \n1174:\tfrom fd00:10:58::62 lookup 16395 \n32766:\tfrom all lookup main \n"

type ip44Runner struct{ calls [][]string }

func (r *ip44Runner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	for _, arg := range args {
		if arg == "-N" {
			return []byte("Option \"-N\" is unknown, try \"ip -help\".\n"), errors.New("exit status 255")
		}
	}
	if slices.Contains(args, "-6") {
		return []byte(keeneticRuleShow6), nil
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
		{[]string{"-N", "-6", "rule", "show"}, []string{"-6", "rule", "show"}},
		{[]string{"-N", "-j", "route", "show", "table", "201"}, nil},
		{[]string{"-N", "rule", "show", "-N"}, nil},
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

// aliasReservedTableName gives table the reserved name main, as a crafted
// rt_tables would. A plain readback then proves nothing about that table.
func aliasReservedTableName(t *testing.T, table int) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rt_tables"), []byte(fmt.Sprintf("# local\n255 local\n0xfe main\n%d main\n", table)), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := rtTablesSources
	rtTablesSources = []string{dir}
	t.Cleanup(func() { rtTablesSources = saved })
}

func TestReservedTableNamesUnaliasedReadsEveryRTTablesSource(t *testing.T) {
	saved := rtTablesSources
	defer func() { rtTablesSources = saved }()
	dir := t.TempDir()
	rtTablesSources = []string{filepath.Join(dir, "missing"), dir}
	if !reservedTableNamesUnaliased() {
		t.Fatal("absent rt_tables refused")
	}
	if err := os.WriteFile(filepath.Join(dir, "rt_tables"), []byte("255\tlocal\n0xfe main\n253 default\n4096 keenetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !reservedTableNamesUnaliased() {
		t.Fatal("reserved numbers refused")
	}
	if err := os.MkdirAll(filepath.Join(dir, "rt_tables.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rt_tables.d", "vpn.conf"), []byte("203 default\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reservedTableNamesUnaliased() {
		t.Fatal("aliased reserved name accepted")
	}
}

// A sing-box default cleanup on the owner's router: ip 4.4 refuses -N and the
// RPDB holds Keenetic firmware rules. Only an rt_tables alias refuses it.
func TestPolicyDefaultDependencyOnKeeneticIP44(t *testing.T) {
	state := testEarlyPolicy()
	for _, family := range []int{4, 6} {
		if err := AssertPolicyDefaultUnreferenced(context.Background(), &ip44Runner{}, "ip", state, family); err != nil {
			t.Fatal("Keenetic RPDB retained the sing-box default", family, err)
		}
	}
	aliasReservedTableName(t, state.Table)
	if err := AssertPolicyDefaultUnreferenced(context.Background(), &ip44Runner{}, "ip", state, 4); !errors.Is(err, ErrPolicyDefaultReferenced) {
		t.Fatal("aliased reserved name proved the default unreferenced", err)
	}
}

type runnerFunc func(context.Context, string, ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}
