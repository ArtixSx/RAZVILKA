package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type nodeTransitRouteExit int

func (e nodeTransitRouteExit) Error() string { return "modeled route exit" }
func (e nodeTransitRouteExit) ExitCode() int { return int(e) }

func TestNodeTransitRouteIP44NegotiatesOnlyExactUnsupportedNumericOption(t *testing.T) {
	for _, mode := range []string{"old-ip", "modern", "wrong-exit", "generic-exit-text", "permission", "wrong-option", "extra-diagnostic", "malformed-success", "wrong-destination", "wrong-source", "wrong-interface", "wrong-table", "missing-table", "reserved-table", "unknown-table", "cancel-numeric", "cancel-plain", "guard-changed", "alias-before", "alias-during", "plain-fib-failure"} {
		t.Run(mode, func(t *testing.T) {
			l, base, authority := nodeTransitFixture(t)
			if err := l.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Fixed local rt_tables evidence, never the host's configuration.
			saved := rtTablesSources
			dir := t.TempDir()
			rtTablesSources = []string{dir}
			t.Cleanup(func() { rtTablesSources = saved })
			alias := func() {
				if err := os.WriteFile(filepath.Join(dir, "rt_tables"), []byte("204 main\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "alias-before" {
				alias()
			}
			numeric := []string{"-N", "-4", "route", "get", l.spec.Destination.String(), "from", l.spec.Source.String(), "oif", l.spec.Interface}
			plain := numeric[1:]
			var routeCalls [][]string
			fibFailure := errors.New("actual route unavailable")
			l.runtime.runner = runnerFunc(func(c context.Context, command string, args ...string) ([]byte, error) {
				if !reflect.DeepEqual(args, numeric) && !reflect.DeepEqual(args, plain) {
					return base.Run(c, command, args...)
				}
				if command != "ip" {
					t.Fatal("route negotiation changed command owner")
				}
				routeCalls = append(routeCalls, append([]string(nil), args...))
				if reflect.DeepEqual(args, numeric) {
					data := []byte("Option \"-N\" is unknown, try \"ip -help\".\n")
					switch mode {
					case "modern":
						return []byte(base.route), nil
					case "wrong-exit":
						return data, nodeTransitRouteExit(2)
					case "generic-exit-text":
						return data, errors.New("exit status 255")
					case "permission":
						return []byte("Operation not permitted\n"), nodeTransitRouteExit(255)
					case "wrong-option":
						return []byte("Option \"-j\" is unknown, try \"ip -help\".\n"), nodeTransitRouteExit(255)
					case "extra-diagnostic":
						return append(data, []byte("unknown extra failure\n")...), nodeTransitRouteExit(255)
					case "malformed-success":
						return []byte("not a route\n"), nil
					case "cancel-numeric":
						cancel()
					case "guard-changed":
						authority.guardErr = ErrReviewChanged
					}
					return data, nodeTransitRouteExit(255)
				}
				output := base.route
				switch mode {
				case "wrong-destination":
					output = strings.Replace(output, l.spec.Destination.String(), "8.8.8.8", 1)
				case "wrong-source":
					output = strings.Replace(output, l.spec.Source.String(), "172.31.22.2", 1)
				case "wrong-interface":
					output = strings.Replace(output, l.spec.Interface, "lo", 1)
				case "wrong-table":
					output = strings.Replace(output, "table 204", "table 203", 1)
				case "missing-table":
					output = strings.Replace(output, "table 204", "", 1)
				case "reserved-table":
					output = strings.Replace(output, "table 204", "table main", 1)
				case "unknown-table":
					output = strings.Replace(output, "table 204", "table own", 1)
				case "cancel-plain":
					cancel()
				case "alias-during":
					alias()
				case "plain-fib-failure":
					return []byte("RTNETLINK answers: Network is unreachable\n"), fibFailure
				}
				return []byte(output), nil
			})
			err := l.VerifyRoute(ctx)
			wantPass := mode == "old-ip" || mode == "modern"
			if (err == nil) != wantPass {
				t.Fatal("format negotiation accepted uncertain route or rejected exact route", mode, err)
			}
			wantCalls := 2
			switch mode {
			case "modern", "wrong-exit", "generic-exit-text", "permission", "wrong-option", "extra-diagnostic", "malformed-success", "cancel-numeric", "guard-changed", "alias-before":
				wantCalls = 1
			}
			if len(routeCalls) != wantCalls || !reflect.DeepEqual(routeCalls[0], numeric) || wantCalls == 2 && !reflect.DeepEqual(routeCalls[1], plain) {
				t.Fatal("negotiation changed exact tuple, repeated a FIB failure or retried an unrelated error", routeCalls)
			}
			if mode == "plain-fib-failure" && !errors.Is(err, fibFailure) || mode == "guard-changed" && !errors.Is(err, ErrReviewChanged) || strings.HasPrefix(mode, "cancel-") && !errors.Is(err, context.Canceled) {
				t.Fatal("negotiation lost refusal classification", err)
			}
			if base.adds != 1 || base.deletes != 0 || isNodeTransitBeforeEffects(err) {
				t.Fatal("route readback acquired mutation or unused authority", err)
			}
		})
	}
}
