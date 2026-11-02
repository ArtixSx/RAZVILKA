package startuptools

import (
	"slices"
	"testing"
)

func TestDomainBaselineObservedReadIsClosedToOriginalQueries(t *testing.T) {
	allowed := [][]string{
		{"-4", "-j", "rule", "show"},
		{"-4", "-j", "route", "show", "table", "all"},
		{"-j", "-details", "link", "show"},
		{"-4", "-j", "route", "get", "1.1.1.2", "from", "192.168.1.42", "iif", "br0"},
	}
	for _, args := range allowed {
		if !domainBaselineObservedRead(args) {
			t.Fatal("original baseline read refused", args)
		}
		if domainBaselineObservedRead(append(slices.Clone(args), "extra")) {
			t.Fatal("additional command operand admitted", args)
		}
	}
	for _, args := range [][]string{
		nil, {"-batch", "-"}, {"netns", "exec", "other", "-4", "-j", "rule", "show"},
		{"-6", "-j", "rule", "show"}, {"-4", "-j", "rule", "add"},
		{"-4", "-j", "route", "flush", "table", "all"}, {"-j", "-details", "link", "set"},
		{"-4", "-j", "route", "get", "127.0.0.1", "from", "192.168.1.42", "iif", "br0"},
		{"-4", "-j", "route", "get", "192.168.1.2", "from", "192.168.1.42", "iif", "br0"},
		{"-4", "-j", "route", "get", "::ffff:1.1.1.2", "from", "192.168.1.42", "iif", "br0"},
		{"-4", "-j", "route", "get", "1.1.1.2", "from", "8.8.8.8", "iif", "br0"},
		{"-4", "-j", "route", "get", "1.1.1.2", "from", "192.168.1.42/32", "iif", "br0"},
		{"-4", "-j", "route", "get", "1.1.1.2", "from", "192.168.1.42", "iif", "lo"},
		{"-4", "-j", "route", "get", "1.1.1.2", "from", "192.168.1.42", "iif", "br0;id"},
	} {
		if domainBaselineObservedRead(args) {
			t.Fatal("non-original or unsafe IP command entered readonly scope", args)
		}
	}
}
