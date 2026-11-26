package startuptools

import "testing"

func TestMihomoSameBootObservedTableReadExactOnly(t *testing.T) {
	for _, prefix := range [][]string{nil, {"-N"}, {"-6"}, {"-N", "-6"}} {
		args := append(append([]string(nil), prefix...), "route", "show", "table", "207")
		if !mihomoSameBootObservedTableRead(args) || !mihomoLiveReadArguments(2, args) {
			t.Fatal("original fixed table read refused", args)
		}
		for _, tail := range [][]string{{"route", "show", "table", "208"}, {"route", "show", "table", "0207"}, {"route", "show", "table", "all"}, {"route", "show", "table", "main"}, {"route", "show", "table", "207", "default"}, {"route", "flush", "table", "207"}, {"route", "del", "table", "207"}, {"route", "list", "table", "207"}, {"route", "show"}} {
			if mihomoSameBootObservedTableRead(append(append([]string(nil), prefix...), tail...)) {
				t.Fatal("different selector/effect admitted", prefix, tail)
			}
		}
		for _, flag := range []string{"-4", "-j", "-N", "-6", "-netns", "-batch"} {
			if mihomoSameBootObservedTableRead(append(append([]string(nil), args...), flag)) {
				t.Fatal("extra option admitted", args, flag)
			}
		}
	}
}
