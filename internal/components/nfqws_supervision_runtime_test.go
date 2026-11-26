package components

import (
	"strings"
	"testing"
)

func TestNFQWSRuntimeStatRejectsDeadAndAmbiguousIdentity(t *testing.T) {
	fields := strings.Fields("R 1 12 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 999")
	for _, mode := range []string{"valid", "zombie", "dead", "unknown-state", "parent", "group", "birth", "short", "comm"} {
		t.Run(mode, func(t *testing.T) {
			copy := append([]string(nil), fields...)
			switch mode {
			case "zombie":
				copy[0] = "Z"
			case "dead":
				copy[0] = "X"
			case "unknown-state":
				copy[0] = "?"
			case "parent":
				copy[1] = "01"
			case "group":
				copy[2] = "0"
			case "birth":
				copy[19] = "0999"
			case "short":
				copy = copy[:19]
			}
			data := "12 (process (with) spaces) " + strings.Join(copy, " ")
			if mode == "comm" {
				data = "broken stat without close " + strings.Join(copy, " ")
			}
			birth, parent, group, err := nfqwsRuntimeStatIdentity([]byte(data))
			if mode == "valid" {
				if err != nil || birth != "999" || parent != 1 || group != 12 {
					t.Fatal("kernel birth/parent/group were not captured", birth, parent, group, err)
				}
			} else if err == nil {
				t.Fatal("dead/ambiguous process gained identity")
			}
		})
	}
}

func TestNFQWSRuntimeArgumentsIdentityPreservesBoundaries(t *testing.T) {
	program := "/opt/private/rzv-nfqws2"
	digest := NFQWSRuntimeArgumentsSHA256(program, []string{"a", "bc"})
	for _, other := range []string{NFQWSRuntimeArgumentsSHA256(program, []string{"ab", "c"}), NFQWSRuntimeArgumentsSHA256(program+"-other", []string{"a", "bc"}), NFQWSRuntimeArgumentsSHA256(program, []string{"a", "bc", ""})} {
		if digest == other || len(digest) != 64 {
			t.Fatal("distinct executable/argv boundaries had the same identity")
		}
	}
}
