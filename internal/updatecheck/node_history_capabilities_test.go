package updatecheck

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

func TestNodeHistoryCandidateCapabilitiesUseTypedRetainedRequirement(t *testing.T) {
	for _, history := range []struct {
		name     string
		material []byte
		required int
	}{
		{"legacy", retainedNodeFixture(t, false), 1},
		{"raw-xray", retainedNodeFixture(t, true), 2},
		{"unchecked-xhttp", retainedXHTTPNodeFixture(t), 3},
	} {
		t.Run(history.name, func(t *testing.T) {
			ctx := context.Background()
			configRoot, stateRoot := t.TempDir(), t.TempDir()
			retainedFile(t, stateRoot, "retained/nodes.private.json", history.material)
			required, err := RequiredRetainedNodeHistoryReadVersion(ctx, configRoot, stateRoot, validatedNodeHistoryRead)
			if err != nil || required != history.required {
				t.Fatal("typed retained fixture", required, err)
			}
			for _, version := range []int{1, 2, 3, 4} {
				calls := 0
				probe := func(c context.Context, binary, flag string) (string, error) {
					calls++
					if binary != "fixed-reviewed-controller" || c != ctx {
						t.Fatal("capability probe lost binding")
					}
					switch flag {
					case "-node-history-read-version":
						return strconv.Itoa(version) + "\n", nil
					case "-self-update-schema", "-component-update-schema":
						return "2\n", nil
					case "-native-enrollment-schema", "-subscription-schema":
						return "1\n", nil
					default:
						t.Fatal("unexpected probe flag", flag)
						return "", errors.New("unexpected probe")
					}
				}
				err := checkFileCapabilitiesForNodeHistory(ctx, "fixed-reviewed-controller", required, probe)
				allowed := version >= max(2, required) && version <= 3
				if allowed != (err == nil) || allowed && calls != 5 {
					t.Fatal("candidate2/3 retained admission or independent schema2 failed", version, err)
				}
			}
		})
	}
}

func TestNodeHistoryCandidateUnknownRequiredAndMalformedProbesFence(t *testing.T) {
	for _, required := range []int{0, 4} {
		calls := 0
		err := checkFileCapabilitiesForNodeHistory(context.Background(), "fixed-reviewed-controller", required, func(context.Context, string, string) (string, error) { calls++; return "3\n", nil })
		if err == nil || calls != 0 {
			t.Fatal("unknown typed required version launched probe")
		}
	}
	for _, output := range []string{"", "3", "03\n", "+3\n", " 3\n", "3\r\n", "3\nextra", "0\n", "4\n", "unknown\n"} {
		probe := func(ctx context.Context, binary, flag string) (string, error) {
			if flag == "-node-history-read-version" {
				return output, nil
			}
			return "2\n", nil
		}
		if err := checkFileCapabilitiesForNodeHistory(context.Background(), "fixed-reviewed-controller", 3, probe); err == nil {
			t.Fatal("malformed/future capability admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := checkFileCapabilitiesForNodeHistory(ctx, "fixed-reviewed-controller", 3, func(context.Context, string, string) (string, error) { calls++; return "3\n", nil })
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("cancellation launched capability probes")
	}
}
