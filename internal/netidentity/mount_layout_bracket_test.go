package netidentity

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Pure calculation comparison only: no proc reads, descriptors, provider,
// syscall or route readiness is measured by these two test helpers.
func mountLayoutBracketBefore(before, after []byte, root uint64, paths []string) bool {
	return mountLayoutOK(before, root, paths) && bytes.Equal(before, after) && mountLayoutOK(after, root, paths)
}

func mountLayoutBracketAfter(before, after []byte, root uint64, paths []string) bool {
	return mountLayoutOK(before, root, paths) && bytes.Equal(before, after)
}

func TestMountLayoutBracketExactContent(t *testing.T) {
	root := []byte("1 0 0:1 / /proc rw - proc proc rw\n")
	other := []byte("2 1 0:2 / /other rw - tmpfs tmpfs rw\n")
	paths := []string{"/proc/17/task/18/ns", "/proc/17/fdinfo"}
	valid := append(bytes.Clone(root), other...)
	shadow := append(bytes.Clone(root), bytes.Replace(other, []byte("/other"), []byte("/proc/17/fdinfo/4"), 1)...)
	for _, sample := range []struct {
		name          string
		before, after []byte
		want          bool
	}{
		{"valid_equal", valid, bytes.Clone(valid), true},
		{"empty_equal", nil, nil, false},
		{"invalid_equal", shadow, bytes.Clone(shadow), false},
		{"partial_equal", root[:len(root)-1], bytes.Clone(root[:len(root)-1]), false},
		{"changed_still_valid", root, valid, false},
		{"closing_shadow", valid, shadow, false},
		{"closing_missing", valid, nil, false},
		{"opening_invalid", shadow, valid, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			for _, check := range []func([]byte, []byte, uint64, []string) bool{mountLayoutBracketBefore, mountLayoutBracketAfter} {
				if got := check(sample.before, sample.after, 1, paths); got != sample.want {
					t.Fatalf("bracket = %t, want %t", got, sample.want)
				}
			}
		})
	}
}

// Exercise the existing observation seam: a good opening result must never
// authorize reuse when the fresh closing mount bracket, read or context fails.
func TestMountLayoutBracketClosingProviderRefusal(t *testing.T) {
	for _, fault := range []string{"none", "mount_changed", "read_failed", "canceled"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p := modelProvider(true, false)
			reads, uses := 0, 0
			p.read = func(context.Context) (observation, error) {
				reads++
				o := validObservation(true)
				if reads == 2 {
					switch fault {
					case "mount_changed":
						o.Checks.SameMountLayout = false
					case "read_failed":
						return observation{}, errors.New("closing read failed")
					case "canceled":
						cancel()
					}
				}
				return o, nil
			}
			err := p.WithCurrent(ctx, func(context.Context, Identity) error { uses++; return nil })
			if reads != 2 || uses != 1 {
				t.Fatalf("fresh bracket calls: reads=%d uses=%d", reads, uses)
			}
			if (err == nil) != (fault == "none") {
				t.Fatalf("closing fault %q: %v", fault, err)
			}
		})
	}
}

func BenchmarkMountLayoutBracketCalculation(b *testing.B) {
	root := "1 0 0:1 / /proc rw - proc proc rw\n"
	var mounts strings.Builder
	mounts.WriteString(root)
	for id := 2; id < 258; id++ {
		mounts.WriteString(strconv.Itoa(id) + " 1 0:2 / /other/" + strconv.Itoa(id) + " rw shared:3 - tmpfs tmpfs rw\n")
	}
	valid := []byte(mounts.String())
	invalid := append(bytes.Clone(valid), []byte("258 1 0:3 / /proc/17/fdinfo/4 ro - tmpfs tmpfs ro\n")...)
	changed := bytes.Replace(bytes.Clone(valid), []byte("shared:3"), []byte("shared:4"), 1)
	paths := []string{"/proc/17/task/18/ns", "/proc/17/fdinfo"}
	for _, sample := range []struct {
		name          string
		before, after []byte
		want          bool
	}{
		{"valid_equal", valid, bytes.Clone(valid), true},
		{"invalid_equal", invalid, bytes.Clone(invalid), false},
		{"changed_valid", valid, changed, false},
	} {
		b.Run(sample.name, func(b *testing.B) {
			for _, version := range []struct {
				name  string
				check func([]byte, []byte, uint64, []string) bool
			}{
				{"before_two_parses", mountLayoutBracketBefore},
				{"after_one_parse", mountLayoutBracketAfter},
			} {
				b.Run(version.name, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if version.check(sample.before, sample.after, 1, paths) != sample.want {
							b.Fatal("bracket admission changed")
						}
					}
				})
			}
		})
	}
}
