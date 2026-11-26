package netidentity

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testBoot = "01234567-89ab-cdef-0123-456789abcdef"

func validObservation(net bool) observation {
	names := []string{"mnt"}
	inode := uint64(0)
	if net {
		names = []string{"net", "mnt"}
		inode = 4026531992
	}
	return observation{KernelRelease: "4.9-ndm-5", Machine: "aarch64", BootID: testBoot,
		Names: names, PIDNames: append([]string(nil), names...), Inode: inode,
		NetPresent: net, MntPresent: true, DirectoryComplete: true, ObservationValid: true,
		Checks: checks{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true}}
}
func modelProvider(net bool, profile bool) *Provider {
	p := NewProcProvider()
	p.buildPair = nil // This fixture explicitly models the individual metadata reads.
	p.read = func(context.Context) (observation, error) { return validObservation(net), nil }
	p.build = func(context.Context) (buildTuple, error) { return nc1812Profile().Build, nil }
	if profile {
		v := nc1812Profile()
		p.profile = &v
	}
	return p
}
func TestIdentityCodecClosedVariants(t *testing.T) {
	if nc1812Profile().hash() != "f77d10cde0399faf1ab9ab6060bc52aa54e61e25c3d4c2381f4f712e78144733" {
		t.Fatal("reviewed catalog changed without a new contract")
	}
	proc := Identity{Version: 1, Kind: ProcNetInode, BootID: testBoot, Inode: 4026531992}
	single := Identity{Version: 1, Kind: ReviewedSingleInitNet, BootID: testBoot, PlatformReviewSHA256: nc1812Profile().hash()}
	if proc == single {
		t.Fatal("variants aliased")
	}
	rebooted := proc
	rebooted.BootID = "11234567-89ab-cdef-0123-456789abcdef"
	if rebooted == proc {
		t.Fatal("boot epochs aliased")
	}
	_ = map[Identity]bool{proc: true, single: true} // The public type is comparable.
	for _, v := range []Identity{proc, single} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Identity
		if json.Unmarshal(raw, &decoded) != nil || decoded != v {
			t.Fatal("canonical roundtrip", v)
		}
		bad := [][]byte{
			append(append([]byte(nil), raw...), '\n'), append(append([]byte(nil), raw...), raw...),
			bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
			bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1),
			bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"extra":0`), 1),
			bytes.Replace(raw, []byte(`"version":1,`), nil, 1),
			[]byte(`"net:[4026531992]"`), []byte(`{"boot_id":"` + testBoot + `"}`), []byte(strings.Repeat("x", 1025)),
		}
		for _, data := range bad {
			if got, err := Decode(data); err == nil || got != (Identity{}) {
				t.Fatalf("accepted malformed/old wire %q", data)
			}
		}
	}
	for _, mutate := range []func(*Identity){
		func(v *Identity) { v.Inode = 0 }, func(v *Identity) { v.PlatformReviewSHA256 = single.PlatformReviewSHA256 },
		func(v *Identity) { v.Kind = "single" }, func(v *Identity) { v.BootID = "00000000-0000-0000-0000-000000000000" },
		func(v *Identity) { v.BootID = strings.ToUpper(testBoot) },
	} {
		v := proc
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("invalid proc variant", v)
		}
	}
	for _, mutate := range []func(*Identity){func(v *Identity) { v.Inode = 1 }, func(v *Identity) { v.PlatformReviewSHA256 = strings.Repeat("a", 64) }, func(v *Identity) {
		v.PlatformReviewSHA256 = "7909df2d50793c6847474b778feb906386f4b66244d6e278d00273892f889c75"
	}} {
		v := single
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("mixed/unknown profile", v)
		}
	}
}
func TestObservationRequiresCompleteAnchoredProcessAndThread(t *testing.T) {
	profile := nc1812Profile()
	if v, err := identityFromObservation(validObservation(false), &profile); err != nil || v.Kind != ReviewedSingleInitNet {
		t.Fatal(v, err)
	}
	if v, err := identityFromObservation(validObservation(true), nil); err != nil || v.Kind != ProcNetInode {
		t.Fatal(v, err)
	}
	if _, err := identityFromObservation(validObservation(false), nil); err == nil {
		t.Fatal("ENOENT/boot-only fallback")
	}
	for _, mutate := range []func(*observation){
		func(o *observation) { o.DirectoryComplete = false }, func(o *observation) { o.ObservationValid = false },
		func(o *observation) { o.PIDNames = []string{"net", "mnt"} }, func(o *observation) { o.Names = []string{"mnt", "mnt"}; o.PIDNames = o.Names },
		func(o *observation) { o.KernelRelease = "4.9-custom" }, func(o *observation) { o.Machine = "x86_64" },
		func(o *observation) { o.BootID = "" }, func(o *observation) { o.MntPresent = false },
	} {
		o := validObservation(false)
		mutate(&o)
		if _, err := identityFromObservation(o, &profile); err == nil {
			t.Fatal("accepted faulty complete observation", o)
		}
	}
	// Every individual mount/task/start/FD/reopen/position fault must revoke the
	// whole observation, even if an earlier producer left Valid=true.
	for i := 0; i < reflect.TypeOf(checks{}).NumField(); i++ {
		o := validObservation(false)
		reflect.ValueOf(&o.Checks).Elem().Field(i).SetBool(false)
		if _, err := identityFromObservation(o, &profile); err == nil {
			t.Fatal("lost bracket", i)
		}
	}
}
func dirent(name string, cookie uint64, inode uint64, kind byte) []byte {
	n := (19 + len(name) + 1 + 7) &^ 7
	if n < 24 {
		n = 24
	}
	raw := make([]byte, n)
	binary.LittleEndian.PutUint64(raw, inode)
	binary.LittleEndian.PutUint64(raw[8:], cookie)
	binary.LittleEndian.PutUint16(raw[16:], uint16(n))
	raw[18] = kind
	copy(raw[19:], name)
	return raw
}
func readDirModel(ctx context.Context, chunks [][]byte, final error) ([]string, bool, bool, bool) {
	i := 0
	return readNamespaceDirectory(ctx, func(buf []byte) (int, error) {
		if i == len(chunks) {
			return 0, final
		}
		data := chunks[i]
		i++
		return copy(buf, data), nil
	})
}
func TestRawDirentsCannotHideNetOrManufactureEOF(t *testing.T) {
	good := append(dirent(".", 1, 1, 4), dirent("..", 2, 1, 4)...)
	good = append(good, dirent("net", 3, 0, 0)...)
	good = append(good, dirent("mnt", 4, 0, 0)...)
	names, unknown, complete, valid := readDirModel(context.Background(), [][]byte{good}, nil)
	if !reflect.DeepEqual(names, []string{"net", "mnt"}) || !unknown || !complete || !valid {
		t.Fatal(names, unknown, complete, valid)
	}
	o := validObservation(true)
	o.Inode = 0
	o.DTUnknownObserved = true
	profile := nc1812Profile()
	if _, err := identityFromObservation(o, &profile); err == nil {
		t.Fatal("net with unknown inode became singleton")
	}
	for _, bad := range [][]byte{
		dirent("mnt", 3, 1, 10), good[:len(good)-1], append(good, dirent("mnt", 5, 1, 10)...), dirent(".", 0, 1, 4),
		append(append(dirent(".", 1, 1, 4), dirent("..", 2, 1, 4)...), dirent("../net", 3, 1, 10)...),
	} {
		_, _, complete, valid := readDirModel(context.Background(), [][]byte{bad}, nil)
		if complete && valid {
			t.Fatal("accepted malformed/position-skipped dirent")
		}
	}
	if _, _, complete, _ := readDirModel(context.Background(), [][]byte{good}, io.ErrUnexpectedEOF); complete {
		t.Fatal("partial read acquired EOF")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, complete, _ := readDirModel(ctx, [][]byte{good}, nil); complete {
		t.Fatal("cancelled read")
	}
	oversize := append(dirent(".", 1, 1, 4), dirent("..", 2, 1, 4)...)
	for i := 0; i < maxNames+1; i++ {
		oversize = append(oversize, dirent(strings.Repeat("x", i+1), uint64(i+3), 1, 10)...)
	}
	if _, _, complete, valid := readDirModel(context.Background(), [][]byte{oversize}, nil); complete && valid {
		t.Fatal("directory cap bypass")
	}
}
func buildText(v buildTuple) []byte {
	var b strings.Builder
	for _, field := range [][2]string{{"manufacturer", v.Manufacturer}, {"model", v.Model}, {"device", v.Device}, {"release", v.Release}, {"sandbox", v.Sandbox}, {"title", v.Title}, {"arch", v.Arch}} {
		b.WriteString(versionLine(17, field[0], field[1]))
	}
	b.WriteString(versionLine(17, "ndm", "") + versionLine(21, "exact", v.NDMExact))
	b.WriteString(versionLine(17, "ndw4", "") + versionLine(21, "version", v.NDW4Version))
	return []byte(b.String())
}
func versionLine(column int, key, value string) string {
	if value != "" {
		value = " " + value
	}
	return strings.Repeat(" ", column-len(key)) + key + ":" + value + "\n"
}
func TestBuildUniqueExactTupleAndFreshProviderDrift(t *testing.T) {
	profile := nc1812Profile()
	raw := buildText(profile.Build)
	if v, err := parseBuild(raw); err != nil || v != profile.Build {
		t.Fatal(v, err)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), []byte(versionLine(17, "release", profile.Build.Release))...), bytes.Replace(raw, []byte(versionLine(17, "arch", profile.Build.Arch)), nil, 1), append(append([]byte(nil), raw...), 0), []byte(strings.Repeat("x", 8193))} {
		if _, err := parseBuild(bad); err == nil {
			t.Fatal("ambiguous/unbounded build")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, fault := range []string{"release", "ndm", "manufacturer", "boot", "kernel", "error"} {
		p := modelProvider(false, true)
		reads, builds := 0, 0
		p.read = func(context.Context) (observation, error) {
			reads++
			o := validObservation(false)
			if reads == 2 {
				if fault == "boot" {
					o.BootID = "11234567-89ab-cdef-0123-456789abcdef"
				}
				if fault == "kernel" {
					o.KernelRelease = "changed"
				}
			}
			return o, nil
		}
		p.build = func(context.Context) (buildTuple, error) {
			builds++
			v := profile.Build
			if builds == 2 {
				switch fault {
				case "release":
					v.Release = "new"
				case "ndm":
					v.NDMExact = "new"
				case "manufacturer":
					v.Manufacturer = "unknown"
				case "error":
					return buildTuple{}, errors.New("read failed")
				}
			}
			return v, nil
		}
		if v, err := p.Observe(ctx); err == nil || v != (Identity{}) {
			t.Fatal("build/boot drift accepted", fault, v, err)
		}
	}
	p := modelProvider(false, true)
	if v, err := p.Observe(ctx); err != nil || v.Kind != ReviewedSingleInitNet {
		t.Fatal(v, err)
	}
}
func TestProviderOriginalBudgetClosingAndCancelNil(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), "operation", "original"), time.Second)
	defer cancel()
	p := modelProvider(true, false)
	if err := p.WithCurrent(ctx, func(c context.Context, v Identity) error {
		outer, _ := ctx.Deadline()
		inner, _ := c.Deadline()
		if inner.After(outer) || c.Value("operation") != "original" || v.Kind != ProcNetInode {
			t.Fatal("replaced operation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reads := 0
	p.read = func(context.Context) (observation, error) {
		reads++
		o := validObservation(true)
		if reads == 2 {
			o.Inode++
		}
		return o, nil
	}
	if err := p.WithCurrent(ctx, func(context.Context, Identity) error { return nil }); err == nil {
		t.Fatal("closing drift")
	}
	p = modelProvider(true, false)
	if err := p.WithCurrent(ctx, func(context.Context, Identity) error { cancel(); return nil }); err == nil {
		t.Fatal("cancelled nil callback")
	}
	if _, err := p.Observe(context.Background()); err == nil {
		t.Fatal("unbounded caller")
	}
	if _, err := new(Provider).Observe(ctx); err == nil {
		t.Fatal("zero provider")
	}
}
func TestMountLayoutRejectsShadowAndAmbiguousRoot(t *testing.T) {
	root := []byte("1 0 0:1 / /proc rw - proc proc rw\n")
	paths := []string{"/proc/17/task/18/ns", "/proc/17/fdinfo", "/proc/sys/kernel/random/boot_id"}
	if !mountLayoutOK(root, 1, paths) {
		t.Fatal("valid root")
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), root...), []byte("2 1 0:2 / /proc/17/task/18/ns ro - tmpfs tmpfs ro\n")...),
		append(append([]byte(nil), root...), root...), bytes.Replace(root, []byte("- proc"), []byte("- tmpfs"), 1), root[:len(root)-1],
		append(append([]byte(nil), root...), []byte("2 1 0:2 / /proc/17/fdinfo/1 ro - tmpfs tmpfs ro\n")...),
	} {
		if mountLayoutOK(bad, 1, paths) {
			t.Fatal("shadow/partial/ambiguous mount")
		}
	}
}
