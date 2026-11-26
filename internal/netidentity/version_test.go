package netidentity

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// Synthetic ignored metadata reuses reviewed strings. No captured response,
// component inventory, device attributes or unreviewed version values.
func structuredVersionModel() []byte {
	v := nc1812Profile().Build
	root := string(buildText(v))
	metadata := versionLine(17, "bsp", "") + versionLine(21, "exact", v.Release) +
		versionLine(17, "ndw", "") + versionLine(21, "features", v.Arch) +
		strings.Repeat(" ", 23) + v.Title + "\n" +
		versionLine(21, "components", v.Arch) + strings.Repeat(" ", 23) + v.Title + "\n" +
		versionLine(17, "ndw3", "") + versionLine(21, "version", v.Release) +
		versionLine(17, "vendor", v.Manufacturer)
	return []byte("\n" + metadata + root + "\n")
}

func TestStructuredVersionScopesAndLiteralEnvelope(t *testing.T) {
	body := structuredVersionModel()
	crlf := bytes.ReplaceAll(body, []byte("\n"), []byte("\r\n"))
	for _, raw := range [][]byte{body, append(append([]byte("\x1b[K"), body...), []byte("\x1b[K")...), crlf, append(append([]byte("\x1b[K"), crlf...), []byte("\x1b[K")...)} {
		v, err := parseBuild(raw)
		if err != nil || v != nc1812Profile().Build {
			t.Fatal("unique scoped model", err)
		}
	}
	// ndw3.version differs from ndw4.version; only the latter is in the tuple.
	if bytes.Equal([]byte(nc1812Profile().Build.Release), []byte(nc1812Profile().Build.NDW4Version)) {
		t.Fatal("model did not distinguish scopes")
	}
}

func TestStructuredVersionRejectsAmbiguousScopesControlsAndBounds(t *testing.T) {
	v := nc1812Profile().Build
	body := buildText(v)
	ndm := versionLine(17, "ndm", "")
	exact := versionLine(21, "exact", v.NDMExact)
	ndw4 := versionLine(17, "ndw4", "")
	version := versionLine(21, "version", v.NDW4Version)
	model := structuredVersionModel()
	feature := versionLine(21, "features", v.Arch)
	cases := map[string][]byte{
		"duplicate-root":              append(bytes.Clone(body), []byte(versionLine(17, "release", v.Release))...),
		"duplicate-child":             bytes.Replace(body, []byte(exact), []byte(exact+exact), 1),
		"duplicate-version":           append(bytes.Clone(body), []byte(version)...),
		"duplicate-header":            bytes.Replace(body, []byte(ndm), []byte(ndm+exact+ndm), 1),
		"ndm-scalar":                  bytes.Replace(body, []byte(ndm), []byte(versionLine(17, "ndm", v.NDMExact)), 1),
		"empty-root-metadata":         append([]byte(versionLine(17, "vendor", "")), body...),
		"orphan-child":                append([]byte(version), body...),
		"wrong-root-column":           bytes.Replace(body, []byte(versionLine(17, "release", v.Release)), []byte(versionLine(21, "release", v.Release)), 1),
		"wrong-child-column":          bytes.Replace(body, []byte(exact), []byte(versionLine(17, "exact", v.NDMExact)), 1),
		"leading-indent-is-not-depth": bytes.Replace(body, []byte(exact), []byte(" "+exact), 1),
		"third-level":                 bytes.Replace(body, []byte(exact), []byte(versionLine(25, "exact", v.NDMExact)), 1),
		"bsp-cannot-issue-ndm":        bytes.Replace(body, []byte(ndm), []byte(versionLine(17, "bsp", "")), 1),
		"ndw3-cannot-issue-ndw4":      bytes.Replace(body, []byte(ndw4), []byte(versionLine(17, "ndw3", "")), 1),
		"flat-dotted-alias":           bytes.Replace(body, []byte(ndm+exact), []byte(versionLine(17, "ndm.exact", v.NDMExact)), 1),
		"foreign-nested-root-field":   bytes.Replace(body, []byte(exact), []byte(versionLine(21, "manufacturer", v.Manufacturer)), 1),
		"empty-required-scalar":       bytes.Replace(body, []byte(exact), []byte(versionLine(21, "exact", "")), 1),
		"required-continuation":       bytes.Replace(body, []byte(exact), []byte(exact+strings.Repeat(" ", 23)+v.NDMExact+"\n"), 1),
		"blank-before-continuation":   bytes.Replace(model, []byte(feature), []byte(feature+"\n"), 1),
		"wrong-continuation-column":   bytes.Replace(model, []byte(strings.Repeat(" ", 23)+v.Title), []byte(strings.Repeat(" ", 24)+v.Title), 1),
		"unpaired-prefix":             append([]byte("\x1b[K"), body...),
		"unpaired-suffix":             append(bytes.Clone(body), []byte("\x1b[K")...),
		"embedded-erase-line":         bytes.Replace(body, []byte(v.Model), []byte(v.Model+"\x1b[K"), 1),
		"unknown-envelope":            append(append([]byte("\x1b[0m"), body...), []byte("\x1b[0m")...),
		"outside-envelope-padding":    append(append([]byte(" \x1b[K"), body...), []byte("\x1b[K")...),
		"nul":                         append(bytes.Clone(body), 0),
		"non-ascii":                   bytes.Replace(body, []byte(v.Arch), []byte{128}, 1),
		"tab-indentation":             append([]byte{'\t'}, body...),
		"bare-cr":                     bytes.Replace(body, []byte(v.Model), []byte(v.Model[:1]+"\r"+v.Model[1:]), 1),
		"missing-eof-newline":         body[:len(body)-1],
		"scalar-cap":                  bytes.Replace(body, []byte(v.Manufacturer), []byte(strings.Repeat("x", 129)), 1),
		"line-cap":                    append(bytes.Clone(body), []byte(strings.Repeat(" ", 1025)+"\n")...),
		"line-count-cap":              append(bytes.Clone(body), []byte(strings.Repeat("\n", 129))...),
		"byte-cap":                    []byte(strings.Repeat("x", 8193)),
		"legacy-flat":                 []byte("manufacturer: " + v.Manufacturer + "\nrelease: " + v.Release + "\nndm: exact: " + v.NDMExact + "\nversion: " + v.NDW4Version + "\n"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := parseBuild(raw); err == nil || got != (buildTuple{}) {
				t.Fatal("malformed structured tuple accepted")
			}
		})
	}
}

func TestForeignVersionCannotSubstituteOrOverrideReviewedTuple(t *testing.T) {
	v := nc1812Profile().Build
	body := structuredVersionModel()
	// Replace the actual ndw4 value with the reviewed release string. A matching
	// ndw3 component value cannot repair or override that different scoped value.
	foreign := versionLine(17, "ndw3", "") + versionLine(21, "version", v.NDW4Version)
	bad := bytes.Replace(body, []byte(versionLine(17, "ndw3", "")+versionLine(21, "version", v.Release)), []byte(foreign), 1)
	bad = bytes.Replace(bad, []byte(versionLine(17, "ndw4", "")+versionLine(21, "version", v.NDW4Version)), []byte(versionLine(17, "ndw4", "")+versionLine(21, "version", v.Release)), 1)
	parsed, err := parseBuild(bad)
	if err != nil || parsed.NDW4Version != v.Release || parsed == v {
		t.Fatal("qualified paths collapsed")
	}
	p := modelProvider(false, true)
	p.build = func(context.Context) (buildTuple, error) { return parseBuild(bad) }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := p.Observe(ctx); err == nil {
		t.Fatal("foreign component granted profile")
	}
}
