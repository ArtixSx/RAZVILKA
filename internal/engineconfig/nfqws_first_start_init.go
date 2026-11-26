package engineconfig

import (
	"bytes"
	"slices"
	"strings"
)

const nfqwsFirstStartDispatchBegin = "# BEGIN RAZVILKA NFQWS2 OWNED DISPATCH v1\n"
const nfqwsFirstStartDispatchEnd = "# END RAZVILKA NFQWS2 OWNED DISPATCH v1\n"

// These names are dispatch only, never permission or bearer tokens. The real
// coordinator must retain the actual package/process/kernel/journal owners.
// Ordinary startup, shutdown and NDM hooks return before sourcing any config.
func nfqwsFirstStartDispatch(owner string) string {
	return nfqwsFirstStartDispatchBegin + "# RAZVILKA INSTANCE " + owner + "\n" + `case "$1" in
  owned_start) set -- start ;;
  owned_stop) set -- stop ;;
  owned_status) set -- status ;;
  status)
    printf '%s\n' 'NFQWS2 is managed by RAZVILKA; runtime status requires the coordinator.'
    exit 3
    ;;
  *)
    printf '%s\n' 'NFQWS2 is managed by RAZVILKA; this entry point is inert.'
    exit 0
    ;;
esac
` + nfqwsFirstStartDispatchEnd
}

// The only owned transformations are the exact three UDP guards and inert
// dispatcher before the exact stock source statement. No arbitrary shell is
// generated from fields; markers alone never recognise stock or grant access.
func NFQWSFirstStartInit(original []byte, owner string) ([]byte, error) {
	if !nfqwsFirstStartOwner.MatchString(owner) || nfqwsFirstStartDigest(original) != NFQWSFirstStartStockInitSHA256 {
		return nil, ErrNFQWSFirstStart
	}
	start := bytes.Index(original, []byte("_firewall_start() {\n"))
	end := bytes.Index(original, []byte("_firewall_stop() {\n"))
	if start < 0 || end <= start {
		return nil, ErrNFQWSFirstStart
	}
	lines := strings.Split(string(original[start:end]), "\n")
	changed := 0
	for i, line := range lines {
		if !strings.Contains(line, " -p udp ") {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = indent + "if [ -n \"$UDP_PORTS\" ]; then\n" + indent + "  " + strings.TrimLeft(line, " \t") + "\n" + indent + "fi"
		changed++
	}
	if changed != 3 {
		return nil, ErrNFQWSFirstStart
	}
	block := "# BEGIN " + strings.TrimPrefix(NFQWSFirstStartInitFormat, "# ") + "\n# RAZVILKA INSTANCE " + owner + "\n" +
		strings.Join(lines, "\n") + "# END " + strings.TrimPrefix(NFQWSFirstStartInitFormat, "# ") + "\n"
	out := append(slices.Clone(original[:start]), []byte(block)...)
	out = append(out, original[end:]...)
	source := []byte("\nsource \"$CONFFILE\"\n")
	if bytes.Count(out, source) != 1 {
		return nil, ErrNFQWSFirstStart
	}
	replacement := []byte("\n" + nfqwsFirstStartDispatch(owner) + "source \"$CONFFILE\"\n")
	return bytes.Replace(out, source, replacement, 1), nil
}

func NFQWSFirstStartOriginalInit(raw []byte, owner string) ([]byte, error) {
	if nfqwsFirstStartDigest(raw) == NFQWSFirstStartStockInitSHA256 {
		return slices.Clone(raw), nil
	}
	if !nfqwsFirstStartOwner.MatchString(owner) || bytes.Count(raw, []byte(nfqwsFirstStartDispatchBegin)) != 1 || bytes.Count(raw, []byte(nfqwsFirstStartDispatchEnd)) != 1 || bytes.Count(raw, []byte(nfqwsFirstStartDispatch(owner))) != 1 {
		return nil, ErrNFQWSFirstStart
	}
	full := raw
	raw = bytes.Replace(raw, []byte(nfqwsFirstStartDispatch(owner)), nil, 1)
	begin := "# BEGIN " + strings.TrimPrefix(NFQWSFirstStartInitFormat, "# ") + "\n# RAZVILKA INSTANCE " + owner + "\n"
	end := "# END " + strings.TrimPrefix(NFQWSFirstStartInitFormat, "# ") + "\n"
	if !nfqwsFirstStartOwner.MatchString(owner) || bytes.Count(raw, []byte(begin)) != 1 || bytes.Count(raw, []byte(end)) != 1 {
		return nil, ErrNFQWSFirstStart
	}
	start := bytes.Index(raw, []byte(begin))
	finish := bytes.Index(raw, []byte(end))
	if finish <= start {
		return nil, ErrNFQWSFirstStart
	}
	lines := strings.Split(string(raw[start+len(begin):finish]), "\n")
	var restored []string
	changed := 0
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) != `if [ -n "$UDP_PORTS" ]; then` {
			restored = append(restored, line)
			continue
		}
		if i+2 >= len(lines) || strings.TrimSpace(lines[i+2]) != "fi" || !strings.Contains(lines[i+1], " -p udp ") {
			return nil, ErrNFQWSFirstStart
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		restored = append(restored, indent+strings.TrimLeft(lines[i+1], " \t"))
		i += 2
		changed++
	}
	if changed != 3 {
		return nil, ErrNFQWSFirstStart
	}
	original := append(slices.Clone(raw[:start]), []byte(strings.Join(restored, "\n"))...)
	original = append(original, raw[finish+len(end):]...)
	if nfqwsFirstStartDigest(original) != NFQWSFirstStartStockInitSHA256 {
		return nil, ErrNFQWSFirstStart
	}
	expected, err := NFQWSFirstStartInit(original, owner)
	if err != nil || !bytes.Equal(full, expected) {
		return nil, ErrNFQWSFirstStart
	}
	return original, nil
}

// The parameter-check issuer can recognise only the fixed safe transformation.
// The dataplane separately requires its own exact lease/plan before execution.
func NFQWSFirstStartInitOwner(raw []byte) (string, error) {
	begin := "# BEGIN " + strings.TrimPrefix(NFQWSFirstStartInitFormat, "# ") + "\n# RAZVILKA INSTANCE "
	index := bytes.Index(raw, []byte(begin))
	if index < 0 {
		return "", ErrNFQWSFirstStart
	}
	rest := string(raw[index+len(begin):])
	owner, _, _ := strings.Cut(rest, "\n")
	if _, err := NFQWSFirstStartOriginalInit(raw, owner); err != nil {
		return "", err
	}
	return owner, nil
}
