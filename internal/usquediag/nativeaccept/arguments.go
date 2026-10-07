package nativeaccept

import (
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const Usage = `usque-owned-native --run-existing-account --mode h2|quic
  --binary /absolute/usque --binary-sha256 <audited-executable-sha256>
  --account /absolute/existing-account.json --account-sha256 <sha256>
  --work-parent /absolute/private-existing-directory --socks-port 19080
  [--timeout 20s] [--cleanup-timeout 5s]

Linux only. Uses one selected mode and the existing account without registration.
The concrete retained CORE issuer is not wired yet; execution currently refuses
before account/process/network IO. This command cannot import receipts or grants.
`

// ParseArguments suppresses flag's echo of arbitrary user input/private paths.
// Errors are fixed codes. Unknown/trailing/duplicate flags are rejected.
func ParseArguments(args []string) (Request, error) {
	var r Request
	f := flag.NewFlagSet("usque-owned-native", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var mode string
	var port int
	f.BoolVar(&r.Enabled, "run-existing-account", false, "explicit opt-in")
	f.StringVar(&mode, "mode", "", "h2 or quic")
	f.StringVar(&r.Binary, "binary", "", "absolute audited executable")
	f.StringVar(&r.BinarySHA256, "binary-sha256", "", "audited SHA256")
	f.StringVar(&r.Account, "account", "", "absolute existing account")
	f.StringVar(&r.AccountSHA256, "account-sha256", "", "existing account SHA256")
	f.StringVar(&r.WorkParent, "work-parent", "", "existing private staging parent")
	f.IntVar(&port, "socks-port", 19080, "exact loopback listener")
	f.DurationVar(&r.Timeout, "timeout", 20*time.Second, "bounded check")
	f.DurationVar(&r.CleanupTimeout, "cleanup-timeout", 5*time.Second, "bounded retained cleanup")
	seen := map[string]bool{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
			if seen[name] {
				return Request{}, errors.New("arguments-invalid")
			}
			seen[name] = true
		}
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Request{}, flag.ErrHelp
		}
		return Request{}, errors.New("arguments-invalid")
	}
	if f.NArg() != 0 || port < 1024 || port > 65535 {
		return Request{}, errors.New("arguments-invalid")
	}
	switch mode {
	case "h2":
		r.Transport = "HTTP/2"
	case "quic":
		r.Transport = "QUIC"
	default:
		return Request{}, errors.New("arguments-invalid")
	}
	r.SOCKSPort = uint16(port)
	if code := validate(r); code != "" {
		return Request{}, errors.New(code)
	}
	return r, nil
}

func validate(r Request) string {
	if !r.Enabled {
		return "opt-in-required"
	}
	if (r.Transport != "HTTP/2" && r.Transport != "QUIC") || r.SOCKSPort < 1024 ||
		r.Timeout < time.Second || r.Timeout > 30*time.Second || r.CleanupTimeout < time.Second || r.CleanupTimeout > 5*time.Second ||
		!digest(r.BinarySHA256) || !digest(r.AccountSHA256) || filepath.Base(r.Binary) != "usque" {
		return "arguments-invalid"
	}
	for _, path := range []string{r.Binary, r.Account, r.WorkParent} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") || path == filepath.VolumeName(path)+string(filepath.Separator) {
			return "arguments-invalid"
		}
	}
	if r.Binary == r.Account || r.Binary == r.WorkParent || r.Account == r.WorkParent {
		return "arguments-invalid"
	}
	return ""
}

func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
