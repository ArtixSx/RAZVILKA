package updatecheck

import (
	"net/netip"
	"strconv"
	"strings"
)

const (
	fileLiveVersionEffect = "live-probe-version"
	fileLiveHealthEffect  = "live-probe-healthcheck"
)

func fileLiveProbeEffect(effect string) bool {
	return effect == fileLiveVersionEffect || effect == fileLiveHealthEffect
}

// The reviewed S99 starts the exact supervised runtime with one explicit
// -listen IPv4:8787. A missing/ambiguous/default bind is not a health endpoint.
// Never rediscover the address by invoking shell, PATH ip, or init scripts.
func fileLiveEndpoint(args []string) (string, error) {
	listen := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "-listen" {
			if listen != "" || i+1 == len(args) || args[i+1] == "" {
				return "", ErrFileProtocol
			}
			listen = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "-listen=") || args[i] == "--listen" || strings.HasPrefix(args[i], "--listen=") {
			return "", ErrFileProtocol
		}
	}
	address, err := netip.ParseAddrPort(listen)
	if err != nil || address.String() != listen || !address.Addr().Is4() || address.Addr().IsUnspecified() || address.Addr().IsMulticast() || address.Port() != 8787 {
		return "", ErrFileProtocol
	}
	return "http://" + listen + "/api/v1/status", nil
}

// Only these two private recipes can reach the held executable. The endpoint
// comes from the already matched runtime argv, and PID is its sealed identity.
func fileLiveProbeArgs(effect, endpoint string, pid int) ([]string, error) {
	if effect == fileLiveVersionEffect && endpoint == "" && pid == 0 {
		return []string{"-version"}, nil
	}
	if effect != fileLiveHealthEffect || pid <= 1 {
		return nil, ErrFileProtocol
	}
	listen := strings.TrimSuffix(strings.TrimPrefix(endpoint, "http://"), "/api/v1/status")
	canonical, err := fileLiveEndpoint([]string{"runtime", "-listen", listen})
	if err != nil || canonical != endpoint {
		return nil, ErrFileProtocol
	}
	return []string{"-healthcheck", endpoint, "-healthcheck-pid", strconv.Itoa(pid), "-healthcheck-require-dataplane"}, nil
}
