package startuptools

import "strings"

// Fixed categories only: never interpolate arbitrary paths or CLI data into
// startup diagnostics. The category identifies which protected boundary failed.
func pathCategory(path string) string {
	switch path {
	case "/":
		return "ROOT"
	case "/opt":
		return "OPT"
	case "/opt/etc":
		return "OPT_ETC"
	case "/etc":
		return "ETC"
	case "/usr", "/usr/sbin", "/usr/bin", "/opt/sbin", "/opt/bin", "/opt/libexec":
		return "TOOL_PARENT"
	case "/lib", "/lib64", "/usr/lib", "/opt/lib", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu":
		return "LIBRARY_ROOT"
	case "/usr/lib/x86_64-linux-gnu/xtables", "/opt/lib/iptables":
		return "EXTENSION_ROOT"
	case "/usr/sbin/iptables-legacy", "/usr/sbin/ip6tables-legacy", "/usr/sbin/xtables-legacy-multi", "/opt/sbin/iptables", "/opt/sbin/ip6tables", "/opt/sbin/xtables-multi":
		return "XTABLES_ENTRY"
	case "/usr/sbin/ip", "/usr/bin/ip", "/opt/sbin/ip", "/opt/libexec/ip-full":
		return "IP_ENTRY"
	case "/lib64/ld-linux-x86-64.so.2", "/opt/lib/ld-linux-aarch64.so.1":
		return "LOADER_ENTRY"
	}
	if strings.HasPrefix(path, "/usr/lib/x86_64-linux-gnu/xtables/") || strings.HasPrefix(path, "/opt/lib/iptables/") {
		return "EXTENSION_PATH"
	}
	if strings.HasPrefix(path, "/lib/") || strings.HasPrefix(path, "/usr/lib/") || strings.HasPrefix(path, "/opt/lib/") {
		return "LIBRARY_PATH"
	}
	return "OTHER_PROTECTED_PATH"
}
