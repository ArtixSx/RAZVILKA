package installpath

import "os/exec"

// EntwareOpkg discovers only the Entware package manager. A firmware or host
// opkg on PATH is not an Entware installation. Keep the canonical /opt spelling
// for the package supervisor; resolving a USB mount target is not discovery.
func EntwareOpkg() string { return entwareOpkg(exec.LookPath) }

func entwareOpkg(lookup func(string) (string, error)) string {
	for _, path := range []string{"/opt/bin/opkg", "/opt/sbin/opkg"} {
		if _, err := lookup(path); err == nil {
			return path
		}
	}
	return ""
}
