package startuptools

import "github.com/ArtixSx/razvilka/internal/netidentity"

type profile struct {
	id, arch, version, mainSHA string
	aliases                    [2]string
	main, loader, extension    string
	libraries                  []string
	pins                       map[string][]string
	stock                      bool
}

func ubuntuProfile() profile {
	return profile{
		id: "ubuntu-amd64-iptables-legacy-1.8.11-v1", arch: "amd64", version: "1.8.11 (legacy)",
		mainSHA: "da62b7b5a7371424906138fa1eba11ec922b256969e5fa3dfa716949abafe8ac",
		aliases: [2]string{"/usr/sbin/iptables-legacy", "/usr/sbin/ip6tables-legacy"},
		main:    "/usr/sbin/xtables-legacy-multi", loader: "/lib64/ld-linux-x86-64.so.2",
		extension: "/usr/lib/x86_64-linux-gnu/xtables",
		libraries: []string{"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib"},
	}
}

func stockProfile() profile {
	return profile{
		id: "stock-nc1812-arm64-iptables-1.4.21-v1", arch: "arm64", version: "1.4.21", stock: true,
		mainSHA: "966a3efa461f9f42a9f48dfb8c0bc8b5ef858aac1130adf5f84e3724b3ec2acf",
		aliases: [2]string{"/opt/sbin/iptables", "/opt/sbin/ip6tables"},
		main:    "/opt/sbin/xtables-multi", loader: "/opt/lib/ld-linux-aarch64.so.1",
		extension: "/opt/lib/iptables", libraries: []string{"/opt/lib", "/lib", "/usr/lib"},
		pins: map[string][]string{
			"/opt/lib/libip4tc.so.0.1.0":    {"70b9df4548483520cfcdcb89cddbe7ff2faa7cae89ed53e22ad60544fdca1c2a"},
			"/opt/lib/libip6tc.so.0.1.0":    {"48a62bbcb302d06abdc438720de6275f63435cd77e87a9379ba5f7aa463788de"},
			"/opt/lib/libxtables.so.10.0.0": {"a97804214fdb2f5a54c17aff8513a5c1213e1e8b90786714cc38c2951b747cf2"},
			"/opt/lib/libiptext4.so":        {"7b5e33c8bc143d4f4b1533c22273bec9f8c271c03055ac93a2bde1ecf081c289"},
			"/opt/lib/libiptext6.so":        {"c5d9ed037c75e361b210e338484296ced63253f8f03af16eb29ed9e572d67bf2"},
			"/opt/lib/libiptext.so":         {"db54c1cf04a661e86502f83313921cb61957c28f0e96cbc651d52011a0789ffa", "7949322daea9707f17307c075df84a51ef710b6c9d4f33e1e271b35d1bf36e05"},
		},
	}
}

func (p profile) environment() []string {
	path := "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
	if p.stock {
		path = "PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return []string{path, "LD_LIBRARY_PATH=" + joinPaths(p.libraries), "XTABLES_LIBDIR=" + p.extension, "LANG=C", "LC_ALL=C"}
}
func (p profile) acceptsIdentity(v netidentity.Identity) bool {
	if v.Validate() != nil {
		return false
	}
	if p.stock {
		return v.Kind == netidentity.ReviewedSingleInitNet
	}
	return v.Kind == netidentity.ProcNetInode
}
