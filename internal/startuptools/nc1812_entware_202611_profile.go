package startuptools

// Fixed package bytes reviewed from Keenetic iptables 1.4.21-6, Entware
// libc 2.27-12/libgcc 8.4.0-12 and xtables-addons_legacy 1.47.1-2.
// Recipe snapshots: Entware 541289a115d32d1ab044e87608bc0ca6b2154ee9,
// The-BB/keendev-3x 9aa40a4101c6e6e772e3b312705b1d2c02a12041, and
// entware-oldpackages-ports 0e8841717b34a4aeac2c280618c50590c65e65f7.
// Package archive SHA256:
// iptables: 36999650d64ace11ccbdfd8cc66b68ccad0b2d1d32ffcdb8a36fe2ab26a1cf15
// libc: 2e0890ada42c28676135198b325b215e169c2549e646a20d3cbb55bcf9be5a61
// libgcc: 8cfa38d0a541419413dbf4b24983eeb572e3c61d3a4424939ee27fab89ebe990
// addons: 50e8a0dc9afa6841117bfc21294de569ec5926354207c94b730c44f06fce318d
// ip-full: bc5fd8f91c956dc112138749903511800354abd074ed37578bde313d9abbd60c
// These are package-byte pins, not a reproducible-build or router grant.
// Acquisition still requires original protected ancestry, vendor identity,
// loader closure, version children, provider bookends and fresh comparisons.
// Public selection is deliberately unchanged until integration is reviewed.
func nc1812Entware202611Profile() profile {
	return profile{
		id:   "stock-nc1812-entware-202611-iptables-1.4.21-v1",
		arch: "arm64", version: "1.4.21", stock: true,
		mainSHA: "aafefd9d754b80fa3915c97dc04a52b0e5c5de96c513ce9556175110228579ab",
		aliases: [2]string{"/opt/sbin/iptables", "/opt/sbin/ip6tables"},
		main:    "/opt/sbin/xtables-multi", loader: "/opt/lib/ld-linux-aarch64.so.1",
		extension: "/opt/lib/iptables", libraries: []string{"/opt/lib", "/lib", "/usr/lib"},
		pins: map[string][]string{
			"/opt/lib/ld-2.27.so":           {"531b2f139616cd3174f19186cca3f83a28e9012d3e4cda0bea1a1962589de66c"},
			"/opt/lib/libc-2.27.so":         {"61023ec5dade3909b7e0ef12099282328d4f8ab10ca0fe3c1d20a2f49785d080"},
			"/opt/lib/libdl-2.27.so":        {"a072007475986e25730befe54563e94a58343ce7a374a42f812bab4efcebfa7e"},
			"/opt/lib/libgcc_s.so.1":        {"a7574eb677288c961a78dabd24ca5fb305ec027d5bf85b6a4241da59c0df8ad6"},
			"/opt/lib/libip4tc.so.0.1.0":    {"b6ff024abbb79e204fa9237db3a9bfa80f6f5f19fa9e672411376d3b9d559d75"},
			"/opt/lib/libip6tc.so.0.1.0":    {"109e517ec08d684d1f8700da5be41c174837cc321a3acc0a9d8d1f6ab8f5c26d"},
			"/opt/lib/libiptext.so":         {"3bac9e31cede5896739884c5b7fc253cfa9038e565ad46457e2090f1d68ef3ee"},
			"/opt/lib/libiptext4.so":        {"49df205e0c3602cbe0c0bce67e713a065d4732d8a98379ff1c3b3708c392627d"},
			"/opt/lib/libiptext6.so":        {"6bbaf591e032027d0e23efdd6aa23947f1b2330d222e9e60fc3c9504d3351dba"},
			"/opt/lib/libm-2.27.so":         {"c6474c12eaad008bfb51f720be08fb835a2c86fa488eefef3b78f9861fc5ae14"},
			"/opt/lib/libxtables.so.10.0.0": {"941e1646d85b892a315dfc8909909016f3a097cd99d2f5a3af6c26911a4aea2e"},
		},
		extensionExpectations: map[string]extensionExpectation{
			"libxt_ACCOUNT.so":     {target: "/opt/lib/iptables/libxt_ACCOUNT.so", sha256: "d4a1ba8548c444cf7ed95f9b0932cd5f050eb6e28d8d6962d590486024c6c010", link: ""},
			"libxt_CHAOS.so":       {target: "/opt/lib/iptables/libxt_CHAOS.so", sha256: "c73a0408b6a54a3ebbd6b1da3304160a79e2f630ced4c3b44fa9609657c65868", link: ""},
			"libxt_CT.so":          {target: "/opt/lib/iptables/libxt_CT.so", sha256: "cbef53413367efbbdb6f93001959fcd473fb1f655960eca51d8f39a650609947", link: ""},
			"libxt_DELUDE.so":      {target: "/opt/lib/iptables/libxt_DELUDE.so", sha256: "ac861c3a2a5728c0e83a401544062b342ce6acdaf857d44ab37653fa7d95e189", link: ""},
			"libxt_DHCPMAC.so":     {target: "/opt/lib/iptables/libxt_DHCPMAC.so", sha256: "5d4459fac479c09d35e2e8c06a65d2984fbd05c2aa5044607db2496011ae2328", link: ""},
			"libxt_DNETMAP.so":     {target: "/opt/lib/iptables/libxt_DNETMAP.so", sha256: "7afcbfa9dec1564aae863fdb5b7e0176daa430e13ea5976a78b5d162acb9ca13", link: ""},
			"libxt_ECHO.so":        {target: "/opt/lib/iptables/libxt_ECHO.so", sha256: "a9647dd7ea8525e665138262783f64ddf96cbb3cfa28e1c084d68585bfb0b86c", link: ""},
			"libxt_IPMARK.so":      {target: "/opt/lib/iptables/libxt_IPMARK.so", sha256: "968e414e2d6cc202e7b40c97297d302eecf5861b4a2af23ae01f04f7b40f460c", link: ""},
			"libxt_LOGMARK.so":     {target: "/opt/lib/iptables/libxt_LOGMARK.so", sha256: "4137f6a5427ffdf5adccc7261a82c59c37f53ba031ec1a12931a89406f643391", link: ""},
			"libxt_NOTRACK.so":     {target: "/opt/lib/iptables/libxt_CT.so", sha256: "cbef53413367efbbdb6f93001959fcd473fb1f655960eca51d8f39a650609947", link: "libxt_CT.so"},
			"libxt_RAWDNAT.so":     {target: "/opt/lib/iptables/libxt_RAWDNAT.so", sha256: "cdbf74fb96092490efc4a79b4b9afb45d4399c16d434d0e07f52691677e234a5", link: ""},
			"libxt_RAWSNAT.so":     {target: "/opt/lib/iptables/libxt_RAWSNAT.so", sha256: "74562c732109df5f57e4065f7d9d43a03ae3d61cd57674380fe03c75aef1c8dd", link: ""},
			"libxt_STEAL.so":       {target: "/opt/lib/iptables/libxt_STEAL.so", sha256: "edbf974a1176a96f899cd806dc77da4fd532e78fe0ed9f2dc65792a5ec4e4fa8", link: ""},
			"libxt_SYSRQ.so":       {target: "/opt/lib/iptables/libxt_SYSRQ.so", sha256: "5248fb77291a77664445b6e2e769e632635a76cdcb37b0499d1ac04c3d21126f", link: ""},
			"libxt_TARPIT.so":      {target: "/opt/lib/iptables/libxt_TARPIT.so", sha256: "3395783d3a22411483c34186abe1c114d35abffad3beab0b43c4ab32a4986ad4", link: ""},
			"libxt_condition.so":   {target: "/opt/lib/iptables/libxt_condition.so", sha256: "85c2e7c24bc84305ba23068376b4c56f07b1f7b065ac2b7c624e7197e460e977", link: ""},
			"libxt_conntrack.so":   {target: "/opt/lib/iptables/libxt_conntrack.so", sha256: "e63cc510c236d1d5f9d9d4bd50760d9b36755a76767d1366ef5db7408c81b2be", link: ""},
			"libxt_dhcpmac.so":     {target: "/opt/lib/iptables/libxt_dhcpmac.so", sha256: "2b483340579bb349ad434807c11454eeb5c915745badbbb6701a574f62f6e95a", link: ""},
			"libxt_fuzzy.so":       {target: "/opt/lib/iptables/libxt_fuzzy.so", sha256: "f3b5ddc1bd8488924d1aac4421287fc6629b03f2f0fc38f1719d88429b1b14d6", link: ""},
			"libxt_geoip.so":       {target: "/opt/lib/iptables/libxt_geoip.so", sha256: "c6f508aadd2bf7501865fc739672f64a34fa3f228c6efc990a3dcd964b48f44d", link: ""},
			"libxt_gradm.so":       {target: "/opt/lib/iptables/libxt_gradm.so", sha256: "61b849436a890a1615adb4c242f678b4a18bf7e8eb1cd307ccc8c2995baae733", link: ""},
			"libxt_iface.so":       {target: "/opt/lib/iptables/libxt_iface.so", sha256: "849cd387086c1516ffc605c74826efd456ddf51bc4b1ce854772db840436d1e1", link: ""},
			"libxt_ipp2p.so":       {target: "/opt/lib/iptables/libxt_ipp2p.so", sha256: "0179e686c1b6f7357bc7abff0da36ec23b3577726f2092f87fbadd7441156929", link: ""},
			"libxt_ipv4options.so": {target: "/opt/lib/iptables/libxt_ipv4options.so", sha256: "115046c44193e7d7ee1c377118757265f8764c6f7e609674818a3a8dd122cc37", link: ""},
			"libxt_length2.so":     {target: "/opt/lib/iptables/libxt_length2.so", sha256: "93eefd5bd493655ad3a852030d6f20c92a11219e3daefaaa9613cbd7c707fa01", link: ""},
			"libxt_lscan.so":       {target: "/opt/lib/iptables/libxt_lscan.so", sha256: "daa1b38d840aab7b6c557637bc199e5d0768348e395fb71e82743cd7fecac229", link: ""},
			"libxt_pknock.so":      {target: "/opt/lib/iptables/libxt_pknock.so", sha256: "8ead7e33a57b2261edad3f359936d95cda759a50beae78fc419edd003fba6c63", link: ""},
			"libxt_psd.so":         {target: "/opt/lib/iptables/libxt_psd.so", sha256: "8773a2178dfb7a1cab7b04430a036a3b7f9e4275307779d63db71a43853cab14", link: ""},
			"libxt_quota2.so":      {target: "/opt/lib/iptables/libxt_quota2.so", sha256: "f3e3b6edcab0fc3d74d3c42b00b2a86c53c12887990baa3264760e0d745863f0", link: ""},
			"libxt_state.so":       {target: "/opt/lib/iptables/libxt_conntrack.so", sha256: "e63cc510c236d1d5f9d9d4bd50760d9b36755a76767d1366ef5db7408c81b2be", link: "libxt_conntrack.so"},
		},
	}
}

func nc1812Entware202611PolicyProfile() profile {
	p := nc1812Entware202611Profile()
	p.id = "stock-nc1812-entware-202611-ip-4.4.0-policy-v1"
	p.ipAlias, p.ipMain = "/opt/sbin/ip", "/opt/libexec/ip-full"
	p.ipSHA = "2a83e9832ad7a3f96f6bcd25e7f90afb80a1a7ee4b680f1a3687e29848c5c2d3"
	p.ipVersion = "ip utility, iproute2-ss4.4.0-11-entware\n"
	return p
}

func nc1812Entware202611WGProfile(engine string) profile {
	p := nc1812Entware202611PolicyProfile()
	p.wgAliases = [2]string{"/opt/bin/wg", "/opt/sbin/awg"}
	p.wgEngine = engine
	p.id += "-" + engine + "-native-v1"
	return p
}

func nc1812Entware202611ManagedListProfile() profile {
	p := nc1812Entware202611WGProfile(managedListWGProfile)
	p.id = "stock-nc1812-entware-202611-managed-list-optional-wg-v1"
	return p
}
