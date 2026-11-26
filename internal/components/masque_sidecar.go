package components

import (
	"errors"
	"runtime"
)

const MASQUESidecarComponent = "masque-sing-box"
const masqueSidecarRelease = "1.14.4"

var ErrMASQUESidecarUnsupported = errors.New("no reviewed private MASQUE TUN companion for this installation")
var ErrMASQUESidecarIntegrity = errors.New("private MASQUE TUN companion failed integrity verification")

type masqueSidecarArtifact struct {
	archiveBytes int64
	archiveSHA   string
	binaryBytes  int64
	binarySHA    string
}

// Official static Linux musl release images with gVisor and baseline CPU
// targets. Pin the compressed artifact and the one file we use.
var masqueSidecarArtifacts = map[string]masqueSidecarArtifact{
	"amd64": {
		archiveBytes: 32555215,
		archiveSHA:   "8f7c5f0651238850d96a0e488e5473cd77ec1a0098f63942e943f475a12057ca",
		binaryBytes:  92070560,
		binarySHA:    "fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c",
	},
	"arm64": {
		archiveBytes: 29763014,
		archiveSHA:   "b95e25f921dc5e17a4cf13327243d1177642c7e35425bf5372862c477c359f56",
		binaryBytes:  86155608,
		binarySHA:    "709d6670c49019955e498872bc39b954461517ad8009968d1cf5592e9087b563",
	},
}

func masqueSidecarArchiveBase(arch string) string {
	return "sing-box-" + masqueSidecarRelease + "-linux-" + arch + "-musl"
}

// MASQUESidecarBinaryIdentity identifies the private image only on its
// reviewed runtime platform. It conveys no standalone engine permission.
func MASQUESidecarBinaryIdentity() (size int64, sha256 string) {
	if runtime.GOOS != "linux" {
		return 0, ""
	}
	image := masqueSidecarArtifacts[runtime.GOARCH]
	return image.binaryBytes, image.binarySHA
}
