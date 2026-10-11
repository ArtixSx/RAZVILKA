package dataplane

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

func xraySelectedTCPELFModel() []byte {
	data := make([]byte, 256)
	copy(data, "\x7fELF\x02\x01\x01")
	le := binary.LittleEndian
	le.PutUint16(data[16:18], 2)
	machine := uint16(62)
	if runtime.GOARCH == "arm64" {
		machine = 183
	}
	le.PutUint16(data[18:20], machine)
	le.PutUint32(data[20:24], 1)
	le.PutUint64(data[24:32], 0x400080)
	le.PutUint64(data[32:40], 64)
	le.PutUint16(data[52:54], 64)
	le.PutUint16(data[54:56], 56)
	le.PutUint16(data[56:58], 1)
	le.PutUint32(data[64:68], 1)
	le.PutUint32(data[68:72], 5)
	le.PutUint64(data[80:88], 0x400000)
	le.PutUint64(data[96:104], 256)
	le.PutUint64(data[104:112], 256)
	return data
}

func TestXraySelectedTCPRuntimeELFBoundedExecutableEntry(t *testing.T) {
	valid := xraySelectedTCPELFModel()
	if err := xraySelectedTCPELFHeader(bytes.NewReader(valid), int64(len(valid))); err != nil {
		t.Fatal(err)
	}
	for _, cut := range []string{"huge-table", "offset-overflow", "truncated-table", "unmapped-entry", "non-executable-entry", "file-overrun", "memory-overflow", "wrong-machine", "short-read"} {
		t.Run(cut, func(t *testing.T) {
			data := bytes.Clone(valid)
			le := binary.LittleEndian
			switch cut {
			case "huge-table":
				le.PutUint16(data[56:58], 65535)
			case "offset-overflow":
				le.PutUint64(data[32:40], ^uint64(0)-12)
			case "truncated-table":
				le.PutUint16(data[56:58], 4)
			case "unmapped-entry":
				le.PutUint64(data[24:32], 0x400100)
			case "non-executable-entry":
				le.PutUint32(data[68:72], 4)
			case "file-overrun":
				le.PutUint64(data[72:80], 1)
			case "memory-overflow":
				le.PutUint64(data[80:88], ^uint64(0)-1)
			case "wrong-machine":
				le.PutUint16(data[18:20], 0)
			case "short-read":
				data = data[:70]
			}
			if err := xraySelectedTCPELFHeader(bytes.NewReader(data), int64(len(valid))); err == nil {
				t.Fatal("malformed executable accepted", cut)
			}
		})
	}
}
