//go:build linux

package dataplane

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

type nfqws2ActiveSocket struct{ conn *net.UnixConn }

func nfqws2ActiveSocketOpen(file *os.File, parentPID int, deadline time.Time) (*nfqws2ActiveSocket, error) {
	// Reuse only AF_UNIX/SEQPACKET/CLOEXEC/SO_PEERCRED and fixed-fd checks.
	s, err := nfqws2ManagedStartSocketOpen(file, parentPID, deadline)
	if err != nil {
		return nil, err
	}
	return &nfqws2ActiveSocket{conn: s.conn}, nil
}
func nfqws2ActiveSocketPair(deadline time.Time) (*nfqws2ActiveSocket, *os.File, error) {
	s, file, err := nfqws2ManagedStartSocketPair(deadline)
	if err != nil {
		return nil, nil, err
	}
	return &nfqws2ActiveSocket{conn: s.conn}, file, nil
}
func (s *nfqws2ActiveSocket) send(frame nfqws2ActiveFrame) error {
	data, err := json.Marshal(frame)
	if err != nil || len(data) == 0 || len(data) > nfqws2ActiveFrameLimit {
		return ErrNFQWSManagedProcessUnknown
	}
	n, _, err := s.conn.WriteMsgUnix(data, nil, nil)
	if err != nil || n != len(data) {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	return nil
}
func (s *nfqws2ActiveSocket) receive() (nfqws2ActiveFrame, error) {
	data := make([]byte, nfqws2ActiveFrameLimit+1)
	oob := make([]byte, 1)
	n, on, flags, _, err := s.conn.ReadMsgUnix(data, oob)
	if err != nil || n == 0 || n > nfqws2ActiveFrameLimit || on != 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return nfqws2ActiveFrame{}, errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	return nfqws2ActiveFrameDecode(data[:n])
}
func (s *nfqws2ActiveSocket) close() error { return s.conn.Close() }
