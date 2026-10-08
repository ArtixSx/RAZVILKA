package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestMTRequestWholeSecondKeepsRequiredFraction(t *testing.T) {
	now := time.Unix(1700000000, 0)
	request := qaMTRequest([16]byte{}, now)
	id := binary.LittleEndian.Uint64(request[10:18])
	if id&3 != 0 || uint32(id) == 0 || id>>32 != uint64(now.Unix()) {
		t.Fatal("client message ID lacks the official nonempty fraction")
	}
}

func TestMTProtoAndHTTPSRemainSeparateThroughOneSOCKSEndpoint(t *testing.T) {
	for _, mode := range []string{"reply", "wrong-nonce"} {
		t.Run(mode, func(t *testing.T) {
			server, roots := fixtureTLS(t, telegramHost, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "Telegram fixture") })
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var request [42]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil {
					done <- err
					return
				}
				if request[0] != 0xef || request[1] != 10 || binary.LittleEndian.Uint32(request[22:26]) != qaMTReqPQ {
					done <- errors.New("unexpected request framing")
					return
				}
				var nonce [16]byte
				copy(nonce[:], request[26:])
				payload := qaMTPacket(nonce, time.Now())
				if mode == "wrong-nonce" {
					payload[24] ^= 1
				}
				_, err = conn.Write(append([]byte{byte(len(payload) / 4)}, payload...))
				done <- err
			}()
			socks := fixtureSOCKS(t, server.Listener.Addr().String(), "", listener.Addr().String())
			o := fixtureOptions(socks.address)
			o.MTProto, o.Duration = true, 3200*time.Millisecond
			o.Pin = netip.MustParseAddr("8.8.8.8")
			r, err := observe(context.Background(), o, roots)
			wantExit, wantReply, wantFailure := 0, 1, 0
			if mode == "wrong-nonce" {
				wantExit, wantReply, wantFailure = 2, 0, 1
			}
			if err != nil || r.ExitCode != wantExit || !r.WindowCompleted || r.Attempts != 1 || r.Accepted != 1 || r.Failures != 0 || r.Protocol == nil || r.Protocol.Attempts != 1 || r.Protocol.Replies != wantReply || r.Protocol.Failures != wantFailure || r.Protocol.Latency.Count != 1 || !r.Initial.OK || !r.Final.OK {
				t.Fatal("independent HTTPS/protocol observations lost their finite window", r, err)
			}
			if mode == "wrong-nonce" && r.Protocol.FailureCodes["mtproto-nonce-mismatch"] != 1 {
				t.Fatal("protocol refusal overwrote or reused the HTTPS acceptance")
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("MTProto fixture failed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("MTProto fixture did not close")
			}
			if len(socks.commands) != 2 {
				t.Fatal("unexpected retry or missing protocol dial", len(socks.commands))
			}
			if first, second := <-socks.commands, <-socks.commands; first != "8.8.8.8:443" || second != qaMTEndpoint {
				t.Fatal("HTTPS and MTProto escaped the single configured SOCKS", first, second)
			}
			if r.MTProto != "single_req_pq_multi_nonce_matched_resPQ_only" || r.Protocol.Scope == "" || r.Protocol.DC != 2 {
				t.Fatal("unauthenticated protocol scope omitted")
			}
		})
	}
}

func qaMTPacket(nonce [16]byte, now time.Time) []byte {
	frame := make([]byte, 76)
	binary.LittleEndian.PutUint64(frame[8:16], uint64(now.Unix())<<32|1)
	binary.LittleEndian.PutUint32(frame[16:20], 56)
	binary.LittleEndian.PutUint32(frame[20:24], qaMTResPQ)
	copy(frame[24:40], nonce[:])
	copy(frame[40:56], bytes.Repeat([]byte{0x55}, 16))
	frame[56], frame[57] = 1, 15
	binary.LittleEndian.PutUint32(frame[60:64], qaMTVector)
	binary.LittleEndian.PutUint32(frame[64:68], 1)
	binary.LittleEndian.PutUint64(frame[68:76], 0x0102030405060708)
	return frame
}

func TestQAMTOfficialAuthorizationExampleAndCanceledBeforeDial(t *testing.T) {
	// Official https://core.telegram.org/mtproto/samples-auth_key resPQ bytes;
	// independent of this implementation's constructor/fixture generator.
	frame, err := hex.DecodeString("000000000000000001f4ccc26170466a500000006324160551a1143fc7a3666be4be54d6890a02dc63248f6748214eab8a2f4cc876e11974082e9cdb98c80cda4b00000015c4b51c0300000085fd64de851d9dd0a5b7f709355fc30b216be86c022bb4c3")
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	copy(nonce[:], frame[24:40])
	now := time.Unix(int64(binary.LittleEndian.Uint64(frame[8:16])>>32), 0)
	if code := qaMTValidate(frame, nonce, now); code != "" {
		t.Fatal("official wire example refused", code)
	}
	request := qaMTRequest(nonce, now)
	if !bytes.Equal(request[22:26], []byte{0xf1, 0x8e, 0x7e, 0xbe}) {
		t.Fatal("req_pq_multi constructor differs from official schema")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	observation := qaMTExchange(ctx, "127.0.0.1:19301", func(context.Context, string) (net.Conn, error) {
		t.Fatal("already canceled exchange opened a socket")
		return nil, nil
	}, time.Now)
	if observation.Code != "mtproto-canceled" || observation.Reply {
		t.Fatal("already canceled exchange accepted")
	}
	observation = qaMTExchange(context.Background(), "127.0.0.1:19301", func(context.Context, string) (net.Conn, error) {
		return nil, &qaMTUnknownError{}
	}, time.Now)
	if observation.Code != "mtproto-io-failed" || observation.Reply {
		t.Fatal("unknown raw I/O error escaped")
	}
}

type qaMTUnknownError struct{}

func (*qaMTUnknownError) Error() string { panic("raw MTProto error must not be formatted") }

func TestQAMTStrictNonceEnvelopeTLAndTimeValidation(t *testing.T) {
	now := time.Now()
	var nonce [16]byte
	copy(nonce[:], "client-nonce-qa1")
	valid := qaMTPacket(nonce, now)
	if code := qaMTValidate(valid, nonce, now); code != "" {
		t.Fatal("valid resPQ refused", code)
	}
	for _, cut := range []string{"nonce", "constructor", "auth-key", "server-id", "old-id", "future-id", "body-length", "pq-zero", "pq-even", "pq-length", "pq-padding", "vector", "vector-zero", "vector-oversize", "trailing", "oversize"} {
		t.Run(cut, func(t *testing.T) {
			frame := bytes.Clone(valid)
			switch cut {
			case "nonce":
				frame[24] ^= 1
			case "constructor":
				frame[20] ^= 1
			case "auth-key":
				frame[0] = 1
			case "server-id":
				frame[8] = 3
			case "old-id":
				binary.LittleEndian.PutUint64(frame[8:16], uint64(now.Unix()-301)<<32|1)
			case "future-id":
				binary.LittleEndian.PutUint64(frame[8:16], uint64(now.Unix()+31)<<32|1)
			case "body-length":
				binary.LittleEndian.PutUint32(frame[16:20], 4096)
			case "pq-zero":
				frame[57] = 0
			case "pq-even":
				frame[57] = 16
			case "pq-length":
				frame[56] = 254
			case "pq-padding":
				frame[58] = 1
			case "vector":
				frame[60] ^= 1
			case "vector-zero":
				binary.LittleEndian.PutUint32(frame[64:68], 0)
			case "vector-oversize":
				binary.LittleEndian.PutUint32(frame[64:68], 0xffffffff)
			case "trailing":
				frame = append(frame, make([]byte, 4)...)
				binary.LittleEndian.PutUint32(frame[16:20], uint32(len(frame)-20))
			case "oversize":
				frame = append(frame, make([]byte, qaMTMaxFrame)...)
			}
			if qaMTValidate(frame, nonce, now) == "" {
				t.Fatal("malformed response became protocol reply")
			}
		})
	}
	for n := 0; n < len(valid); n++ {
		if qaMTValidate(valid[:n], nonce, now) == "" {
			t.Fatal("truncated response accepted", n)
		}
	}
	request := qaMTRequest(nonce, now)
	if len(request) != 42 || request[0] != 0xef || request[1] != 10 || binary.LittleEndian.Uint64(request[2:10]) != 0 || binary.LittleEndian.Uint64(request[10:18])&3 != 0 || binary.LittleEndian.Uint32(request[18:22]) != 20 || binary.LittleEndian.Uint32(request[22:26]) != qaMTReqPQ || !bytes.Equal(request[26:], nonce[:]) {
		t.Fatal("wire request differs from official req_pq_multi envelope")
	}
}

type qaMTHeaderReader struct {
	header []byte
	reads  int
}

func (r *qaMTHeaderReader) Read(p []byte) (int, error) {
	r.reads++
	if len(r.header) == 0 {
		panic("oversized frame must not allocate/read payload")
	}
	n := copy(p, r.header)
	r.header = r.header[n:]
	return n, nil
}
func TestQAMTFrameBoundBeforePayloadReadAndTransportErrors(t *testing.T) {
	r := &qaMTHeaderReader{header: []byte{127, 255, 255, 255}}
	frame, code := qaMTReadFrame(context.Background(), r)
	if frame != nil || code != "mtproto-frame-oversize" || r.reads != 2 {
		t.Fatal("unbounded frame allocation/read", code, r.reads)
	}
	for _, header := range [][]byte{{0}, {128}, {0xef}, {127, 1, 0, 0}} {
		if _, code := qaMTReadFrame(context.Background(), bytes.NewReader(header)); code != "mtproto-frame-invalid" {
			t.Fatal("invalid abridged header accepted", code)
		}
	}
	transport := make([]byte, 5)
	transport[0] = 1
	negative := int32(-404)
	binary.LittleEndian.PutUint32(transport[1:], uint32(negative))
	if _, code := qaMTReadFrame(context.Background(), bytes.NewReader(transport)); code != "mtproto-transport-error" {
		t.Fatal("transport error became response", code)
	}
}

func TestQAMTExchangeSingleRequestTruncationOversizeStallAndCancel(t *testing.T) {
	for _, cut := range []string{"valid", "wrong-nonce", "truncated", "oversize", "stall", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			heard := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				request := make([]byte, 42)
				if _, err := io.ReadFull(server, request); err != nil {
					done <- err
					return
				}
				close(heard)
				if request[0] != 0xef || request[1] != 10 || binary.LittleEndian.Uint32(request[22:26]) != qaMTReqPQ {
					done <- errors.New("wrong request")
					return
				}
				var nonce [16]byte
				copy(nonce[:], request[26:])
				frame := qaMTPacket(nonce, time.Now())
				payload := append([]byte{byte(len(frame) / 4)}, frame...)
				switch cut {
				case "wrong-nonce":
					payload[25] ^= 1
				case "truncated":
					payload = payload[:12]
				case "oversize":
					payload = []byte{127, 255, 255, 255}
				case "stall", "cancel":
					_, _ = io.Copy(io.Discard, server)
					done <- nil
					return
				}
				_, err := server.Write(payload)
				if err != nil && cut == "oversize" {
					err = nil
				}
				done <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if cut == "stall" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			if cut == "cancel" {
				go func() {
					select {
					case <-heard:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			calls := 0
			started := time.Now()
			observation := qaMTExchange(ctx, "127.0.0.1:19301", func(c context.Context, address string) (net.Conn, error) {
				calls++
				if address != "127.0.0.1:19301" {
					t.Error("listener changed")
				}
				if _, ok := c.Deadline(); !ok {
					t.Error("unbounded dial")
				}
				return client, nil
			}, time.Now)
			if calls != 1 || time.Since(started) > 2*time.Second {
				t.Fatal("retry or deadline widening")
			}
			want := map[string]string{"valid": "mtproto-respq", "wrong-nonce": "mtproto-nonce-mismatch", "truncated": "mtproto-truncated", "oversize": "mtproto-frame-oversize", "stall": "mtproto-deadline", "cancel": "mtproto-canceled"}[cut]
			if observation.Code != want || observation.Reply != (cut == "valid") {
				t.Fatal("bad protocol observation", observation.Code, observation.Reply)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("fixture server failed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("fixture leaked a goroutine")
			}
		})
	}
}

type qaMTForward struct {
	conn             net.Conn
	calls            int
	network, address string
}

func (f *qaMTForward) Dial(network, address string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, address)
}
func (f *qaMTForward) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	f.calls++
	f.network, f.address = network, address
	return f.conn, nil
}
func TestQAMTSOCKSSendsNumericPinnedDCAndNeverDialsItDirect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		var greeting [3]byte
		if _, err := io.ReadFull(server, greeting[:]); err != nil {
			done <- err
			return
		}
		if greeting != [3]byte{5, 1, 0} {
			done <- errors.New("wrong SOCKS greeting")
			return
		}
		if _, err := server.Write([]byte{5, 0}); err != nil {
			done <- err
			return
		}
		var request [10]byte
		if _, err := io.ReadFull(server, request[:]); err != nil {
			done <- err
			return
		}
		if request != [10]byte{5, 1, 0, 1, 149, 154, 167, 51, 1, 187} {
			done <- errors.New("destination was not pinned numeric DC")
			return
		}
		_, err := server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	forward := &qaMTForward{conn: client}
	conn, err := qaMTSOCKSDial(ctx, "127.0.0.1:19301", forward)
	if err != nil || conn == nil || forward.calls != 1 || forward.network != "tcp" || forward.address != "127.0.0.1:19301" {
		t.Fatal("direct or additional dial occurred")
	}
	_ = conn.Close()
	if err := <-done; err != nil {
		t.Fatal("SOCKS fixture failed", err)
	}
	for _, address := range []string{qaMTEndpoint, "localhost:19301", "127.0.0.1:0"} {
		if _, err := qaMTSOCKSDial(ctx, address, forward); err == nil || forward.calls != 1 {
			t.Fatal("unowned listener accepted")
		}
	}
}
