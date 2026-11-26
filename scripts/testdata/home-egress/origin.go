//go:build ignore

// This HTTP origin runs only inside the private packet fixture.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const bulkBytes = 256 << 10

func bulkPayload() []byte {
	data := make([]byte, bulkBytes)
	for i := range data {
		data[i] = byte((i * 13) ^ (i >> 8))
	}
	return data
}

// Verify the egress seen by the origin on both large transfers, including the
// server's digest of the bytes it received. A working small GET is insufficient.
func checkBulk(address, path string) error {
	data := bulkPayload()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 6 * time.Second}
	url := "http://" + address + "/bulk"
	get, err := client.Get(url)
	if err != nil {
		return err
	}
	defer get.Body.Close()
	body, err := io.ReadAll(io.LimitReader(get.Body, bulkBytes+1))
	if err != nil || get.StatusCode != http.StatusOK || get.Header.Get("X-Fixture-Path") != path || !bytes.Equal(data, body) {
		return fmt.Errorf("download through %s: status=%d path=%q bytes=%d err=%v", path, get.StatusCode, get.Header.Get("X-Fixture-Path"), len(body), err)
	}
	post, err := client.Post(url, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer post.Body.Close()
	digest, err := io.ReadAll(io.LimitReader(post.Body, 65))
	if err != nil || post.StatusCode != http.StatusOK || post.Header.Get("X-Fixture-Path") != path || string(digest) != fmt.Sprintf("%x", sha256.Sum256(data)) {
		return fmt.Errorf("upload through %s: status=%d path=%q err=%v", path, post.StatusCode, post.Header.Get("X-Fixture-Path"), err)
	}
	fmt.Printf("bulk path=%s bytes_each_way=%d sha256=%x\n", path, bulkBytes, sha256.Sum256(data))
	return nil
}

// Reuse the same TCP socket: opening a replacement would hide loss of the
// established service path during the idle interval.
func checkRetained(address, path string) error {
	dialer := net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request := func() error {
		if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodGet, "http://"+address+"/bulk", nil)
		if err != nil {
			return err
		}
		if err := req.Write(conn); err != nil {
			return err
		}
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, bulkBytes+1))
		if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("X-Fixture-Path") != path || !bytes.Equal(body, bulkPayload()) {
			return fmt.Errorf("unexpected response: status=%d path=%q bytes=%d err=%v", resp.StatusCode, resp.Header.Get("X-Fixture-Path"), len(body), err)
		}
		return nil
	}
	if err := request(); err != nil {
		return err
	}
	second, err := net.DialTimeout("tcp", address, 1500*time.Millisecond)
	if err == nil {
		second.Close()
		return fmt.Errorf("a second connection was admitted into a full set")
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		return fmt.Errorf("second connection did not reach admission timeout: %w", err)
	}
	const idle = 121 * time.Second
	fmt.Println("retention-first-response-and-capacity-refusal")
	time.Sleep(idle)
	if err := request(); err != nil {
		return err
	}
	fmt.Printf("same-socket-idle=%s path=%s bytes-before-and-after=%d\n", idle, path, bulkBytes)
	return nil
}

func main() {
	if len(os.Args) == 4 && os.Args[1] == "check-retained" {
		if err := checkRetained(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "check-bulk" {
		if err := checkBulk(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	bind, name := os.Args[1], os.Args[2]
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "bad peer", http.StatusBadRequest)
			return
		}
		label := name
		if name == "wan" && ip == "10.31.1.1" {
			label = "wan-snat"
		}
		if name == "wan" && ip == "192.0.2.12" {
			// Only the VLESS server inside this namespace opens a new local connection.
			label = "xray"
		}
		if r.URL.Path == "/bulk" {
			w.Header().Set("X-Fixture-Path", label)
			if r.Method == http.MethodPost {
				data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bulkBytes))
				if err != nil || len(data) != bulkBytes {
					http.Error(w, "incomplete upload", http.StatusBadRequest)
					return
				}
				fmt.Fprintf(w, "%x", sha256.Sum256(data))
				return
			}
			w.Write(bulkPayload())
			return
		}
		fmt.Fprintln(w, label)
	})
	if err := http.ListenAndServe(bind, nil); err != nil {
		panic(err)
	}
}
