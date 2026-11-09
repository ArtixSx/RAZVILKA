//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

const pairedHistoryEngineSHA = "25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1"
const pairedHistoryHost = "www.youtube.com"
const pairedHistoryAddress = "203.0.113.9"

type nativePairedHistory struct {
	evidence  []strategylab.Evidence
	selection strategylab.Selection
}

// Runs before the genuine old panel starts, inside the same proven private
// namespaces. Only that old process receives SSL_CERT_FILE; no TLS checks or
// production source authorities are changed. These are synthetic lab peers.
func TestNativePairedHistoryTLSMaterial(t *testing.T) {
	if os.Getenv("RAZVILKA_PAIRED_NATIVE_HISTORY") != "history" {
		t.Skip("separate history fixture only")
	}
	nativePairedPrivateScope(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RAZVILKA isolated historical probe CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{pairedHistoryHost}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	for name, block := range map[string]*pem.Block{"history-ca.pem": {Type: "CERTIFICATE", Bytes: caDER}, "history-cert.pem": {Type: "CERTIFICATE", Bytes: leafDER}, "history-key.pem": {Type: "PRIVATE KEY", Bytes: keyDER}} {
		raw := pem.EncodeToMemory(block)
		f, err := os.OpenFile(filepath.Join(installpath.Config, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			clear(raw)
			t.Fatal("exclusive private TLS material", err)
		}
		_, writeErr := f.Write(raw)
		closeErr := f.Close()
		clear(raw)
		if writeErr != nil || closeErr != nil {
			t.Fatal("private TLS material write", errors.Join(writeErr, closeErr))
		}
	}
}

func nativePairedHistoryCommand(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out, stderr := &nativePairedRestoreOutput{}, &nativePairedRestoreOutput{}
	command.Stdout, command.Stderr, command.WaitDelay = out, stderr, 100*time.Millisecond
	if err := command.Run(); err != nil || command.ProcessState == nil || stderr.Len() != 0 {
		t.Fatal("fixed private history command refused", name, err)
	}
	return bytes.Clone(out.Bytes())
}

func nativePairedHistoryKernel(t *testing.T, engine os.FileInfo) string {
	t.Helper()
	var state strings.Builder
	for _, binary := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		for _, table := range []string{"filter", "nat", "mangle", "raw", "security"} {
			state.WriteString(binary + "/" + table + "\n")
			state.Write(nativePairedHistoryCommand(t, binary, "-t", table, "-S"))
		}
	}
	for _, family := range []string{"-4", "-6"} {
		for _, what := range []string{"route", "rule"} {
			args := []string{"-j", family, what, "show"}
			if what == "route" {
				args = append(args, "table", "all")
			}
			raw := nativePairedHistoryCommand(t, "/usr/sbin/ip", args...)
			if what == "route" {
				var routes []struct {
					Dev     string `json:"dev"`
					Gateway string `json:"gateway"`
				}
				if json.Unmarshal(raw, &routes) != nil {
					t.Fatal("full private routes unreadable")
				}
				for _, route := range routes {
					if route.Dev != "lo" || route.Gateway != "" {
						t.Fatal("outward route in historical fixture")
					}
				}
			}
			state.WriteString(family + "/" + what + "\n")
			state.Write(raw)
		}
	}
	queue, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil || len(bytes.TrimSpace(queue)) != 0 {
		t.Fatal("historical NFQ child/queue did not settle", err)
	}
	for _, family := range []string{"ip", "ip6"} {
		raw, err := os.ReadFile("/proc/net/" + family + "_tables_names")
		if err != nil {
			t.Fatal("full registered table inventory", err)
		}
		names := strings.Fields(string(raw))
		seen := map[string]bool{}
		for _, name := range names {
			switch name {
			case "filter", "nat", "mangle", "raw", "security":
			default:
				t.Fatal("unexpected kernel table")
			}
			if seen[name] {
				t.Fatal("duplicate kernel table")
			}
			seen[name] = true
		}
		if len(seen) != 5 {
			t.Fatal("incomplete registered kernel tables")
		}
	}
	if engine != nil {
		processes, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		for _, process := range processes {
			if _, err := strconv.Atoi(process.Name()); err != nil {
				continue
			}
			info, err := os.Stat(filepath.Join("/proc", process.Name(), "exe"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal("engine absence unknown", err)
			}
			if os.SameFile(engine, info) {
				t.Fatal("original NFQ child still alive")
			}
		}
	}
	return state.String()
}

func nativePairedHistoryPeer(t *testing.T) (func() error, *atomic.Int64) {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(installpath.Config+"/history-cert.pem", installpath.Config+"/history-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", pairedHistoryAddress+":443", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	served, active := &atomic.Int64{}, &atomic.Int64{}
	server := &http.Server{ReadHeaderTimeout: 2 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		if r.Method != http.MethodGet || r.Host != pairedHistoryHost || r.URL.RequestURI() != "/" || r.TLS == nil || r.TLS.ServerName != pairedHistoryHost {
			http.Error(w, "fixed lab target only", http.StatusBadRequest)
			return
		}
		served.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var once sync.Once
	var result error
	closePeer := func() error {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result = server.Shutdown(ctx)
			if result != nil {
				result = errors.Join(result, server.Close())
			}
			select {
			case err := <-done:
				if !errors.Is(err, http.ErrServerClosed) {
					result = errors.Join(result, err)
				}
			case <-time.After(5 * time.Second):
				result = errors.Join(result, errors.New("historical TLS Serve did not join"))
			}
			if active.Load() != 0 {
				result = errors.Join(result, errors.New("historical TLS requests remain active"))
			}
		})
		return result
	}
	t.Cleanup(func() {
		if err := closePeer(); err != nil {
			t.Error(err)
		}
	})
	return closePeer, served
}

func nativePairedPublicHistoryBefore(t *testing.T) *nativePairedDraft {
	t.Helper()
	nativePairedPrivateScope(t)
	var links []struct {
		Name string `json:"ifname"`
	}
	if json.Unmarshal(nativePairedHistoryCommand(t, "/usr/sbin/ip", "-j", "link", "show"), &links) != nil || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("history fixture is not isolated loopback geometry")
	}
	// The genuine main catalog, not the separate community catalog, supplies
	// Probe's trusted URL. Preserve and check that original source verbatim.
	catalogPath := installpath.Config + "/service-catalog.json"
	originalCatalog := filepath.Join(filepath.Dir(os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_CANDIDATE")), "old-source/configs/service-catalog.json")
	if nativePairedRestoreFileHash(t, catalogPath) != nativePairedRestoreFileHash(t, originalCatalog) {
		t.Fatal("original source catalog changed")
	}
	catalogRaw, err := os.ReadFile(catalogPath)
	var catalog struct {
		Services []struct {
			ID       string `json:"id"`
			ProbeURL string `json:"probe_url"`
		} `json:"services"`
	}
	if err != nil || len(catalogRaw) > 1<<20 || json.Unmarshal(catalogRaw, &catalog) != nil {
		t.Fatal("original trusted catalog unreadable")
	}
	targets := 0
	for _, service := range catalog.Services {
		if service.ID == "youtube" {
			if service.ProbeURL != "https://www.youtube.com/" {
				t.Fatal("original trusted historical probe target changed")
			}
			targets++
		}
	}
	if targets != 1 {
		t.Fatal("original trusted target is not unique")
	}
	originalKernel := nativePairedHistoryKernel(t, nil)
	nativePairedHistoryCommand(t, "/usr/sbin/ip", "addr", "add", pairedHistoryAddress+"/32", "dev", "lo")
	program := filepath.Join(filepath.Dir(os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_CANDIDATE")), "zapret2-v1.0.6/binaries/linux-x86_64/nfqws2")
	data, err := os.ReadFile(program)
	if err != nil || len(data) == 0 || len(data) > 16<<20 {
		t.Fatal("pinned original fixture engine unavailable", err)
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != pairedHistoryEngineSHA {
		t.Fatal("pinned engine hash changed")
	}
	enginePath := "/opt/bin/nfqws2"
	f, err := os.OpenFile(enginePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	clear(data)
	engine, statErr := os.Lstat(enginePath)
	if writeErr != nil || closeErr != nil || statErr != nil || nativePairedRestoreFileHash(t, enginePath) != pairedHistoryEngineSHA {
		t.Fatal("genuine private engine copy", errors.Join(writeErr, closeErr, statErr))
	}
	closePeer, served := nativePairedHistoryPeer(t)
	baseline := nativePairedHistoryKernel(t, engine)
	token := nativePairedSourceToken(t)
	var empty strategylab.Snapshot
	if json.Unmarshal(nativePairedDraftHTTP(t, http.MethodGet, "/api/v1/strategy-lab", nil, ""), &empty) != nil || len(empty.Candidates)+len(empty.Evidence)+len(empty.Selections) != 0 {
		t.Fatal("history source baseline not empty")
	}
	var candidate strategylab.Candidate
	raw := nativePairedDraftHTTP(t, http.MethodPost, "/api/v1/strategy-lab/candidates", []byte(`{"pool_id":"tcp-tls","name":"public paired historical selection","arguments":"--filter-tcp=443"}`), token)
	if json.Unmarshal(raw, &candidate) != nil || candidate.ID == "" {
		t.Fatal("actual historical candidate creation")
	}
	raw = nativePairedSourceHTTP(t, http.MethodPost, "/api/v1/strategy-lab/candidates/"+candidate.ID+"/validate", nil, token, http.StatusOK, 12*time.Second)
	if json.Unmarshal(raw, &candidate) != nil || !candidate.Validation.OK || !candidate.Validation.Native {
		t.Fatal("genuine old native validation did not pass")
	}
	history := &nativePairedHistory{}
	for i := 0; i < 3; i++ {
		if nativePairedHistoryKernel(t, engine) != baseline {
			t.Fatal("kernel changed before original historical probe")
		}
		raw = nativePairedSourceHTTP(t, http.MethodPost, "/api/v1/strategy-lab/candidates/"+candidate.ID+"/probe", []byte(`{"service_id":"youtube","ip_family":"ipv4"}`), token, http.StatusOK, 20*time.Second)
		var evidence strategylab.Evidence
		if json.Unmarshal(raw, &evidence) != nil || !evidence.Success || !evidence.RouteConfirmed || evidence.CandidateID != candidate.ID || evidence.ServiceID != "youtube" || evidence.Protocol != "tcp" || evidence.IPFamily != "ipv4" || evidence.HTTPStatus != 204 || evidence.CheckedAt == "" {
			t.Fatal("actual old probe did not produce confirmed historical evidence")
		}
		stages := map[string]bool{}
		for _, stage := range evidence.Stages {
			if stage.Status == "pass" {
				stages[stage.Stage] = true
			}
		}
		if !stages["route"] || !stages["cleanup"] || !stages["result"] {
			t.Fatal("actual route/counter/cleanup stages incomplete")
		}
		if nativePairedHistoryKernel(t, engine) != baseline {
			t.Fatal("historical probe did not restore full kernel baseline")
		}
		history.evidence = append(history.evidence, evidence)
	}
	body, _ := json.Marshal(map[string]any{"service_id": "youtube", "protocol": "tcp", "ip_family": "ipv4", "candidate_id": candidate.ID, "frozen": true})
	raw = nativePairedSourceHTTP(t, http.MethodPost, "/api/v1/strategy-lab/selections", body, token, http.StatusOK, 5*time.Second)
	if json.Unmarshal(raw, &history.selection) != nil || history.selection.CandidateID != candidate.ID || history.selection.ServiceID != "youtube" || history.selection.Protocol != "tcp" || history.selection.IPFamily != "ipv4" || !history.selection.Frozen || !history.selection.Healthy || history.selection.SelectedAt == "" {
		t.Fatal("actual old frozen manual selection refused")
	}
	if err := closePeer(); err != nil || served.Load() != 3 {
		t.Fatal("owned historical TLS peer did not settle", err, served.Load())
	}
	if nativePairedHistoryKernel(t, engine) != baseline {
		t.Fatal("historical resources changed during peer join")
	}
	current, err := os.Lstat(enginePath)
	if err != nil || !os.SameFile(engine, current) || nativePairedRestoreFileHash(t, enginePath) != pairedHistoryEngineSHA {
		t.Fatal("foreign fixture engine at cleanup")
	}
	if err := os.Remove(enginePath); err != nil {
		t.Fatal(err)
	}
	nativePairedHistoryCommand(t, "/usr/sbin/ip", "addr", "del", pairedHistoryAddress+"/32", "dev", "lo")
	if nativePairedHistoryKernel(t, nil) != originalKernel {
		t.Fatal("history fixture did not restore original routing/rules")
	}
	nativePairedHistoryCommand(t, "/usr/bin/umount", "/etc/hosts")
	for _, name := range []string{"history-hosts", "history-ca.pem", "history-cert.pem", "history-key.pem"} {
		if err := os.Remove(filepath.Join(installpath.Config, name)); err != nil {
			t.Fatal("private history material cleanup", err)
		}
	}
	draft := &nativePairedDraft{candidate: candidate, history: history, stateSHA: nativePairedRestoreFileHash(t, installpath.State+"/strategy-lab.json")}
	nativePairedHistoryReadback(t, draft)
	t.Log("actual_old193_history authored_http=true native_validation=true completed_probes=3 frozen_manual_selection=true real_queue_counter_cleanup=true synthetic_private_tls=true public_service_readiness=false")
	return draft
}

func nativePairedHistoryReadback(t *testing.T, draft *nativePairedDraft) {
	t.Helper()
	path := installpath.State + "/strategy-lab.json"
	if nativePairedRestoreFileHash(t, path) != draft.stateSHA {
		t.Fatal("original historical state bytes changed")
	}
	reader, err := strategylab.New(path)
	if err != nil {
		t.Fatal("current historical reader", err)
	}
	got := reader.Snapshot()
	if got.QuiescenceUnknown || len(got.Candidates) != 1 || !reflect.DeepEqual(got.Candidates[0], draft.candidate) || !reflect.DeepEqual(got.Evidence, draft.history.evidence) || len(got.Selections) != 1 {
		t.Fatal("original candidate/completed history lost")
	}
	selection, want := got.Selections[0], draft.history.selection
	if selection.ServiceID != want.ServiceID || selection.Protocol != want.Protocol || selection.IPFamily != want.IPFamily || selection.CandidateID != want.CandidateID || selection.PreviousCandidateID != want.PreviousCandidateID || selection.SelectedAt != want.SelectedAt || selection.LastHealthyAt != want.LastHealthyAt || !selection.Frozen {
		t.Fatal("frozen manual intent lost")
	}
	for _, summary := range got.Summaries {
		if summary.Eligible {
			t.Fatal("legacy history became current route authority")
		}
	}
	if selection.Healthy {
		t.Fatal("legacy selection became current readiness")
	}
	if nativePairedRestoreFileHash(t, path) != draft.stateSHA {
		t.Fatal("read-only history projection changed durable state")
	}
}

func nativePairedPublicHistoryAfter(t *testing.T, draft *nativePairedDraft) {
	t.Helper()
	nativePairedHistoryReadback(t, draft)
	t.Log("actual_public_pair_retained_history preserved=true completed_probes=3 frozen_manual_selection=true original_old_http_writer=true current_reader=true legacy_readiness=false old_live_compatibility=false")
}
