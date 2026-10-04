package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

const inactiveFixtureRules = "0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"
const inactiveFixtureSocketHeader = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

type inactiveFixtureProcesses struct{ calls int }

func (p *inactiveFixtureProcesses) Start(context.Context, ProcessSpec) error { p.calls++; return nil }
func (p *inactiveFixtureProcesses) Stop(context.Context, ProcessSpec) error  { p.calls++; return nil }
func (p *inactiveFixtureProcesses) Running(ProcessSpec) bool                 { p.calls++; return false }

type inactiveFixtureRunner struct {
	t        *testing.T
	seen     []string
	rules    map[int]string
	routes   map[int]string
	fw       map[string]string
	hook     func()
	readHook func(string, []string)
	err      error
}

func (r *inactiveFixtureRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	r.t.Helper()
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > proxyInactiveBudget+time.Millisecond {
		r.t.Fatal("unbounded inactivity command")
	}
	key := command + " " + strings.Join(args, " ")
	r.seen = append(r.seen, key)
	if r.readHook != nil {
		r.readHook(command, args)
	}
	if r.hook != nil {
		hook := r.hook
		r.hook = nil
		hook()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.err != nil {
		return nil, r.err
	}
	if command == "ip" {
		if len(args) == 0 || args[0] != "-N" {
			r.t.Fatal("non-numeric RPDB inspection", key)
		}
		family, plain := 4, args[1:]
		if len(plain) > 0 && plain[0] == "-6" {
			family, plain = 6, plain[1:]
		}
		if reflect.DeepEqual(plain, []string{"rule", "show"}) {
			return []byte(r.rules[family]), nil
		}
		if len(plain) == 4 && reflect.DeepEqual(plain[:3], []string{"route", "show", "table"}) {
			return []byte(r.routes[family]), nil
		}
	} else if command == "iptables" || command == "ip6tables" {
		if len(args) == 3 && args[0] == "-t" && args[2] == "-S" {
			if output, set := r.fw[command+"/"+args[1]]; set {
				return []byte(output), nil
			}
			parent := "FORWARD"
			if args[1] == "nat" {
				parent = "POSTROUTING"
			}
			return []byte("-P " + parent + " ACCEPT\n"), nil
		}
	}
	r.t.Fatal("unexpected or mutating inactivity command", key)
	return nil, ErrProxyRuntimeInactive
}

type inactiveFixture struct {
	a         *ProxyTunnelAdapter
	proof     proxyInactiveProof
	runner    *inactiveFixtureRunner
	processes *inactiveFixtureProcesses
}

func newInactiveFixture(t *testing.T, engine string) *inactiveFixture {
	t.Helper()
	base := privateScopedXrayFixtureDir(t)
	a, err := NewProxyTunnelAdapter(engine, engineconfig.New(filepath.Join(base, "stage"), filepath.Join(base, "backup")), filepath.Join(base, "state"))
	if err != nil {
		t.Fatal(err)
	}
	a.EngineBin, a.SidecarBin, a.IP, a.IPTables, a.IP6Tables = "fixture-engine", "fixture-sidecar", "ip", "iptables", "ip6tables"
	a.bootIdentity = func() (string, error) { return "inactive-fixture-boot", nil }
	processes := &inactiveFixtureProcesses{}
	runner := &inactiveFixtureRunner{t: t, rules: map[int]string{4: inactiveFixtureRules, 6: inactiveFixtureRules}, routes: map[int]string{}, fw: map[string]string{}}
	a.Processes, a.Runner = processes, runner
	proof := proxyInactiveProof{procRoot: filepath.Join(base, "proc"), selfPID: 123,
		readlink: func(path string) (string, error) { data, err := os.ReadFile(path); return string(data), err },
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 1, Name: "lo"}, {Index: 2, Name: "eth0"}}, nil
		}}
	f := &inactiveFixture{a: a, proof: proof, runner: runner, processes: processes}
	f.writeProcess(t, proof.selfPID, "S", "0", "fixture-controller\x00--serve\x00")
	for _, kind := range []string{"tcp", "tcp6"} {
		inactiveWrite(t, filepath.Join(proof.procRoot, "net", kind), []byte(inactiveFixtureSocketHeader))
	}
	return f
}

func inactiveWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *inactiveFixture) writeProcess(t *testing.T, pid int, state, flags, argv string) {
	t.Helper()
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[6], fields[19] = state, flags, "12345"
	path := filepath.Join(f.proof.procRoot, strconv.Itoa(pid))
	inactiveWrite(t, filepath.Join(path, "stat"), []byte(fmt.Sprintf("%d (fixture) %s\n", pid, strings.Join(fields, " "))))
	inactiveWrite(t, filepath.Join(path, "cmdline"), []byte(argv))
	inactiveWrite(t, filepath.Join(path, "exe"), []byte("/fixture/"+strings.Split(argv, "\x00")[0]))
}

func (f *inactiveFixture) receipt(t *testing.T, schema int, state string) (string, policyAdditionDocument) {
	t.Helper()
	id := strings.Repeat("a", 32)
	path, err := f.a.policyGenerationRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	doc := policyAdditionDocument{Schema: schema, ID: id, Boot: "inactive-fixture-boot", RootHash: policyAdditionRootHash(path), Phase: "active",
		Steps: []policyAdditionStep{{Add: []string{"route", "add", "default"}, Delete: []string{"route", "del", "default"}, State: state}}}
	if schema == 1 {
		doc.PolicyHash = routeidentity.Hash([]byte("fixture-policy"))
	} else {
		doc.Generation, doc.EffectsHash = routeidentity.Hash([]byte("fixture-generation")), routeidentity.Hash([]byte("fixture-effects"))
		doc.Steps[0].Tool = PolicyEffectIP
	}
	inactiveWrite(t, filepath.Join(path, policyAdditionLock), []byte(policyAdditionMarker))
	f.writeReceipt(t, path, doc)
	return path, doc
}

func (f *inactiveFixture) writeReceipt(t *testing.T, path string, doc policyAdditionDocument) {
	t.Helper()
	doc.Checksum = policyAdditionChecksum(doc)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	inactiveWrite(t, filepath.Join(path, policyAdditionFile), raw)
}

func TestProxyRuntimeInactiveFreshNegativeInventories(t *testing.T) {
	for _, engine := range []string{"usque", "sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			f := newInactiveFixture(t, engine)
			// Successful Deactivate of an unused adapter supplies no evidence.
			if err := f.a.Deactivate(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); err != nil {
				t.Fatal(err)
			}
			if f.processes.calls != 0 || len(f.runner.seen) != 20 {
				t.Fatal("process-controller history or missing readback", f.processes.calls, f.runner.seen)
			}
			if _, err := os.Lstat(f.a.StateRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("observer created runtime metadata", err)
			}
		})
	}
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprintf("removed-schema-%d", schema), func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			path, _ := f.receipt(t, schema, "removed")
			before, _ := os.ReadFile(filepath.Join(path, policyAdditionFile))
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(path, policyAdditionFile))
			if string(before) != string(after) || f.processes.calls != 0 {
				t.Fatal("observer changed history or consulted process boolean")
			}
		})
	}
	t.Run("restoration-generation-has-independent-receipt-id", func(t *testing.T) {
		f := newInactiveFixture(t, "sing-box")
		path, doc := f.receipt(t, 1, "removed")
		// applyRetainedPolicy allocates its directory before the addition writer
		// allocates the independent receipt ID; only the anchored root must match.
		doc.ID = strings.Repeat("b", 32)
		f.writeReceipt(t, path, doc)
		if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); err != nil {
			t.Fatal("rejected settled restored generation", err)
		}
	})
}

func TestProxyRuntimeInactiveRefusesProcessAndMissingProof(t *testing.T) {
	for _, mode := range []string{"engine-without-pid", "foreign-exe-owned-config", "option-owned-config", "empty-live-argv", "malformed-stat", "missing-stat", "empty-inventory", "missing-self", "missing-exe", "exe-owned-with-fake-argv", "foreign-engine-config", "canary-config", "canary-listener4", "canary-listener6", "missing-tcp6", "malformed-sockets", "listener4", "listener6", "empty-interfaces", "interface-error", "foreign-tun"} {
		t.Run(mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			self := filepath.Join(f.proof.procRoot, strconv.Itoa(f.proof.selfPID))
			switch mode {
			case "engine-without-pid", "foreign-exe-owned-config", "option-owned-config":
				arg := f.a.engineConfigPath()
				if mode == "option-owned-config" {
					arg = "--config=" + f.a.sidecarConfigPath()
				}
				f.writeProcess(t, 456, "S", "0", "arbitrary-foreign-executable\x00"+arg+"\x00")
			case "empty-live-argv":
				f.writeProcess(t, 456, "S", "0", "")
			case "foreign-engine-config":
				f.writeProcess(t, 456, "S", "0", "fixture-engine\x00--config=/foreign/config.json\x00")
			case "exe-owned-with-fake-argv":
				f.writeProcess(t, 456, "S", "0", "changed-argv\x00")
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "456", "exe"), []byte("/fixture/fixture-engine (deleted)"))
			case "canary-config":
				canary := filepath.Join(filepath.Dir(f.a.StateRoot), "transactions", "dp-0123456789abcdef", f.a.ID(), "canary", "engine.json")
				f.writeProcess(t, 456, "S", "0", "foreign-binary\x00-config\x00"+canary+"\x00")
			case "malformed-stat":
				inactiveWrite(t, filepath.Join(self, "stat"), []byte("unknown"))
			case "missing-stat":
				if err := os.Remove(filepath.Join(self, "stat")); err != nil {
					t.Fatal(err)
				}
			case "missing-exe":
				if err := os.Remove(filepath.Join(self, "exe")); err != nil {
					t.Fatal(err)
				}
			case "empty-inventory", "missing-self":
				if err := os.RemoveAll(self); err != nil {
					t.Fatal(err)
				}
				if mode == "missing-self" {
					f.writeProcess(t, 456, "S", "0", "unrelated\x00")
				}
			case "missing-tcp6":
				if err := os.Remove(filepath.Join(f.proof.procRoot, "net", "tcp6")); err != nil {
					t.Fatal(err)
				}
			case "malformed-sockets":
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "net", "tcp"), []byte(""))
			case "listener4", "listener6", "canary-listener4", "canary-listener6":
				kind, address := "tcp", "0100007F"
				remote := "00000000"
				if strings.HasSuffix(mode, "6") {
					kind, address, remote = "tcp6", strings.Repeat("0", 32), strings.Repeat("0", 32)
				}
				port := f.a.SOCKSPort
				if strings.HasPrefix(mode, "canary-") {
					var err error
					port, err = f.a.canaryPort()
					if err != nil {
						t.Fatal(err)
					}
				}
				row := fmt.Sprintf("0: %s:%04X %s:0000 0A 0:0 0:0 0 0 0 123\n", address, port, remote)
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "net", kind), []byte(inactiveFixtureSocketHeader+row))
			case "empty-interfaces":
				f.proof.interfaces = func() ([]net.Interface, error) { return nil, nil }
			case "interface-error":
				f.proof.interfaces = func() ([]net.Interface, error) { return nil, errors.New("unavailable") }
			case "foreign-tun":
				f.proof.interfaces = func() ([]net.Interface, error) {
					return []net.Interface{{Index: 1, Name: "lo"}, {Index: 3, Name: f.a.Interface}}, nil
				}
			}
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) {
				t.Fatal("accepted missing/foreign proof", err)
			}
			if f.processes.calls != 0 || len(f.runner.seen) != 0 {
				t.Fatal("inspection passed an earlier missing proof", f.processes.calls, f.runner.seen)
			}
		})
	}
}

func TestProxyRuntimeInactiveControllerRootArgumentAndKernelThreads(t *testing.T) {
	f := newInactiveFixture(t, "xray")
	f.writeProcess(t, f.proof.selfPID, "S", "0", "fixture-controller\x00--dataplane-state="+filepath.Dir(f.a.StateRoot)+"\x00")
	f.writeProcess(t, 456, "I", "2097152", "")
	f.writeProcess(t, 457, "Z", "0", "")
	if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); err != nil {
		t.Fatal("controller state argument or nonrunning kernel task acquired runtime ownership", err)
	}
}

func TestProxyRuntimeInactiveBoundedUnknownInventory(t *testing.T) {
	for _, mode := range []string{"argv-bytes", "argv-count", "stat-bytes", "socket-bytes", "socket-lines", "proc-entries", "schema-args"} {
		t.Run(mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			switch mode {
			case "argv-bytes":
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "123", "cmdline"), []byte(strings.Repeat("x", (64<<10)+1)))
			case "argv-count":
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "123", "cmdline"), []byte(strings.Repeat("x\x00", 257)))
			case "stat-bytes":
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "123", "stat"), []byte(strings.Repeat("x", (16<<10)+1)))
			case "socket-bytes":
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "net", "tcp"), []byte(strings.Repeat("x", (1<<20)+1)))
			case "socket-lines":
				inactiveWrite(t, filepath.Join(f.proof.procRoot, "net", "tcp"), []byte(inactiveFixtureSocketHeader+strings.Repeat("\n", 8193)))
			case "proc-entries":
				for i := 0; i < 8193; i++ {
					if err := os.WriteFile(filepath.Join(f.proof.procRoot, fmt.Sprintf("nonpid-%d", i)), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "schema-args":
				path, doc := f.receipt(t, 2, "removed")
				doc.Steps[0].Add = make([]string, maxPolicyEffectArgs+1)
				for i := range doc.Steps[0].Add {
					doc.Steps[0].Add[i] = "x"
				}
				f.writeReceipt(t, path, doc)
			}
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) {
				t.Fatal("accepted unbounded inventory", err)
			}
			if len(f.runner.seen) != 0 || f.processes.calls != 0 {
				t.Fatal("oversize proof passed early fence")
			}
		})
	}
}

func TestProxyRuntimeInactiveRefusesKernelOccupationAndUnknown(t *testing.T) {
	for _, mode := range []string{"legacy-slot", "shared-slot", "transit-slot", "table-reference", "alias", "unknown-selector", "empty-rpdb", "duplicate", "foreign-route4", "foreign-route6", "chain4", "chain6", "foreign-chain-reference", "unavailable-firewall", "command-error"} {
		t.Run(mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			switch mode {
			case "legacy-slot":
				f.runner.rules[4] += "24005: from all to 198.51.100.1 lookup 254\n"
			case "shared-slot":
				f.runner.rules[6] += "66: from all to 2001:4860::1 lookup 254\n"
			case "transit-slot":
				for _, owner := range NodeTransitOwnershipSpecs() {
					if owner.Engine == f.a.ID() {
						f.runner.rules[4] += fmt.Sprintf("%d: from all to 198.51.100.1 lookup 254\n", owner.Priority)
					}
				}
			case "table-reference":
				f.runner.rules[4] += "15000: from all to 198.51.100.1 lookup 204\n"
			case "alias":
				f.runner.rules[6] = "0: from all lookup local\n32766: from all lookup main\n"
			case "unknown-selector":
				f.runner.rules[4] += "100: from all goto 200\n"
			case "empty-rpdb":
				f.runner.rules[6] = ""
			case "duplicate":
				f.runner.rules[4] += "32766: from all lookup 254\n"
			case "foreign-route4":
				f.runner.routes[4] = "198.51.100.0/24 dev foreign0\n"
			case "foreign-route6":
				f.runner.routes[6] = "default dev foreign0\n"
			case "chain4":
				f.runner.fw["iptables/filter"] = "-P FORWARD ACCEPT\n-N " + f.a.forwardingChain() + "\n"
			case "chain6":
				f.runner.fw["ip6tables/nat"] = "-P POSTROUTING ACCEPT\n-N " + f.a.forwardingChain() + "\n"
			case "foreign-chain-reference":
				f.runner.fw["iptables/nat"] = "-P POSTROUTING ACCEPT\n-A FOREIGN -j " + f.a.forwardingChain() + "\n"
			case "unavailable-firewall":
				f.runner.fw["ip6tables/filter"] = ""
			case "command-error":
				f.runner.err = errors.New("read failed")
			}
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) {
				t.Fatal("accepted occupied/unknown kernel", err)
			}
			if f.processes.calls != 0 {
				t.Fatal("observer consulted Running or mutated process")
			}
		})
	}
}

func TestProxyRuntimeInactiveRefusesRetainedRuntimeFiles(t *testing.T) {
	for _, name := range []string{"policy.json", "policy-generation.json", "forwarding.json", "transport.json", "runtime/engine.json", "runtime/sidecar.json", "runtime/nodes.json", "runtime/interface.json", "runtime/engine.pid", "runtime/sidecar.pid", "runtime/engine.pid" + routeidentity.ReceiptSuffix, "runtime/sidecar.pid" + routeidentity.ReceiptSuffix} {
		t.Run(name, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			inactiveWrite(t, filepath.Join(f.a.StateRoot, filepath.FromSlash(name)), []byte("{}"))
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) {
				t.Fatal("accepted retained file", err)
			}
			if len(f.runner.seen) != 0 || f.processes.calls != 0 {
				t.Fatal("retained runtime did not fence early")
			}
		})
	}
}

func TestProxyRuntimeInactiveRefusesUnknownGenerationWithoutMutation(t *testing.T) {
	for _, mode := range []string{"added", "intent", "cleanup-intent", "missing-receipt", "missing-lock", "corrupt", "boot", "promotion", "schema", "invalid-dag", "invalid-argv"} {
		t.Run(mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			path, doc := f.receipt(t, 2, "removed")
			switch mode {
			case "added", "intent", "cleanup-intent":
				doc.Steps[0].State = mode
			case "missing-receipt":
				if err := os.Remove(filepath.Join(path, policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "missing-lock":
				if err := os.Remove(filepath.Join(path, policyAdditionLock)); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				inactiveWrite(t, filepath.Join(path, policyAdditionFile), []byte("{}"))
			case "boot":
				doc.Boot = "previous-boot"
			case "promotion":
				doc.Phase = "promoted"
				doc.PromotionTarget = strings.Repeat("b", 64)
			case "schema":
				doc.Schema = 3
			case "invalid-dag":
				doc.Steps[0].Needs = []int{0}
			case "invalid-argv":
				doc.Steps[0].Add = []string{"illegal\x00argv"}
			}
			if mode != "missing-receipt" && mode != "missing-lock" && mode != "corrupt" {
				f.writeReceipt(t, path, doc)
			}
			before, beforeErr := os.ReadFile(filepath.Join(path, policyAdditionFile))
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) {
				t.Fatal("accepted unknown generation", err)
			}
			after, afterErr := os.ReadFile(filepath.Join(path, policyAdditionFile))
			if string(before) != string(after) || errors.Is(beforeErr, os.ErrNotExist) != errors.Is(afterErr, os.ErrNotExist) || len(f.runner.seen) != 0 || f.processes.calls != 0 {
				t.Fatal("unknown generation changed or kernel inspected")
			}
			if mode == "missing-lock" {
				if _, err := os.Lstat(filepath.Join(path, policyAdditionLock)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("observer recreated lock", err)
				}
			}
		})
	}
}

func TestProxyRuntimeInactiveClosesFileAndProcessReadWindow(t *testing.T) {
	for _, mode := range []string{"file", "process", "interface", "coordinates", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.runner.hook = func() {
				switch mode {
				case "file":
					inactiveWrite(t, f.a.policyBindingPath(), []byte("{}"))
				case "process":
					f.writeProcess(t, 456, "S", "0", "foreign\x00"+f.a.engineConfigPath()+"\x00")
				case "interface":
					f.proof.interfaces = func() ([]net.Interface, error) {
						return []net.Interface{{Index: 1, Name: "lo"}, {Index: 3, Name: f.a.Interface}}, nil
					}
				case "coordinates":
					f.a.Table++
				case "cancel":
					cancel()
				}
			}
			// Interface callbacks are copied into the private proof; capture a live
			// inventory separately to model the actual OS changing between reads.
			if mode == "interface" {
				changed := false
				f.proof.interfaces = func() ([]net.Interface, error) {
					if changed {
						return []net.Interface{{Index: 1, Name: "lo"}, {Index: 3, Name: f.a.Interface}}, nil
					}
					return []net.Interface{{Index: 1, Name: "lo"}}, nil
				}
				f.runner.hook = func() { changed = true }
			}
			if err := f.a.verifyRuntimeInactive(ctx, f.proof); !errors.Is(err, ErrProxyRuntimeInactive) {
				t.Fatal("accepted drift/cancel", err)
			}
			if f.processes.calls != 0 {
				t.Fatal("observer changed runtime")
			}
		})
	}
}

func TestProxyRuntimeInactiveClosesKernelReadWindow(t *testing.T) {
	for _, mode := range []string{"rule", "route", "chain"} {
		t.Run(mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			calls := 0
			f.proof.interfaces = func() ([]net.Interface, error) {
				calls++
				if calls == 2 {
					switch mode {
					case "rule":
						f.runner.rules[4] += "24001: from all to 198.51.100.1 lookup 254\n"
					case "route":
						f.runner.routes[6] = "default dev foreign0\n"
					case "chain":
						f.runner.fw["iptables/filter"] = "-P FORWARD ACCEPT\n-N " + f.a.forwardingChain() + "\n"
					}
				}
				return []net.Interface{{Index: 1, Name: "lo"}}, nil
			}
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) || calls != 2 {
				t.Fatal("accepted closing foreign kernel insertion", calls, err)
			}
		})
	}
	for _, mode := range []string{"own-table-reference", "unknown-row"} {
		t.Run("last-observed-rules-"+mode, func(t *testing.T) {
			f := newInactiveFixture(t, "xray")
			reads := 0
			f.runner.readHook = func(command string, args []string) {
				if command == "ip" && reflect.DeepEqual(args, []string{"-N", "rule", "show"}) {
					reads++
					if reads == 4 {
						if mode == "own-table-reference" {
							f.runner.rules[4] += "15000: from all to 198.51.100.1 lookup 204\n"
						} else {
							f.runner.rules[4] += "15000: from all goto 15010\n"
						}
					}
				}
			}
			if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) || reads != 4 {
				t.Fatal("forgot last observed own-table/unknown rule", reads, err)
			}
		})
	}
}

func TestProxyRuntimeInactiveCancelledAndUnsupportedNeverReadKernel(t *testing.T) {
	f := newInactiveFixture(t, "xray")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.a.verifyRuntimeInactive(ctx, f.proof); !errors.Is(err, context.Canceled) || len(f.runner.seen) != 0 {
		t.Fatal("cancel passed admission", err)
	}
	if runtime.GOOS != "linux" {
		if err := f.a.VerifyRuntimeInactive(context.Background()); !errors.Is(err, ErrProxyRuntimeInactive) || len(f.runner.seen) != 0 {
			t.Fatal("unsupported platform granted inactivity", err)
		}
	}
}
