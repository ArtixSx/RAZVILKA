// Command nodeeval compares node sources with the exact check the autopilot
// uses (connection, internet through the node, the service by name and IP).
// It runs beside the panel with its own store, port and state directory and
// changes nothing else. Development tool; not part of release packages.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

type line struct {
	Source    string `json:"source"`
	Node      string `json:"node"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
	Stage     string `json:"stage"`
	Verdict   string `json:"verdict"`
	Available bool   `json:"available"`
	Code      string `json:"code,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Seconds   int64  `json:"seconds"`
}

func main() {
	root := flag.String("root", "/opt/tmp/nodeeval", "private working directory")
	port := flag.Int("port", 19291, "loopback port of the temporary proxy")
	limit := flag.Int("limit", 30, "candidates per source")
	sources := flag.String("sources", "", "comma-separated preset:<id> or url:<https URL>")
	flag.Parse()
	if err := os.MkdirAll(filepath.Join(*root, "store"), 0o700); err != nil {
		log.Fatal(err)
	}
	store, err := nodestore.Open(filepath.Join(*root, "store"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	feeds := providerfeed.New(store)
	checker := dataplane.NewExactNodeChecker(filepath.Join(*root, "checker"))
	checker.Port = *port
	ctx := context.Background()
	profile, err := checker.FreshProfile(ctx)
	if err != nil {
		log.Fatal("network profile: ", err)
	}
	service := catalog.Service{ID: "custom-telegram-networks", Name: "Telegram", Domains: []string{"telegram.org", "t.me", "telegram.me"},
		CIDRs:    []string{"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/21", "91.108.16.0/21", "91.108.56.0/22", "95.161.64.0/20", "185.76.151.0/24"},
		Strategy: []string{"auto"}, ProbeURL: "https://telegram.org/"}
	out, err := os.OpenFile(filepath.Join(*root, "results.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	type tally struct{ total, connected, internet, service int }
	summary := map[string]*tally{}
	order := []string{}
	for _, spec := range strings.Split(*sources, ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		request := providerfeed.Request{Limit: *limit, AcceptPartial: true}
		name := spec
		switch {
		case strings.HasPrefix(spec, "preset:"):
			request.PresetID = strings.TrimPrefix(spec, "preset:")
		case strings.HasPrefix(spec, "url:"):
			request.URL, request.Format = strings.TrimPrefix(spec, "url:"), "uri-lines"
			name = request.URL[strings.LastIndex(request.URL, "/")+1:]
		default:
			log.Fatal("unknown source ", spec)
		}
		var result providerfeed.Result
		var err error
		for attempt := 0; attempt < 4; attempt++ {
			if result, err = feeds.Sync(ctx, request); err == nil {
				break
			}
			time.Sleep(5 * time.Second)
		}
		if err != nil {
			log.Printf("%s: fetch failed: %v (%s)", name, err, providerfeed.ErrorCode(err))
			continue
		}
		t := &tally{}
		summary[name] = t
		order = append(order, name)
		snapshot, err := store.Snapshot(ctx, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		protocols := map[string][2]string{}
		for _, n := range snapshot.Nodes {
			protocols[n.ID] = [2]string{n.Protocol, n.Transport}
		}
		log.Printf("%s: %d candidates (total %d, rejected %d)", name, len(result.NodeIDs), result.TotalEntries, result.Rejected)
		for _, id := range result.NodeIDs {
			started := time.Now()
			// The network epoch may change between checks; each check binds
			// to the epoch observed right before it.
			if fresh, err := checker.FreshProfile(ctx); err == nil {
				profile = fresh
			}
			var check dataplane.NodeCheckResult
			err := store.WithSecret(ctx, id, func(material []byte) error {
				var checkErr error
				check, checkErr = checker.Check(ctx, dataplane.NodeCheckRequest{NodeID: id, Outbound: material, Service: service, NetworkProfile: profile})
				return checkErr
			})
			if err != nil {
				check.ErrorCode = "check-error"
				log.Printf("%s %s: %v", name, id[5:17], err)
				// A failed cleanup fences the checker until its recovery ran.
				if recoverErr := checker.Recover(ctx); recoverErr != nil {
					log.Printf("recover: %v", recoverErr)
				}
			}
			entry := line{Source: name, Node: id[5:17], Protocol: protocols[id][0], Transport: protocols[id][1], Stage: check.Stage, Verdict: string(check.Verdict),
				Available: check.Available, Code: check.ErrorCode, LatencyMS: check.LatencyMS, Seconds: int64(time.Since(started).Seconds())}
			data, _ := json.Marshal(entry)
			_, _ = out.Write(append(data, '\n'))
			t.total++
			switch {
			case check.Available:
				t.connected++
				t.internet++
				t.service++
			case check.ErrorCode == "node-transport-failed" || check.ErrorCode == "node-runtime-config-rejected" || check.ErrorCode == "check-error":
			case check.ErrorCode == "node-egress-failed":
				t.connected++
			default:
				t.connected++
				t.internet++
			}
		}
		log.Printf("%s: checked %d, connected %d, internet %d, Telegram %d", name, t.total, t.connected, t.internet, t.service)
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := summary[order[i]], summary[order[j]]
		return a.service*b.total > b.service*a.total
	})
	fmt.Println("source\tchecked\tconnected\tinternet\ttelegram")
	for _, name := range order {
		t := summary[name]
		fmt.Printf("%s\t%d\t%d\t%d\t%d\n", name, t.total, t.connected, t.internet, t.service)
	}
}
