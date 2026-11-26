// warp-candidate is a one-shot HIL tool. It never calls the application's
// Apply/Restore API or changes an existing provider enrollment.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	result, err := run(ctx, os.Args[1:])
	if result == nil {
		result = map[string]any{}
	}
	result["ok"] = err == nil
	if err != nil {
		result["error"] = err.Error()
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(result)
	if err != nil {
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) (map[string]any, error) {
	if len(args) == 0 {
		return nil, errors.New("command required: capabilities, generate-wg, recover-wg, export-wg, scan-wg, generate-masque, scan-masque")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("work-root", "", "absolute private candidate directory")
	accept := flags.Bool("accept-tos", false, "explicit Cloudflare application terms acceptance")
	allowRuntime := flags.Bool("allow-isolated-runtime", false, "allow only owned temporary candidate runtime")
	catalogPath := flags.String("catalog", "", "catalog file")
	serviceID := flags.String("service", "telegram", "catalog service ID")
	profilePath := flags.String("profile", "", "explicit candidate profile; defaults inside work-root")
	usque := flags.String("usque", "", "separate verified USQUE 4.2.1 binary")
	sha := flags.String("usque-sha256", "", "expected checksum of verified USQUE binary")
	mode := flags.String("mode", "both", "MASQUE h2, h3, or both")
	wg := flags.String("wg", "", "explicit WireGuard tool path")
	ip := flags.String("ip", "", "explicit iproute2 path")
	endpointIndex := flags.Int("endpoint-index", 0, "export one registrar-issued endpoint index")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return nil, errors.New("invalid arguments")
	}
	if args[0] == "capabilities" {
		return capabilities(ctx, *usque, *sha, *wg, *ip), nil
	}
	if !filepath.IsAbs(*root) || filepath.Clean(*root) == filepath.VolumeName(*root)+string(filepath.Separator) {
		return nil, errors.New("a dedicated absolute work-root is required")
	}
	switch args[0] {
	case "generate-wg":
		return generateWG(ctx, *root, *accept)
	case "recover-wg":
		return recoverWG(ctx, *root)
	case "export-wg":
		return exportWG(ctx, *root, *endpointIndex)
	case "scan-wg":
		if !*allowRuntime {
			return nil, errors.New("isolated runtime opt-in is required")
		}
		if runtime.GOOS != "linux" {
			return nil, errors.New("WireGuard scan requires Linux kernel WireGuard support")
		}
		if err := existingPrivateRoot(*root); err != nil {
			return nil, err
		}
		service, err := selectedService(*catalogPath, *serviceID)
		if err != nil {
			return nil, err
		}
		if *profilePath == "" {
			*profilePath = filepath.Join(*root, "wireguard.conf")
		}
		return scanWG(ctx, *root, *profilePath, *wg, *ip, service)
	case "generate-masque":
		return generateMasque(ctx, *root, *usque, *sha, *accept)
	case "scan-masque":
		if !*allowRuntime {
			return nil, errors.New("isolated runtime opt-in is required")
		}
		if err := existingPrivateRoot(*root); err != nil {
			return nil, err
		}
		service, err := selectedService(*catalogPath, *serviceID)
		if err != nil {
			return nil, err
		}
		if *profilePath == "" {
			*profilePath = filepath.Join(*root, "masque.json")
		}
		return scanMasque(ctx, *root, *profilePath, *usque, *sha, *mode, service)
	default:
		return nil, errors.New("unknown command")
	}
}

func generateWG(parent context.Context, root string, accepted bool) (map[string]any, error) {
	if !accepted {
		return nil, cloudflareprovider.ErrRegistrationTerms
	}
	if err := newPrivateRoot(root); err != nil {
		return nil, err
	}
	report := map[string]any{"transport": "wireguard", "state": "registration-requested", "api_schema": cloudflareprovider.ConsumerRegistrationVersion, "automatic_retry": false}
	if err := writePrivateJSON(filepath.Join(root, "registration.json"), report); err != nil {
		return report, err
	}
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	api := cloudflareprovider.NewConsumerRegistrationAPI()
	api.CheckpointResponse = func(data []byte) error {
		return writePrivate(filepath.Join(root, "registration-response.private.json"), data)
	}
	candidate, err := (cloudflareprovider.Registrar{API: api, CheckpointKey: func(key []byte) error { return writePrivate(filepath.Join(root, "wireguard-key.private.bin"), key) }}).NewCandidate(ctx, true)
	if err != nil {
		report["state"] = "remote-creation-uncertain"
		var failure *cloudflareprovider.RegistrationHTTPError
		if errors.As(err, &failure) {
			report["http"] = failure
			if !failure.Uncertain {
				report["state"] = "registration-rejected"
			}
		}
		_ = writePrivateJSON(filepath.Join(root, "registration-result.json"), report)
		return report, err
	}
	return persistWG(ctx, root, candidate, report, "registration-result.json")
}

func persistWG(ctx context.Context, root string, candidate cloudflareprovider.RegistrationCandidate, report map[string]any, resultFile string) (map[string]any, error) {
	report["state"] = "remote-created-local-uncommitted"
	storePath := filepath.Join(root, "provider")
	if err := os.Mkdir(storePath, 0o700); err != nil {
		return report, errors.New("create candidate store")
	}
	store, err := cloudflareprovider.OpenStore(storePath)
	if err != nil {
		return report, err
	}
	defer store.Close()
	account, err := store.ImportCandidate(ctx, candidate)
	if err != nil {
		return report, err
	}
	report["account_id"] = account.ID
	err = store.WithWireGuardCandidate(ctx, account.ID, cloudflareprovider.CandidateOptions{}, func(_ context.Context, candidate cloudflareprovider.WireGuardCandidate) error {
		var config bytes.Buffer
		if err := candidate.WriteConfig(&config); err != nil {
			return err
		}
		defer wipe(config.Bytes())
		return writePrivate(filepath.Join(root, "wireguard.conf"), config.Bytes())
	})
	if err != nil {
		return report, err
	}
	report["state"] = "registered-unverified"
	report["profile_file"] = "wireguard.conf"
	if err := writePrivateJSON(filepath.Join(root, resultFile), report); err != nil {
		return report, err
	}
	return report, nil
}

func recoverWG(ctx context.Context, root string) (map[string]any, error) {
	if err := existingPrivateRoot(root); err != nil {
		return nil, err
	}
	key, err := readPrivate(filepath.Join(root, "wireguard-key.private.bin"))
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	response, err := readPrivate(filepath.Join(root, "registration-response.private.json"))
	if err != nil {
		return nil, err
	}
	defer wipe(response)
	candidate, err := cloudflareprovider.RecoverConsumerCandidate(key, response, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return persistWG(ctx, root, candidate, map[string]any{"transport": "wireguard", "network_requests": 0, "recovered_local_checkpoint": true}, "recovery-result.json")
}

func exportWG(ctx context.Context, root string, index int) (map[string]any, error) {
	if err := existingPrivateRoot(root); err != nil {
		return nil, err
	}
	if index < 0 || index > 15 {
		return nil, errors.New("invalid endpoint index")
	}
	store, err := cloudflareprovider.OpenStore(filepath.Join(root, "provider"))
	if err != nil {
		return nil, err
	}
	defer store.Close()
	accounts, err := store.List(ctx)
	if err != nil || len(accounts) != 1 {
		return nil, errors.New("candidate work-root must contain exactly one generated account")
	}
	name := "wireguard-endpoint-" + strconv.Itoa(index) + ".conf"
	out := map[string]any{"transport": "wireguard", "profile_file": name, "endpoint_index": index, "network_requests": 0}
	err = store.WithWireGuardCandidate(ctx, accounts[0].ID, cloudflareprovider.CandidateOptions{EndpointIndex: index}, func(_ context.Context, candidate cloudflareprovider.WireGuardCandidate) error {
		var config bytes.Buffer
		if err := candidate.WriteConfig(&config); err != nil {
			return err
		}
		defer wipe(config.Bytes())
		out["endpoint"] = candidate.Public().Endpoint
		return writePrivate(filepath.Join(root, name), config.Bytes())
	})
	return out, err
}

func scanWG(parent context.Context, root, profilePath, wg, ip string, service catalog.Service) (map[string]any, error) {
	profile, err := readPrivate(profilePath)
	if err != nil {
		return nil, err
	}
	defer wipe(profile)
	ctx, cancel := context.WithTimeout(parent, 110*time.Second)
	defer cancel()
	network, err := systemprobe.FreshWANProfile(ctx)
	if err != nil || !systemprobe.ValidWANProfileID(network.ID) {
		return nil, errors.New("current WAN epoch is unavailable")
	}
	adapter := dataplane.NewWARPWireGuardAdapter(nil, root)
	adapter.WG, adapter.IP = wg, ip
	runner := dataplane.NewCloudflareScanRunner(adapter, filepath.Join(root, "wg-scan"), []catalog.Service{service})
	scanner := cloudflareprovider.Scanner{Runner: runner}
	report, scanErr := scanner.ScanReviewedWireGuard(ctx, profile, true, cloudflareprovider.ScanOptions{ServiceID: service.ID, Attempts: 2, AttemptTimeout: 40 * time.Second})
	current, err := systemprobe.FreshWANProfile(ctx)
	if err != nil || current.ID != network.ID {
		report.Verified = false
		report.ValidUntil = time.Time{}
		report.ReasonCode = "network-profile-changed"
		scanErr = errors.New("WAN epoch changed during scan")
	}
	out := map[string]any{"transport": "wireguard", "network_profile_id": network.ID, "service_id": service.ID, "probe_scope": "primary-catalog-probe", "scan": report, "activation": false}
	if !report.Verified && scanErr == nil {
		scanErr = errors.New("candidate is not service-confirmed")
	}
	return out, scanErr
}

func selectedService(path, id string) (catalog.Service, error) {
	if path == "" {
		return catalog.Service{}, errors.New("catalog path is required")
	}
	cat, err := catalog.Load(path)
	if err != nil {
		return catalog.Service{}, errors.New("catalog is unavailable or invalid")
	}
	for _, service := range cat.Services {
		if service.ID == id && service.ProbeURL != "" {
			return service, nil
		}
	}
	return catalog.Service{}, errors.New("service has no catalog probe")
}

func newPrivateRoot(root string) error {
	if err := os.Mkdir(root, 0o700); err != nil {
		return errors.New("work-root must be new; inspect earlier registration before retrying")
	}
	return existingPrivateRoot(root)
}

func existingPrivateRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("work-root is not a private directory")
	}
	return nil
}

func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create private candidate artifact")
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("persist private candidate artifact")
	}
	return nil
}

func writePrivateJSON(path string, data any) error {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.New("encode candidate report")
	}
	return writePrivate(path, encoded)
}

func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > cloudflareprovider.MaxImportBytes || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("candidate profile is not a bounded private regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read candidate profile")
	}
	return data, nil
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
