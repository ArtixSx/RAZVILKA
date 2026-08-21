package profileexchange

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

const (
	Kind             = "razvilka-profile"
	Schema           = 1
	MaxBundleBytes   = 8 << 20
	MaxEngineFiles   = 32
	MaxEngineFileLen = 2 << 20
)

type EngineFile struct {
	EngineID string `json:"engine_id"`
	FileID   string `json:"file_id"`
	Content  string `json:"content"`
	SHA256   string `json:"sha256"`
}

type Omission struct {
	EngineID string `json:"engine_id"`
	FileID   string `json:"file_id"`
	Reason   string `json:"reason"`
}

// Bundle is deliberately portable and secret-free. Importers must always
// preview it and stage its contents; a profile is never authorization to write
// firewall, DNS, routes, or live engine configuration.
type Bundle struct {
	Kind             string                         `json:"kind"`
	Schema           int                            `json:"schema"`
	AppVersion       string                         `json:"app_version"`
	Name             string                         `json:"name"`
	Description      string                         `json:"description,omitempty"`
	Author           string                         `json:"author,omitempty"`
	CreatedAt        string                         `json:"created_at"`
	Services         map[string]config.ServiceState `json:"services"`
	CustomServices   []catalog.Service              `json:"custom_services,omitempty"`
	EngineFiles      []EngineFile                   `json:"engine_files,omitempty"`
	SensitiveOmitted []Omission                     `json:"sensitive_omitted,omitempty"`
	ContainsSecrets  bool                           `json:"contains_secrets"`
	Digest           string                         `json:"digest"`
}

func New(version, name, description, author string) Bundle {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Мой профиль RAZVILKA"
	}
	return Bundle{
		Kind: Kind, Schema: Schema, AppVersion: strings.TrimSpace(version), Name: name,
		Description: strings.TrimSpace(description), Author: strings.TrimSpace(author),
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Services: map[string]config.ServiceState{},
		ContainsSecrets: false,
	}
}

func Seal(bundle *Bundle) error {
	if bundle == nil {
		return errors.New("profile is nil")
	}
	bundle.Digest = ""
	data, err := canonical(*bundle)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	bundle.Digest = hex.EncodeToString(sum[:])
	return nil
}

func Validate(bundle Bundle) error {
	if bundle.Kind != Kind || bundle.Schema != Schema {
		return fmt.Errorf("unsupported profile kind or schema")
	}
	if bundle.ContainsSecrets {
		return errors.New("profiles marked as containing secrets are not accepted")
	}
	if len(strings.TrimSpace(bundle.Name)) == 0 || len(bundle.Name) > 120 {
		return errors.New("profile name must contain 1 to 120 characters")
	}
	if len(bundle.Description) > 1000 || len(bundle.Author) > 120 || len(bundle.AppVersion) > 32 {
		return errors.New("profile metadata is too long")
	}
	if _, err := time.Parse(time.RFC3339, bundle.CreatedAt); err != nil {
		return errors.New("profile created_at must use RFC3339")
	}
	if len(bundle.Services) > 512 || len(bundle.CustomServices) > 256 || len(bundle.EngineFiles) > MaxEngineFiles {
		return errors.New("profile item limit exceeded")
	}
	for id, state := range bundle.Services {
		if !validServiceID(id) {
			return fmt.Errorf("invalid service id %q", id)
		}
		route := state.Route
		if route == "" {
			route = state.Mode
		}
		if route == "" {
			route = "auto"
		}
		if !validPortableRoute(route) {
			return fmt.Errorf("service %q has invalid route %q", id, route)
		}
	}
	if err := validateCustomServices(bundle.CustomServices); err != nil {
		return err
	}
	seenFiles := map[string]bool{}
	for _, file := range bundle.EngineFiles {
		key := file.EngineID + "/" + file.FileID
		if file.EngineID == "" || file.FileID == "" || seenFiles[key] {
			return fmt.Errorf("invalid or duplicate engine file %q", key)
		}
		seenFiles[key] = true
		if len(file.Content) > MaxEngineFileLen || strings.IndexByte(file.Content, 0) >= 0 {
			return fmt.Errorf("engine file %q is too large or contains NUL", key)
		}
		if !strings.EqualFold(file.SHA256, Sum([]byte(file.Content))) {
			return fmt.Errorf("engine file %q checksum mismatch", key)
		}
	}
	if len(bundle.Digest) != sha256.Size*2 {
		return errors.New("profile digest is missing")
	}
	want := strings.ToLower(bundle.Digest)
	bundle.Digest = ""
	data, err := canonical(bundle)
	if err != nil {
		return err
	}
	got := Sum(data)
	if want != got {
		return errors.New("profile digest mismatch")
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	if len(encoded) > MaxBundleBytes {
		return fmt.Errorf("profile exceeds %d bytes", MaxBundleBytes)
	}
	return nil
}

func Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func canonical(bundle Bundle) ([]byte, error) {
	return json.Marshal(bundle)
}

func validateCustomServices(services []catalog.Service) error {
	for _, service := range services {
		if !strings.HasPrefix(service.ID, "custom-") {
			return fmt.Errorf("portable custom service %q must use custom- prefix", service.ID)
		}
	}
	if err := catalog.Validate(catalog.Catalog{Services: services}); err != nil {
		return fmt.Errorf("custom services: %w", err)
	}
	return nil
}

func validServiceID(id string) bool {
	if len(id) == 0 || len(id) > 64 || !((id[0] >= 'a' && id[0] <= 'z') || (id[0] >= '0' && id[0] <= '9')) {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validPortableRoute(id string) bool {
	options := []routecatalog.Option{
		{ID: "auto", Selectable: true}, {ID: "direct", Selectable: true},
		{ID: "nfqws2", Selectable: true}, {ID: "usque", Selectable: true},
		{ID: "warp-wg", Selectable: true}, {ID: "sing-box", Selectable: true},
		{ID: "xray", Selectable: true}, {ID: "amneziawg", Selectable: true},
	}
	return routecatalog.ValidWithOptions(id, options)
}
