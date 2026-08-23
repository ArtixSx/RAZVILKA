package privatebackup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/devices"
)

const (
	EnvelopeKind   = "razvilka-private-backup"
	PayloadKind    = "razvilka-private-state"
	Schema         = 1
	KDF            = "pbkdf2-hmac-sha256"
	KDFIterations  = 310000
	MaxPayload     = 8 << 20
	MaxEnvelope    = 9 << 20
	MaxEngineFiles = 64
)

type EngineFile struct {
	EngineID  string `json:"engine_id"`
	FileID    string `json:"file_id"`
	Content   string `json:"content"`
	SHA256    string `json:"sha256"`
	Sensitive bool   `json:"sensitive"`
}

type Payload struct {
	Kind           string                         `json:"kind"`
	Schema         int                            `json:"schema"`
	AppVersion     string                         `json:"app_version"`
	CreatedAt      string                         `json:"created_at"`
	Services       map[string]config.ServiceState `json:"services"`
	EngineOrder    []string                       `json:"engine_order"`
	CustomServices []catalog.Service              `json:"custom_services,omitempty"`
	EngineFiles    []EngineFile                   `json:"engine_files,omitempty"`
	Devices        []devices.Device               `json:"devices,omitempty"`
	Digest         string                         `json:"digest"`
}

type Envelope struct {
	Kind       string `json:"kind"`
	Schema     int    `json:"schema"`
	AppVersion string `json:"app_version"`
	CreatedAt  string `json:"created_at"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Cipher     string `json:"cipher"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func NewPayload(version string) Payload {
	return Payload{Kind: PayloadKind, Schema: Schema, AppVersion: strings.TrimSpace(version), CreatedAt: time.Now().UTC().Format(time.RFC3339), Services: map[string]config.ServiceState{}}
}

func Seal(payload *Payload) error {
	if payload == nil {
		return errors.New("private backup payload is nil")
	}
	payload.Digest = ""
	data, err := json.Marshal(*payload)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	payload.Digest = hex.EncodeToString(digest[:])
	return Validate(*payload)
}

func Validate(payload Payload) error {
	if payload.Kind != PayloadKind || payload.Schema != Schema {
		return errors.New("unsupported private backup payload")
	}
	if len(payload.AppVersion) == 0 || len(payload.AppVersion) > 32 {
		return errors.New("invalid backup application version")
	}
	if _, err := time.Parse(time.RFC3339, payload.CreatedAt); err != nil {
		return errors.New("invalid backup creation time")
	}
	if len(payload.Services) > 512 || len(payload.CustomServices) > 256 || len(payload.EngineFiles) > MaxEngineFiles || len(payload.Devices) > 512 {
		return errors.New("private backup item limit exceeded")
	}
	for id, state := range payload.Services {
		if !validID(id) {
			return fmt.Errorf("invalid service id %q", id)
		}
		if _, err := config.NormalizeSources(state.Sources); err != nil {
			return fmt.Errorf("service %s: %w", id, err)
		}
		if !validRoute(firstNonEmpty(state.Route, state.Mode, "auto")) {
			return fmt.Errorf("service %s has an invalid route", id)
		}
	}
	if len(payload.EngineOrder) > 16 {
		return errors.New("engine order is too long")
	}
	for _, route := range payload.EngineOrder {
		if !validRoute(route) || route == "auto" || route == "direct" {
			return fmt.Errorf("invalid engine order route %q", route)
		}
	}
	if len(payload.CustomServices) > 0 {
		for _, service := range payload.CustomServices {
			if !strings.HasPrefix(service.ID, "custom-") {
				return fmt.Errorf("private custom service %q must use custom- prefix", service.ID)
			}
		}
		if err := catalog.Validate(catalog.Catalog{Services: payload.CustomServices}); err != nil {
			return fmt.Errorf("custom services: %w", err)
		}
	}
	seen := map[string]bool{}
	total := 0
	for _, file := range payload.EngineFiles {
		key := file.EngineID + "/" + file.FileID
		if !validID(file.EngineID) || !validFileID(file.FileID) || seen[key] {
			return fmt.Errorf("invalid or duplicate engine file %q", key)
		}
		seen[key] = true
		if len(file.Content) > 2<<20 || strings.IndexByte(file.Content, 0) >= 0 {
			return fmt.Errorf("engine file %q is too large or contains NUL", key)
		}
		total += len(file.Content)
		if !strings.EqualFold(file.SHA256, Sum([]byte(file.Content))) {
			return fmt.Errorf("engine file %q checksum mismatch", key)
		}
	}
	if total > MaxPayload {
		return errors.New("private backup engine data exceeds safety limit")
	}
	if len(payload.Digest) != sha256.Size*2 {
		return errors.New("private backup digest is missing")
	}
	want := strings.ToLower(payload.Digest)
	payload.Digest = ""
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if Sum(data) != want {
		return errors.New("private backup digest mismatch")
	}
	if len(data) > MaxPayload {
		return errors.New("private backup payload is too large")
	}
	return nil
}

func Encrypt(payload Payload, password string) (Envelope, error) {
	if err := Validate(payload); err != nil {
		return Envelope{}, err
	}
	if err := validatePassword(password); err != nil {
		return Envelope{}, err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	salt := make([]byte, 24)
	if _, err := rand.Read(salt); err != nil {
		return Envelope{}, err
	}
	key := pbkdf2SHA256([]byte(password), salt, KDFIterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{Kind: EnvelopeKind, Schema: Schema, AppVersion: payload.AppVersion, CreatedAt: payload.CreatedAt, KDF: KDF, Iterations: KDFIterations, Cipher: "aes-256-gcm", Salt: base64.RawStdEncoding.EncodeToString(salt), Nonce: base64.RawStdEncoding.EncodeToString(nonce)}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(envelopeAAD(envelope)))
	envelope.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
	return envelope, nil
}

func Decrypt(envelope Envelope, password string) (Payload, error) {
	if err := validateEnvelope(envelope); err != nil {
		return Payload{}, err
	}
	if err := validatePassword(password); err != nil {
		return Payload{}, err
	}
	salt, _ := base64.RawStdEncoding.DecodeString(envelope.Salt)
	nonce, _ := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	ciphertext, _ := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	key := pbkdf2SHA256([]byte(password), salt, envelope.Iterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Payload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Payload{}, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(envelopeAAD(envelope)))
	if err != nil {
		return Payload{}, errors.New("wrong password or damaged private backup")
	}
	if len(plaintext) > MaxPayload {
		return Payload{}, errors.New("decrypted private backup is too large")
	}
	var payload Payload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return Payload{}, errors.New("invalid decrypted private backup")
	}
	if payload.AppVersion != envelope.AppVersion || payload.CreatedAt != envelope.CreatedAt {
		return Payload{}, errors.New("private backup metadata authentication failed")
	}
	if err := Validate(payload); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.Kind != EnvelopeKind || envelope.Schema != Schema || envelope.KDF != KDF || envelope.Cipher != "aes-256-gcm" {
		return errors.New("unsupported private backup envelope")
	}
	if envelope.Iterations < 200000 || envelope.Iterations > 1000000 {
		return errors.New("unsafe private backup KDF parameters")
	}
	if _, err := time.Parse(time.RFC3339, envelope.CreatedAt); err != nil || len(envelope.AppVersion) == 0 || len(envelope.AppVersion) > 32 {
		return errors.New("invalid private backup metadata")
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(envelope.Salt)
	nonce, nonceErr := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	ciphertext, ciphertextErr := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if saltErr != nil || nonceErr != nil || ciphertextErr != nil || len(salt) < 16 || len(nonce) != 12 || len(ciphertext) < 16 || len(ciphertext) > MaxEnvelope {
		return errors.New("invalid private backup cryptographic fields")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 12 || len(password) > 256 {
		return errors.New("private backup password must contain 12 to 256 characters")
	}
	return nil
}

func envelopeAAD(envelope Envelope) string {
	return strings.Join([]string{envelope.Kind, fmt.Sprint(envelope.Schema), envelope.AppVersion, envelope.CreatedAt, envelope.KDF, fmt.Sprint(envelope.Iterations), envelope.Cipher}, "\x00")
}

func pbkdf2SHA256(password, salt []byte, iterations, length int) []byte {
	result := make([]byte, 0, length)
	var blockIndex uint32 = 1
	for len(result) < length {
		message := make([]byte, len(salt)+4)
		copy(message, salt)
		message[len(salt)] = byte(blockIndex >> 24)
		message[len(salt)+1] = byte(blockIndex >> 16)
		message[len(salt)+2] = byte(blockIndex >> 8)
		message[len(salt)+3] = byte(blockIndex)
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(message)
		u := mac.Sum(nil)
		block := append([]byte(nil), u...)
		for index := 1; index < iterations; index++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for offset := range block {
				block[offset] ^= u[offset]
			}
		}
		result = append(result, block...)
		blockIndex++
	}
	return result[:length]
}

func Sum(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func validRoute(route string) bool {
	switch route {
	case "auto", "direct", "nfqws2", "usque", "warp-wg", "sing-box", "xray", "amneziawg":
		return true
	default:
		return false
	}
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' && index > 0 {
			continue
		}
		return false
	}
	return true
}

func validFileID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
