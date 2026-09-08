package cloudflareprovider

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type registrationRoundTrip func(*http.Request) (*http.Response, error)

func (f registrationRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func consumerFixture(publicKey string) string {
	peer := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	return fmt.Sprintf(`{"id":"private-device-marker","token":"private-token-marker","key":%q,"key_type":"curve25519","tunnel_type":"wireguard","config":{"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:1234::2"}},"peers":[{"public_key":%q,"endpoint":{"v4":"162.159.192.1:2408","v6":"[2606:4700:d0::1]:2408"}}]}}`, publicKey, peer)
}

func TestConsumerRegistrationSendsOnlyPublicKeyAndParsesBoundCandidate(t *testing.T) {
	api := NewConsumerRegistrationAPI()
	calls := 0
	api.client.Transport = registrationRoundTrip(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.String() != consumerRegistrationURL || request.Header.Get("Authorization") != "" || request.Header.Get("CF-Client-Version") != "a-6.35-4471" || request.GetBody != nil {
			t.Fatalf("unexpected registration request: %s %s", request.Method, request.URL)
		}
		data, _ := io.ReadAll(request.Body)
		var fields map[string]string
		if json.Unmarshal(data, &fields) != nil || len(fields) != 10 || fields["key_type"] != "curve25519" || fields["tunnel_type"] != "wireguard" || len(fields["serial_number"]) != 16 || strings.Contains(string(data), "private") {
			t.Fatal("request shape or private-key boundary changed")
		}
		if _, err := time.Parse(time.RFC3339Nano, fields["tos"]); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(consumerFixture(fields["key"])))}, nil
	})
	candidate, err := (Registrar{API: api}).NewCandidate(context.Background(), true)
	if err != nil || calls != 1 {
		t.Fatalf("registration calls=%d err=%v", calls, err)
	}
	if candidate.Public().Verification != "registered-unverified" || len(candidate.Public().AssignedAddresses) != 2 {
		t.Fatalf("registration claimed connectivity or lost assigned addresses: %+v", candidate.Public())
	}
	data, _ := json.Marshal(candidate)
	if strings.Contains(string(data), "private-token-marker") || strings.Contains(fmt.Sprintf("%+v", candidate), "private-device-marker") {
		t.Fatal("candidate leaked API secrets")
	}
}

func TestConsumerRegistrationDoesNotRetryOrExposeErrorBodies(t *testing.T) {
	for _, status := range []int{302, 403, 429, 500, 200} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			api := NewConsumerRegistrationAPI()
			calls := 0
			api.client.Transport = registrationRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"60"}, "Location": []string{"https://other.example/"}}, Body: io.NopCloser(strings.NewReader("private-token-marker"))}, nil
			})
			_, err := (Registrar{API: api}).NewCandidate(context.Background(), true)
			var failure *RegistrationHTTPError
			if !errors.As(err, &failure) || calls != 1 || failure.HTTPStatus != status || strings.Contains(err.Error(), "private-token-marker") {
				t.Fatalf("unsafe failure calls=%d err=%v", calls, err)
			}
			if failure.Uncertain != (status == 500 || status == 200) {
				t.Fatalf("lost remote uncertainty: %+v", failure)
			}
		})
	}
}

func TestConsumerRegistrationRejectsTransportFailureAndOversizedOrMismatchedResponse(t *testing.T) {
	for _, mode := range []string{"transport", "oversized", "wrong-key", "wrong-transport", "private-endpoint"} {
		t.Run(mode, func(t *testing.T) {
			api := NewConsumerRegistrationAPI()
			api.client.Transport = registrationRoundTrip(func(request *http.Request) (*http.Response, error) {
				if mode == "transport" {
					return nil, errors.New("private-token-marker")
				}
				var fields map[string]string
				_ = json.NewDecoder(request.Body).Decode(&fields)
				body := consumerFixture(fields["key"])
				switch mode {
				case "oversized":
					body = strings.Repeat("x", maxConsumerResponse+1)
				case "wrong-key":
					body = consumerFixture(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32))))
				case "wrong-transport":
					body = strings.ReplaceAll(body, "wireguard", "masque")
				case "private-endpoint":
					body = strings.ReplaceAll(body, "162.159.192.1:2408", "127.0.0.1:2408")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			_, err := (Registrar{API: api}).NewCandidate(context.Background(), true)
			var failure *RegistrationHTTPError
			if !errors.As(err, &failure) || !failure.Uncertain || strings.Contains(err.Error(), "private-token-marker") {
				t.Fatalf("unsafe schema/network failure: %v", err)
			}
		})
	}
}

func TestConsumerRegistrationTermsAndCancellationPrecedeNetwork(t *testing.T) {
	api := NewConsumerRegistrationAPI()
	api.client.Transport = registrationRoundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network call"); return nil, nil })
	if _, err := (Registrar{API: api}).NewCandidate(context.Background(), false); !errors.Is(err, ErrRegistrationTerms) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Registrar{API: api}).NewCandidate(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestConsumerRecoveryUsesOriginalKeyAndIssuedPortsWithoutNetwork(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	body := strings.ReplaceAll(consumerFixture(public), `"v4":"162.159.192.1:2408","v6":"[2606:4700:d0::1]:2408"`, `"v4":"162.159.192.1:0","v6":"[2606:4700:d0::1]:0","ports":[2408,500,1701,4500]`)
	candidate, err := RecoverConsumerCandidate(key.Bytes(), []byte(body), time.Now())
	if err != nil || candidate.Public().Verification != "registered-unverified" || len(candidate.response.Endpoints) != 8 || candidate.response.Endpoints[0] != "162.159.192.1:2408" || candidate.response.Endpoints[7] != "[2606:4700:d0::1]:4500" {
		t.Fatalf("current API port list was not recovered: candidate=%+v err=%v", candidate.Public(), err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := RecoverConsumerCandidate(other.Bytes(), []byte(body), time.Now()); err == nil {
		t.Fatal("response was rebound to another private key")
	}
	for _, ports := range []string{"[]", "[0]", "[65536]", "[2408,2408]"} {
		bad := strings.ReplaceAll(body, "[2408,500,1701,4500]", ports)
		if _, err := RecoverConsumerCandidate(key.Bytes(), []byte(bad), time.Now()); err == nil {
			t.Fatalf("invalid issued ports accepted: %s", ports)
		}
	}
}

func TestRegistrarCheckpointFailurePreventsRemoteRequest(t *testing.T) {
	api := NewConsumerRegistrationAPI()
	api.client.Transport = registrationRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("private key was not durable before POST")
		return nil, nil
	})
	_, err := (Registrar{API: api, CheckpointKey: func(key []byte) error {
		if len(key) != 32 {
			t.Fatal("invalid key checkpoint")
		}
		return errors.New("private-path-marker")
	}}).NewCandidate(context.Background(), true)
	if !errors.Is(err, ErrRegistration) || strings.Contains(err.Error(), "private-path-marker") {
		t.Fatalf("unsafe checkpoint failure: %v", err)
	}
}
