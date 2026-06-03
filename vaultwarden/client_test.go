package vaultwarden

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticateSuccess(t *testing.T) {
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}
		tokenCalls.Add(1)
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("unexpected content type: %s", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("unexpected accept header: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"token-one","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL + "/",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
		Scope:        "api",
	})

	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatalf("unexpected auth error: %v", err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("expected 1 token call, got %d", tokenCalls.Load())
	}
	if client.token == nil || client.token.AccessToken != "token-one" {
		t.Fatalf("expected cached token")
	}
}

func TestAuthenticateTokenEndpoint400(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_client","client_secret":"super-secret","access_token":"raw-token"}`))
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected authentication error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", apiErr.StatusCode)
	}
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "raw-token") {
		t.Fatalf("error should not expose secrets: %v", err)
	}
}

func TestAuthenticateTokenEndpointEmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected authentication error")
	}
	if !strings.Contains(err.Error(), "empty token response body") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthenticateTokenEndpointInvalidJSONSanitized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`oops access_token=secret-token client_secret=secret-value`))
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	err := client.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected authentication error")
	}
	if !strings.Contains(err.Error(), "decode token response") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("error should be sanitized: %v", err)
	}
}

func TestAuthenticateTokenEndpointLargeSuccessBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"token-large","token_type":"Bearer","expires_in":3600,"filler":"` + strings.Repeat("x", 6000) + `"}`))
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatalf("unexpected authentication error: %v", err)
	}
}

func TestClientSecretRequired(t *testing.T) {
	_, err := NewClient(Config{
		BaseURL:   "https://vaultwarden.example",
		ClientID:  "client-id",
		GrantType: "client_credentials",
	})
	if err == nil {
		t.Fatal("expected config validation error")
	}
}

func TestExpiredTokenRefreshesBeforeRequest(t *testing.T) {
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"fresh-token","token_type":"Bearer","expires_in":3600}`))
		case "/api/sync":
			if got := r.Header.Get("Authorization"); got != "Bearer fresh-token" {
				t.Fatalf("unexpected authorization header: %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})
	client.token = &Token{
		AccessToken: "stale-token",
		TokenType:   "Bearer",
		ExpiresIn:   10,
		ObtainedAt:  time.Now().Add(-1 * time.Hour),
	}

	var response map[string]any
	if err := client.Get(context.Background(), "/api/sync", &response); err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("expected one refresh token call, got %d", tokenCalls.Load())
	}
}

func TestGetSendsBearerAuthorization(t *testing.T) {
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
		case "/api/sync":
			if got := r.Header.Get("Authorization"); got != "Bearer token-auth" {
				t.Fatalf("unexpected authorization header: %s", got)
			}
			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Fatalf("unexpected accept header: %s", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("unexpected content type: %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	var response map[string]any
	if err := client.Get(context.Background(), "/api/sync", &response); err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("expected one token call, got %d", tokenCalls.Load())
	}
}

func Test401TriggersSingleRefreshAndRetry(t *testing.T) {
	var tokenCalls atomic.Int32
	var apiCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			call := tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if call == 1 {
				w.Write([]byte(`{"access_token":"token-initial","token_type":"Bearer","expires_in":3600}`))
				return
			}
			w.Write([]byte(`{"access_token":"token-refreshed","token_type":"Bearer","expires_in":3600}`))
		case "/api/sync":
			call := apiCalls.Add(1)
			if call == 1 {
				if got := r.Header.Get("Authorization"); got != "Bearer token-initial" {
					t.Fatalf("unexpected first token: %s", got)
				}
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"expired_token"}`))
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer token-refreshed" {
				t.Fatalf("unexpected retried token: %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	var response map[string]any
	if err := client.Get(context.Background(), "/api/sync", &response); err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if apiCalls.Load() != 2 {
		t.Fatalf("expected one retry, got %d API calls", apiCalls.Load())
	}
	if tokenCalls.Load() != 2 {
		t.Fatalf("expected two token calls (initial+refresh), got %d", tokenCalls.Load())
	}
}

func TestAPIErrorSanitizesSensitiveData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
		case "/api/sync":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`client_secret=super-secret&access_token=internal-token`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	err := client.Get(context.Background(), "/api/sync", nil)
	if err == nil {
		t.Fatal("expected API error")
	}
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "internal-token") {
		t.Fatalf("error should be sanitized: %v", err)
	}
}

func TestListSecretsFromSync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
		case "/api/sync":
			if got := r.Header.Get("Authorization"); got != "Bearer token-auth" {
				t.Fatalf("unexpected authorization header: %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"ciphers":[
					{
						"id":"abc123",
						"name":"prod/db",
						"notes":"primary database",
						"login":{"username":"db-user","password":"db-pass"},
						"sshKey":{"publicKey":"ssh-pub","privateKey":"ssh-priv","fingerprint":"ssh-fp"},
						"card":{"cardholderName":"JOHN DOE","brand":"visa","number":"4111111111111111","expMonth":"12","expYear":"2030","code":"123"},
						"fields":[{"name":"host","value":"db.local"},{"name":"port","value":"5432"}]
					}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	secrets, err := client.ListSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected list secrets error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected one secret, got %d", len(secrets))
	}
	if secrets[0].Name != "prod/db" || secrets[0].Username != "db-user" || secrets[0].Password != "db-pass" {
		t.Fatalf("unexpected secret payload: %+v", secrets[0])
	}
	if secrets[0].SSHPublicKey != "ssh-pub" || secrets[0].SSHPrivateKey != "ssh-priv" || secrets[0].SSHFingerprint != "ssh-fp" {
		t.Fatalf("unexpected ssh payload: %+v", secrets[0])
	}
	if secrets[0].CardholderName != "JOHN DOE" || secrets[0].CardBrand != "visa" || secrets[0].CardNumber != "4111111111111111" {
		t.Fatalf("unexpected card payload: %+v", secrets[0])
	}
	if secrets[0].Fields["host"] != "db.local" || secrets[0].Fields["port"] != "5432" {
		t.Fatalf("unexpected secret fields: %+v", secrets[0].Fields)
	}
}

func TestListSecretsByOrganizationAndGetByID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
		case "/api/sync":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"ciphers":[
					{"id":"a1","organizationId":"org-1","name":"secret-a","login":{"username":"u1","password":"p1"},"fields":[]},
					{"id":"b2","organizationId":"org-2","name":"secret-b","login":{"username":"u2","password":"p2"},"fields":[]}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	list, err := client.ListSecretsByOrganization(context.Background(), "org-2")
	if err != nil {
		t.Fatalf("unexpected list by org error: %v", err)
	}
	if len(list) != 1 || list[0].ID != "b2" {
		t.Fatalf("unexpected org-filtered list: %+v", list)
	}

	secret, err := client.GetSecretByID(context.Background(), "a1")
	if err != nil {
		t.Fatalf("unexpected get by id error: %v", err)
	}
	if secret.ID != "a1" || secret.Username != "u1" {
		t.Fatalf("unexpected secret: %+v", secret)
	}

	_, err = client.GetSecretByID(context.Background(), "missing")
	if err == nil || !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got: %v", err)
	}
}

func TestAuthenticateIncludesDeviceAndUserParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}

		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		values, err := url.ParseQuery(string(rawBody))
		if err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		if got := values.Get("device_identifier"); got != "dev-123" {
			t.Fatalf("unexpected device_identifier: %s", got)
		}
		if got := values.Get("device_name"); got != "connector-cli" {
			t.Fatalf("unexpected device_name: %s", got)
		}
		if got := values.Get("device_type"); got != "21" {
			t.Fatalf("unexpected device_type: %s", got)
		}
		if got := values.Get("username"); got != "user@example.com" {
			t.Fatalf("unexpected username: %s", got)
		}
		if got := values.Get("password"); got != "my-password" {
			t.Fatalf("unexpected password")
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:          server.URL,
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		Username:         "user@example.com",
		Password:         "my-password",
		GrantType:        "password",
		DeviceIdentifier: "dev-123",
		DeviceName:       "connector-cli",
		DeviceType:       "21",
	})

	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatalf("unexpected auth error: %v", err)
	}
}

func TestAuthenticateUsesDefaultDeviceParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" {
			http.NotFound(w, r)
			return
		}

		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		values, err := url.ParseQuery(string(rawBody))
		if err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		if got := values.Get("device_identifier"); got != "govaultwarden" {
			t.Fatalf("unexpected default device_identifier: %s", got)
		}
		if got := values.Get("device_name"); got != "govaultwarden" {
			t.Fatalf("unexpected default device_name: %s", got)
		}
		if got := values.Get("device_type"); got != "21" {
			t.Fatalf("unexpected default device_type: %s", got)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:      server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})

	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatalf("unexpected auth error: %v", err)
	}
}

func newTestClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}
