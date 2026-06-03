package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Option configures client initialization.
type Option func(*Client) error

// Client is a reusable Vaultwarden API client with token caching.
type Client struct {
	cfg        Config
	httpClient *http.Client
	tokenMu    sync.Mutex
	token      *Token
}

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) error {
		if httpClient == nil {
			return errors.New("custom HTTP client cannot be nil")
		}
		c.httpClient = httpClient
		return nil
	}
}

// NewClient creates a Vaultwarden client with validated configuration.
func NewClient(cfg Config, opts ...Option) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	normalizedCfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("normalize config: %w", err)
	}

	client := &Client{
		cfg: normalizedCfg,
		httpClient: &http.Client{
			Timeout: normalizedCfg.Timeout,
		},
	}

	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	if client.httpClient == nil {
		return nil, errors.New("HTTP client is required")
	}
	if client.httpClient.Timeout <= 0 {
		client.httpClient.Timeout = normalizedCfg.Timeout
	}

	return client, nil
}

// Authenticate obtains and caches a valid token.
func (c *Client) Authenticate(ctx context.Context) error {
	_, err := c.getValidToken(ctx)
	return err
}

// Do sends a JSON request with bearer authentication.
func (c *Client) Do(ctx context.Context, method, path string, requestBody any, responseBody any) error {
	if strings.TrimSpace(method) == "" {
		return errors.New("method is required")
	}
	if strings.TrimSpace(path) == "" {
		return errors.New("path is required")
	}

	endpoint, err := joinURLPath(c.cfg.BaseURL, path)
	if err != nil {
		return fmt.Errorf("build request URL: %w", err)
	}

	var payload []byte
	if requestBody != nil {
		payload, err = json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
	}

	token, err := c.getValidToken(ctx)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	err = c.doWithToken(ctx, method, endpoint, token.AccessToken, payload, responseBody)
	if err == nil {
		return nil
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		return err
	}

	token, refreshErr := c.forceRefreshToken(ctx)
	if refreshErr != nil {
		return fmt.Errorf("refresh access token after 401: %w", refreshErr)
	}

	return c.doWithToken(ctx, method, endpoint, token.AccessToken, payload, responseBody)
}

// Get performs a GET request.
func (c *Client) Get(ctx context.Context, path string, responseBody any) error {
	return c.Do(ctx, http.MethodGet, path, nil, responseBody)
}

// Post performs a POST request.
func (c *Client) Post(ctx context.Context, path string, requestBody any, responseBody any) error {
	return c.Do(ctx, http.MethodPost, path, requestBody, responseBody)
}

func (c *Client) doWithToken(ctx context.Context, method, endpoint, accessToken string, payload []byte, responseBody any) error {
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyLength*4))
		if readErr != nil {
			return fmt.Errorf("read error response: %w", readErr)
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Body:       sanitizeErrorBody(string(body)),
		}
	}

	if responseBody == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode response body: %w", err)
	}
	return nil
}
