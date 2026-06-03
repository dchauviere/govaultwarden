package vaultwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const tokenRefreshSkew = 30 * time.Second

// Token represents an OAuth2-like access token response.
type Token struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int       `json:"expires_in"`
	Scope       string    `json:"scope,omitempty"`
	ObtainedAt  time.Time `json:"-"`
}

// Expired reports whether a token is expired using an expiration skew.
func (t Token) Expired(skew time.Duration) bool {
	if strings.TrimSpace(t.AccessToken) == "" {
		return true
	}
	if t.ExpiresIn <= 0 || t.ObtainedAt.IsZero() {
		return true
	}
	return time.Now().Add(skew).After(t.ObtainedAt.Add(time.Duration(t.ExpiresIn) * time.Second))
}

func (c *Client) getValidToken(ctx context.Context) (*Token, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.token != nil && !c.token.Expired(tokenRefreshSkew) {
		return cloneToken(c.token), nil
	}

	token, err := c.requestToken(ctx)
	if err != nil {
		return nil, err
	}
	c.token = token
	return cloneToken(c.token), nil
}

func (c *Client) forceRefreshToken(ctx context.Context) (*Token, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	token, err := c.requestToken(ctx)
	if err != nil {
		return nil, err
	}
	c.token = token
	return cloneToken(c.token), nil
}

func (c *Client) requestToken(ctx context.Context) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", c.cfg.GrantType)
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	if c.cfg.Username != "" {
		form.Set("username", c.cfg.Username)
	}
	if c.cfg.Password != "" {
		form.Set("password", c.cfg.Password)
	}
	if c.cfg.Scope != "" {
		form.Set("scope", c.cfg.Scope)
	}
	if c.cfg.DeviceIdentifier != "" {
		form.Set("device_identifier", c.cfg.DeviceIdentifier)
	}
	if c.cfg.DeviceName != "" {
		form.Set("device_name", c.cfg.DeviceName)
	}
	if c.cfg.DeviceType != "" {
		form.Set("device_type", c.cfg.DeviceType)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyLength*4))
		if err != nil {
			return nil, fmt.Errorf("read token error response: %w", err)
		}
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       sanitizeErrorBody(string(body)),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil, fmt.Errorf("empty token response body")
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf(
			"decode token response: %w (content_type=%q body=%s)",
			err,
			resp.Header.Get("Content-Type"),
			sanitizeErrorBody(string(body)),
		)
	}

	token.AccessToken = strings.TrimSpace(token.AccessToken)
	token.TokenType = strings.TrimSpace(token.TokenType)
	token.Scope = strings.TrimSpace(token.Scope)
	token.ObtainedAt = time.Now().UTC()

	if token.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	if token.TokenType == "" {
		return nil, fmt.Errorf("token response missing token_type")
	}
	if token.ExpiresIn <= 0 {
		return nil, fmt.Errorf("token response missing or invalid expires_in")
	}

	return &token, nil
}

func cloneToken(token *Token) *Token {
	if token == nil {
		return nil
	}
	cloned := *token
	return &cloned
}
