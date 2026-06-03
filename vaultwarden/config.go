package vaultwarden

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultTokenPath      = "/identity/connect/token"
	defaultRequestTimeout = 15 * time.Second
	defaultScope          = "api"
	defaultDeviceID       = "govaultwarden"
	defaultDeviceName     = "govaultwarden"
	defaultDeviceType     = "21"
)

// Config contains connector settings for Vaultwarden authentication and API calls.
type Config struct {
	BaseURL          string
	TokenEndpoint    string
	ClientID         string
	ClientSecret     string
	MasterPassword   string
	Username         string
	Password         string
	Scope            string
	GrantType        string
	DeviceIdentifier string
	DeviceName       string
	DeviceType       string
	Timeout          time.Duration
}

// LoadConfigFromEnv loads connector configuration from environment variables.
func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		BaseURL:        os.Getenv("VAULTWARDEN_URL"),
		ClientID:       os.Getenv("VAULTWARDEN_CLIENT_ID"),
		ClientSecret:   os.Getenv("VAULTWARDEN_CLIENT_SECRET"),
		MasterPassword: os.Getenv("VAULTWARDEN_MASTER_PASSWORD"),
		GrantType:      os.Getenv("VAULTWARDEN_GRANT_TYPE"),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate validates mandatory fields and configuration values.
func (c Config) Validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("base URL is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("client ID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("client secret is required")
	}
	if strings.TrimSpace(c.GrantType) == "" {
		return errors.New("grant type is required")
	}
	if c.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}

	if _, err := normalizeBaseURL(c.BaseURL); err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}

	if strings.TrimSpace(c.TokenEndpoint) != "" {
		if _, err := resolveTokenEndpoint(c.BaseURL, c.TokenEndpoint); err != nil {
			return fmt.Errorf("invalid token endpoint: %w", err)
		}
	}

	return nil
}

func normalizeBaseURL(rawBaseURL string) (string, error) {
	base := strings.TrimSpace(rawBaseURL)
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("URL must include scheme and host")
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func resolveTokenEndpoint(baseURL, configuredTokenEndpoint string) (string, error) {
	normalizedBaseURL, err := normalizeBaseURL(baseURL)
	if err != nil {
		return "", err
	}

	tokenEndpoint := strings.TrimSpace(configuredTokenEndpoint)
	if tokenEndpoint == "" {
		return joinURLPath(normalizedBaseURL, defaultTokenPath)
	}

	parsed, err := url.Parse(tokenEndpoint)
	if err != nil {
		return "", err
	}
	if parsed.IsAbs() {
		if parsed.Scheme == "" || parsed.Host == "" {
			return "", errors.New("absolute token endpoint must include scheme and host")
		}
		parsed.Path = "/" + strings.TrimLeft(parsed.Path, "/")
		parsed.RawPath = ""
		return strings.TrimRight(parsed.String(), "/"), nil
	}

	return joinURLPath(normalizedBaseURL, tokenEndpoint)
}

func joinURLPath(baseURL, path string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	joinedPath := strings.TrimRight(parsed.Path, "/") + "/" + strings.TrimLeft(path, "/")
	parsed.Path = joinedPath
	parsed.RawPath = ""
	return parsed.String(), nil
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.TokenEndpoint = strings.TrimSpace(cfg.TokenEndpoint)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)
	cfg.MasterPassword = strings.TrimSpace(cfg.MasterPassword)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Password = strings.TrimSpace(cfg.Password)
	cfg.Scope = strings.TrimSpace(cfg.Scope)
	cfg.GrantType = strings.TrimSpace(cfg.GrantType)
	cfg.DeviceIdentifier = strings.TrimSpace(cfg.DeviceIdentifier)
	cfg.DeviceName = strings.TrimSpace(cfg.DeviceName)
	cfg.DeviceType = strings.TrimSpace(cfg.DeviceType)

	if cfg.DeviceIdentifier == "" {
		cfg.DeviceIdentifier = defaultDeviceID
	}
	if cfg.DeviceName == "" {
		cfg.DeviceName = defaultDeviceName
	}
	if cfg.DeviceType == "" {
		cfg.DeviceType = defaultDeviceType
	}
	if cfg.Scope == "" {
		cfg.Scope = defaultScope
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = defaultRequestTimeout
	}

	normalizedBaseURL, err := normalizeBaseURL(cfg.BaseURL)
	if err != nil {
		return Config{}, err
	}
	cfg.BaseURL = normalizedBaseURL

	tokenEndpoint, err := resolveTokenEndpoint(cfg.BaseURL, cfg.TokenEndpoint)
	if err != nil {
		return Config{}, err
	}
	cfg.TokenEndpoint = tokenEndpoint

	return cfg, nil
}
