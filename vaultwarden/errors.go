package vaultwarden

import (
	"fmt"
	"regexp"
)

const maxErrorBodyLength = 1024

type sensitivePattern struct {
	re          *regexp.Regexp
	replacement string
}

var sensitiveBodyPatterns = []sensitivePattern{
	{re: regexp.MustCompile(`(?i)("client_secret"\s*:\s*")[^"]*(")`), replacement: `$1[REDACTED]$2`},
	{re: regexp.MustCompile(`(?i)("access_token"\s*:\s*")[^"]*(")`), replacement: `$1[REDACTED]$2`},
	{re: regexp.MustCompile(`(?i)("password"\s*:\s*")[^"]*(")`), replacement: `$1[REDACTED]$2`},
	{re: regexp.MustCompile(`(?i)(client_secret=)[^&\s]+`), replacement: `$1[REDACTED]`},
	{re: regexp.MustCompile(`(?i)(access_token=)[^&\s]+`), replacement: `$1[REDACTED]`},
	{re: regexp.MustCompile(`(?i)(password=)[^&\s]+`), replacement: `$1[REDACTED]`},
}

// APIError represents a non-successful HTTP response from Vaultwarden.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("vaultwarden API error: status=%d", e.StatusCode)
	}
	return fmt.Sprintf("vaultwarden API error: status=%d body=%s", e.StatusCode, e.Body)
}

func sanitizeErrorBody(body string) string {
	sanitized := body
	for _, pattern := range sensitiveBodyPatterns {
		sanitized = pattern.re.ReplaceAllString(sanitized, pattern.replacement)
	}

	if len(sanitized) > maxErrorBodyLength {
		return sanitized[:maxErrorBodyLength] + "...(truncated)"
	}
	return sanitized
}
