package vaultwarden

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func generateCurrentTOTPCode(raw string) (string, error) {
	secret, digits, period, err := parseTOTPInput(raw)
	if err != nil {
		return "", err
	}
	return generateTOTPCode(secret, digits, period, time.Now().UTC())
}

func parseTOTPInput(raw string) (secret string, digits int, period int64, err error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", 0, 0, fmt.Errorf("empty TOTP secret")
	}

	digits = 6
	period = 30

	if strings.HasPrefix(strings.ToLower(value), "otpauth://") {
		parsed, parseErr := url.Parse(value)
		if parseErr != nil {
			return "", 0, 0, fmt.Errorf("invalid otpauth URI: %w", parseErr)
		}
		query := parsed.Query()
		value = strings.TrimSpace(query.Get("secret"))
		if value == "" {
			return "", 0, 0, fmt.Errorf("otpauth URI missing secret")
		}
		if d := strings.TrimSpace(query.Get("digits")); d != "" {
			parsedDigits, convErr := strconv.Atoi(d)
			if convErr == nil && parsedDigits >= 6 && parsedDigits <= 8 {
				digits = parsedDigits
			}
		}
		if p := strings.TrimSpace(query.Get("period")); p != "" {
			parsedPeriod, convErr := strconv.ParseInt(p, 10, 64)
			if convErr == nil && parsedPeriod > 0 {
				period = parsedPeriod
			}
		}
	}

	normalizedSecret := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(value, " ", ""), "-", ""))
	return normalizedSecret, digits, period, nil
}

func generateTOTPCode(secret string, digits int, period int64, ts time.Time) (string, error) {
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := encoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret encoding: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("empty decoded TOTP secret")
	}

	counter := uint64(ts.Unix() / period)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	hash := hmac.New(sha1.New, key)
	hash.Write(msg[:])
	sum := hash.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)

	modulo := 1
	for range digits {
		modulo *= 10
	}
	code := binCode % modulo
	return fmt.Sprintf("%0*d", digits, code), nil
}
