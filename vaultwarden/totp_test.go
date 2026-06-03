package vaultwarden

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateTOTPCodeRFCVector(t *testing.T) {
	// RFC 6238 test secret in base32 for "12345678901234567890".
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := generateTOTPCode(secret, 8, 30, time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != "94287082" {
		t.Fatalf("unexpected TOTP code: %s", code)
	}
}

func TestParseTOTPInputOtpauthURI(t *testing.T) {
	secret, digits, period, err := parseTOTPInput("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=6&period=30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "JBSWY3DPEHPK3PXP" || digits != 6 || period != 30 {
		t.Fatalf("unexpected parsed values: secret=%s digits=%d period=%d", secret, digits, period)
	}
}

func TestGenerateCurrentTOTPCodeRejectsInvalidSecret(t *testing.T) {
	_, err := generateCurrentTOTPCode("invalid***")
	if err == nil || !strings.Contains(err.Error(), "invalid TOTP secret encoding") {
		t.Fatalf("unexpected error: %v", err)
	}
}
