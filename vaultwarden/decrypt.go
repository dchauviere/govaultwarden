package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	kdfTypePBKDF2 = 0

	encTypeAesCbc256B64            = 0
	encTypeAesCbc256HmacSha256B64  = 2
	encTypeRsa2048OaepSha256B64    = 3
	encTypeRsa2048OaepSha1B64      = 4
	defaultPBKDF2Iteration         = 600000
	requiredSymmetricKeyTotalBytes = 64
)

type symmetricKey struct {
	encKey []byte
	macKey []byte
}

type parsedCipherString struct {
	encType int
	iv      []byte
	ct      []byte
	mac     []byte
}

func deriveMasterKey(password, salt string, kdfType, iterations int) ([]byte, error) {
	return deriveMasterKeySized(password, salt, kdfType, iterations, 32)
}

func deriveMasterKeySized(password, salt string, kdfType, iterations, size int) ([]byte, error) {
	if kdfType != kdfTypePBKDF2 {
		return nil, fmt.Errorf("unsupported kdf type: %d", kdfType)
	}
	if iterations <= 0 {
		iterations = defaultPBKDF2Iteration
	}
	return pbkdf2.Key(sha256.New, password, []byte(strings.TrimSpace(salt)), iterations, size)
}

func stretchMasterKey(masterKey []byte) (symmetricKey, error) {
	enc, err := hkdf.Expand(sha256.New, masterKey, "enc", 32)
	if err != nil {
		return symmetricKey{}, fmt.Errorf("derive enc key: %w", err)
	}
	mac, err := hkdf.Expand(sha256.New, masterKey, "mac", 32)
	if err != nil {
		return symmetricKey{}, fmt.Errorf("derive mac key: %w", err)
	}
	return symmetricKey{encKey: enc, macKey: mac}, nil
}

func stretchMasterKeyWithExtract(masterKey []byte) (symmetricKey, error) {
	enc, err := hkdf.Key(sha256.New, masterKey, nil, "enc", 32)
	if err != nil {
		return symmetricKey{}, fmt.Errorf("derive enc key (extract+expand): %w", err)
	}
	mac, err := hkdf.Key(sha256.New, masterKey, nil, "mac", 32)
	if err != nil {
		return symmetricKey{}, fmt.Errorf("derive mac key (extract+expand): %w", err)
	}
	return symmetricKey{encKey: enc, macKey: mac}, nil
}

func decryptUserSymmetricKey(encrypted string, masterKey []byte) (symmetricKey, error) {
	parsed, err := parseCipherString(encrypted)
	if err != nil {
		return symmetricKey{}, err
	}

	var candidates []struct {
		name string
		key  symmetricKey
	}
	stretched, stretchErr := stretchMasterKey(masterKey)
	if stretchErr == nil {
		candidates = append(candidates, struct {
			name string
			key  symmetricKey
		}{name: "hkdf-expand", key: stretched})
	}
	stretchedExtract, extractErr := stretchMasterKeyWithExtract(masterKey)
	if extractErr == nil {
		candidates = append(candidates, struct {
			name string
			key  symmetricKey
		}{name: "hkdf-extract-expand", key: stretchedExtract})
	}
	candidates = append(candidates,
		struct {
			name string
			key  symmetricKey
		}{name: "legacy-dual", key: symmetricKey{encKey: masterKey, macKey: masterKey}},
		struct {
			name string
			key  symmetricKey
		}{name: "legacy-enc-only", key: symmetricKey{encKey: masterKey}},
	)

	var attempts []string
	for _, candidate := range candidates {
		raw, decryptErr := decryptWithSymmetricKey(parsed, candidate.key)
		if decryptErr != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", candidate.name, decryptErr))
			continue
		}
		if len(raw) != requiredSymmetricKeyTotalBytes {
			attempts = append(attempts, fmt.Sprintf("%s: invalid decrypted user key length: %d", candidate.name, len(raw)))
			continue
		}

		return symmetricKey{
			encKey: raw[:32],
			macKey: raw[32:],
		}, nil
	}

	if stretchErr != nil {
		attempts = append(attempts, fmt.Sprintf("hkdf-expand setup: %v", stretchErr))
	}
	if extractErr != nil {
		attempts = append(attempts, fmt.Sprintf("hkdf-extract-expand setup: %v", extractErr))
	}

	return symmetricKey{}, fmt.Errorf("unable to decrypt user key with available derivation strategies: %s", strings.Join(attempts, "; "))
}

func decryptUserSymmetricKeyPBKDF2Split(encrypted, password, salt string, iterations int) (symmetricKey, error) {
	parsed, err := parseCipherString(encrypted)
	if err != nil {
		return symmetricKey{}, err
	}
	derived, err := deriveMasterKeySized(password, salt, kdfTypePBKDF2, iterations, 64)
	if err != nil {
		return symmetricKey{}, err
	}
	derivedKey := symmetricKey{
		encKey: derived[:32],
		macKey: derived[32:],
	}
	raw, err := decryptWithSymmetricKey(parsed, derivedKey)
	if err != nil {
		return symmetricKey{}, err
	}
	if len(raw) != requiredSymmetricKeyTotalBytes {
		return symmetricKey{}, fmt.Errorf("invalid decrypted user key length: %d", len(raw))
	}
	return symmetricKey{
		encKey: raw[:32],
		macKey: raw[32:],
	}, nil
}

func decryptPrivateKey(encrypted string, key symmetricKey) (*rsa.PrivateKey, error) {
	parsed, err := parseCipherString(encrypted)
	if err != nil {
		return nil, err
	}
	plain, err := decryptWithSymmetricKey(parsed, key)
	if err != nil {
		return nil, err
	}
	pk, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

func decryptOrganizationKey(encrypted string, privateKey *rsa.PrivateKey) (symmetricKey, error) {
	parsed, err := parseCipherString(encrypted)
	if err != nil {
		return symmetricKey{}, err
	}

	var decrypted []byte
	switch parsed.encType {
	case encTypeRsa2048OaepSha256B64:
		decrypted, err = rsa.DecryptOAEP(sha256.New(), nil, privateKey, parsed.ct, nil)
	case encTypeRsa2048OaepSha1B64:
		decrypted, err = rsa.DecryptOAEP(sha1.New(), nil, privateKey, parsed.ct, nil)
	default:
		return symmetricKey{}, fmt.Errorf("unsupported organization key encryption type: %d", parsed.encType)
	}
	if err != nil {
		return symmetricKey{}, fmt.Errorf("decrypt organization key: %w", err)
	}

	if len(decrypted) != requiredSymmetricKeyTotalBytes {
		return symmetricKey{}, fmt.Errorf("invalid decrypted organization key length: %d", len(decrypted))
	}
	return symmetricKey{encKey: decrypted[:32], macKey: decrypted[32:]}, nil
}

func decryptFieldValue(raw string, key symmetricKey) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := parseCipherString(raw)
	if err != nil {
		return "", err
	}
	plain, err := decryptWithSymmetricKey(parsed, key)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func parseCipherString(s string) (*parsedCipherString, error) {
	if s == "" {
		return nil, errors.New("empty cipher string")
	}
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cipher string format")
	}

	var encType int
	if _, err := fmt.Sscanf(parts[0], "%d", &encType); err != nil {
		return nil, fmt.Errorf("invalid cipher encryption type: %w", err)
	}

	payload := strings.Split(parts[1], "|")
	out := &parsedCipherString{encType: encType}

	switch encType {
	case encTypeAesCbc256B64:
		if len(payload) != 2 {
			return nil, fmt.Errorf("invalid type 0 cipher payload")
		}
		iv, err := base64.StdEncoding.DecodeString(payload[0])
		if err != nil {
			return nil, fmt.Errorf("invalid cipher IV: %w", err)
		}
		ct, err := base64.StdEncoding.DecodeString(payload[1])
		if err != nil {
			return nil, fmt.Errorf("invalid cipher text: %w", err)
		}
		out.iv = iv
		out.ct = ct
	case encTypeAesCbc256HmacSha256B64:
		if len(payload) != 3 {
			return nil, fmt.Errorf("invalid type 2 cipher payload")
		}
		iv, err := base64.StdEncoding.DecodeString(payload[0])
		if err != nil {
			return nil, fmt.Errorf("invalid cipher IV: %w", err)
		}
		ct, err := base64.StdEncoding.DecodeString(payload[1])
		if err != nil {
			return nil, fmt.Errorf("invalid cipher text: %w", err)
		}
		mac, err := base64.StdEncoding.DecodeString(payload[2])
		if err != nil {
			return nil, fmt.Errorf("invalid cipher MAC: %w", err)
		}
		out.iv = iv
		out.ct = ct
		out.mac = mac
	case encTypeRsa2048OaepSha256B64, encTypeRsa2048OaepSha1B64:
		if len(payload) != 1 {
			return nil, fmt.Errorf("invalid RSA cipher payload")
		}
		ct, err := base64.StdEncoding.DecodeString(payload[0])
		if err != nil {
			return nil, fmt.Errorf("invalid RSA cipher text: %w", err)
		}
		out.ct = ct
	default:
		return nil, fmt.Errorf("unsupported cipher encryption type: %d", encType)
	}
	return out, nil
}

func decryptWithSymmetricKey(cs *parsedCipherString, key symmetricKey) ([]byte, error) {
	if cs.encType != encTypeAesCbc256B64 && cs.encType != encTypeAesCbc256HmacSha256B64 {
		return nil, fmt.Errorf("cipher type %d is not symmetric", cs.encType)
	}
	if len(cs.iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid cipher IV length: %d", len(cs.iv))
	}
	if len(cs.ct) == 0 || len(cs.ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid cipher text length: %d", len(cs.ct))
	}

	if cs.encType == encTypeAesCbc256HmacSha256B64 {
		if len(key.macKey) == 0 {
			return nil, errors.New("missing MAC key for type 2 cipher")
		}
		mac := hmacSHA256(key.macKey, cs.iv, cs.ct)
		if !hmacEqual(mac, cs.mac) {
			return nil, errors.New("cipher MAC verification failed")
		}
	}

	block, err := aes.NewCipher(key.encKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	out := make([]byte, len(cs.ct))
	copy(out, cs.ct)
	cipher.NewCBCDecrypter(block, cs.iv).CryptBlocks(out, out)
	return pkcs7Unpad(out, aes.BlockSize)
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, fmt.Errorf("invalid padding size")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if data[i] != byte(pad) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return data[:len(data)-pad], nil
}
