package vaultwarden

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListDecryptedSecretsDecryptsOrganizationCipher(t *testing.T) {
	masterPassword := "master-password"
	salt := "user@example.com"

	masterKey, err := deriveMasterKey(masterPassword, salt, kdfTypePBKDF2, 600000)
	if err != nil {
		t.Fatalf("derive master key failed: %v", err)
	}
	stretched, err := stretchMasterKey(masterKey)
	if err != nil {
		t.Fatalf("stretch master key failed: %v", err)
	}

	userKeyRaw := randomBytes(t, 64)
	userKey := symmetricKey{encKey: userKeyRaw[:32], macKey: userKeyRaw[32:]}
	encryptedUserKey := encryptType2(t, userKeyRaw, stretched)

	privateRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key failed: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateRSAKey)
	if err != nil {
		t.Fatalf("marshal private key failed: %v", err)
	}
	encryptedPrivateKey := encryptType2(t, privateDER, userKey)

	orgKeyRaw := randomBytes(t, 64)
	orgKey := symmetricKey{encKey: orgKeyRaw[:32], macKey: orgKeyRaw[32:]}
	orgCipher, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateRSAKey.PublicKey, orgKeyRaw, nil)
	if err != nil {
		t.Fatalf("encrypt org key failed: %v", err)
	}
	encryptedOrgKey := "4." + base64.StdEncoding.EncodeToString(orgCipher)

	encName := encryptType2(t, []byte("prod/db"), orgKey)
	encUsername := encryptType2(t, []byte("db-user"), orgKey)
	encPassword := encryptType2(t, []byte("db-pass"), orgKey)
	encTOTP := encryptType2(t, []byte("JBSWY3DPEHPK3PXP"), orgKey)
	encFieldName := encryptType2(t, []byte("host"), orgKey)
	encFieldValue := encryptType2(t, []byte("db.local"), orgKey)

	syncPayload := fmt.Sprintf(`{
	  "ciphers": [
		{
		  "id": "cipher-1",
		  "organizationId": "org-1",
		  "key": null,
		  "name": %q,
		  "notes": "",
		  "login": {"username": %q, "password": %q, "totp": %q},
		  "fields": [{"name": %q, "value": %q}]
		}
	  ],
	  "profile": {
		"email": %q,
		"key": %q,
		"privateKey": %q,
		"organizations": [{"id": "org-1", "key": %q}]
	  },
	  "userDecryption": {
		"masterPasswordUnlock": {
		  "salt": %q,
		  "masterKeyEncryptedUserKey": %q,
		  "kdf": {"kdfType": 0, "iterations": 600000}
		}
	  }
	}`, encName, encUsername, encPassword, encTOTP, encFieldName, encFieldValue, salt, encryptedUserKey, encryptedPrivateKey, encryptedOrgKey, salt, encryptedUserKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
		case "/api/sync":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(syncPayload))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, Config{
		BaseURL:        server.URL,
		ClientID:       "client-id",
		ClientSecret:   "client-secret",
		GrantType:      "client_credentials",
		MasterPassword: masterPassword,
	})

	secrets, err := client.ListDecryptedSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected one secret, got %d", len(secrets))
	}
	secret := secrets[0]
	if secret.Name != "prod/db" || secret.Username != "db-user" || secret.Password != "db-pass" {
		t.Fatalf("unexpected decrypted secret: %+v", secret)
	}
	if secret.TOTP != "JBSWY3DPEHPK3PXP" || len(secret.TOTPCode) != 6 {
		t.Fatalf("unexpected totp payload: %+v", secret)
	}
	if secret.OrganizationID != "org-1" {
		t.Fatalf("unexpected organization id: %s", secret.OrganizationID)
	}
	if secret.Fields["host"] != "db.local" {
		t.Fatalf("unexpected field value: %+v", secret.Fields)
	}

	byOrg, err := client.ListDecryptedSecretsByOrganization(context.Background(), "org-1")
	if err != nil {
		t.Fatalf("unexpected list decrypted by org error: %v", err)
	}
	if len(byOrg) != 1 || byOrg[0].ID != "cipher-1" {
		t.Fatalf("unexpected decrypted by-org result: %+v", byOrg)
	}

	byID, err := client.GetDecryptedSecretByID(context.Background(), "cipher-1")
	if err != nil {
		t.Fatalf("unexpected get decrypted by id error: %v", err)
	}
	if byID.Name != "prod/db" || byID.Password != "db-pass" {
		t.Fatalf("unexpected decrypted by-id result: %+v", byID)
	}
}

func TestListDecryptedSecretsRequiresMasterPassword(t *testing.T) {
	client := newTestClient(t, Config{
		BaseURL:      "https://vaultwarden.example.com",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		GrantType:    "client_credentials",
	})
	_, err := client.ListDecryptedSecrets(context.Background())
	if err == nil || !strings.Contains(err.Error(), "VAULTWARDEN_MASTER_PASSWORD") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListDecryptedSecretsDecryptsSSHAndCard(t *testing.T) {
	masterPassword := "master-password"
	salt := "user@example.com"

		masterKey, err := deriveMasterKey(masterPassword, salt, kdfTypePBKDF2, 600000)
		if err != nil {
			t.Fatalf("derive master key failed: %v", err)
		}
		stretched, err := stretchMasterKey(masterKey)
		if err != nil {
			t.Fatalf("stretch master key failed: %v", err)
		}

		userKeyRaw := randomBytes(t, 64)
		userKey := symmetricKey{encKey: userKeyRaw[:32], macKey: userKeyRaw[32:]}
		encryptedUserKey := encryptType2(t, userKeyRaw, stretched)

		privateRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key failed: %v", err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(privateRSAKey)
		if err != nil {
			t.Fatalf("marshal private key failed: %v", err)
		}
		encryptedPrivateKey := encryptType2(t, privateDER, userKey)

		orgKeyRaw := randomBytes(t, 64)
		orgKey := symmetricKey{encKey: orgKeyRaw[:32], macKey: orgKeyRaw[32:]}
		orgCipher, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateRSAKey.PublicKey, orgKeyRaw, nil)
		if err != nil {
			t.Fatalf("encrypt org key failed: %v", err)
		}
		encryptedOrgKey := "4." + base64.StdEncoding.EncodeToString(orgCipher)

		encSSHName := encryptType2(t, []byte("ssh-item"), orgKey)
		encSSHPublic := encryptType2(t, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"), orgKey)
		encSSHPrivate := encryptType2(t, []byte("-----BEGIN OPENSSH PRIVATE KEY-----"), orgKey)
		encSSHFingerprint := encryptType2(t, []byte("SHA256:abc123"), orgKey)

		encCardName := encryptType2(t, []byte("card-item"), orgKey)
		encCardholder := encryptType2(t, []byte("JOHN DOE"), orgKey)
		encBrand := encryptType2(t, []byte("visa"), orgKey)
		encNumber := encryptType2(t, []byte("4111111111111111"), orgKey)
		encExpMonth := encryptType2(t, []byte("12"), orgKey)
		encExpYear := encryptType2(t, []byte("2030"), orgKey)
		encCode := encryptType2(t, []byte("123"), orgKey)

		syncPayload := fmt.Sprintf(`{
		  "ciphers": [
			{
			  "id": "ssh-1",
			  "organizationId": "org-1",
			  "key": null,
			  "name": %q,
			  "sshKey": {"publicKey": %q, "privateKey": %q, "fingerprint": %q}
			},
			{
			  "id": "card-1",
			  "organizationId": "org-1",
			  "key": null,
			  "name": %q,
			  "card": {
				"cardholderName": %q,
				"brand": %q,
				"number": %q,
				"expMonth": %q,
				"expYear": %q,
				"code": %q
			  }
			}
		  ],
		  "profile": {
			"email": %q,
			"key": %q,
			"privateKey": %q,
			"organizations": [{"id": "org-1", "key": %q}]
		  },
		  "userDecryption": {
			"masterPasswordUnlock": {
			  "salt": %q,
			  "masterKeyEncryptedUserKey": %q,
			  "kdf": {"kdfType": 0, "iterations": 600000}
			}
		  }
		}`, encSSHName, encSSHPublic, encSSHPrivate, encSSHFingerprint, encCardName, encCardholder, encBrand, encNumber, encExpMonth, encExpYear, encCode, salt, encryptedUserKey, encryptedPrivateKey, encryptedOrgKey, salt, encryptedUserKey)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/identity/connect/token":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"token-auth","token_type":"Bearer","expires_in":3600}`))
			case "/api/sync":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(syncPayload))
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		client := newTestClient(t, Config{
			BaseURL:        server.URL,
			ClientID:       "client-id",
			ClientSecret:   "client-secret",
			GrantType:      "client_credentials",
			MasterPassword: masterPassword,
		})

		secrets, err := client.ListDecryptedSecrets(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(secrets) != 2 {
			t.Fatalf("expected two secrets, got %d", len(secrets))
		}

		sshItem, err := client.GetDecryptedSecretByID(context.Background(), "ssh-1")
		if err != nil {
			t.Fatalf("unexpected get decrypted ssh by id error: %v", err)
		}
		if sshItem.SSHPublicKey == "" || sshItem.SSHPrivateKey == "" || sshItem.SSHFingerprint == "" {
			t.Fatalf("missing decrypted ssh fields: %+v", sshItem)
		}

		cardItem, err := client.GetDecryptedSecretByID(context.Background(), "card-1")
		if err != nil {
			t.Fatalf("unexpected get decrypted card by id error: %v", err)
		}
		if cardItem.CardBrand != "visa" || cardItem.CardNumber != "4111111111111111" || cardItem.CardCode != "123" {
			t.Fatalf("missing decrypted card fields: %+v", cardItem)
		}
	}

func encryptType2(t *testing.T, plaintext []byte, key symmetricKey) string {
	t.Helper()
	block, err := aes.NewCipher(key.encKey)
	if err != nil {
		t.Fatalf("new cipher failed: %v", err)
	}
	iv := randomBytes(t, aes.BlockSize)
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))
	copy(ct, padded)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, ct)

	h := hmac.New(sha256.New, key.macKey)
	h.Write(iv)
	h.Write(ct)
	mac := h.Sum(nil)

	return "2." + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(ct) + "|" + base64.StdEncoding.EncodeToString(mac)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	if pad == 0 {
		pad = blockSize
	}
	return append(bytes.Clone(data), bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand read failed: %v", err)
	}
	return b
}
