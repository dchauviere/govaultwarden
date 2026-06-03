package vaultwarden

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const defaultSyncPath = "/api/sync"

var ErrSecretNotFound = errors.New("secret not found")

// Secret represents a normalized secret extracted from Vaultwarden sync data.
type Secret struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	OrganizationID string            `json:"organization_id,omitempty"`
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	TOTP           string            `json:"totp,omitempty"`
	TOTPCode       string            `json:"totp_code,omitempty"`
	SSHPublicKey   string            `json:"ssh_public_key,omitempty"`
	SSHPrivateKey  string            `json:"ssh_private_key,omitempty"`
	SSHFingerprint string            `json:"ssh_fingerprint,omitempty"`
	CardholderName string            `json:"cardholder_name,omitempty"`
	CardBrand      string            `json:"card_brand,omitempty"`
	CardNumber     string            `json:"card_number,omitempty"`
	CardExpMonth   string            `json:"card_exp_month,omitempty"`
	CardExpYear    string            `json:"card_exp_year,omitempty"`
	CardCode       string            `json:"card_code,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	Fields         map[string]string `json:"fields,omitempty"`
}

type syncResponse struct {
	Ciphers        []vaultCipher  `json:"ciphers"`
	Profile        profile        `json:"profile"`
	UserDecryption userDecryption `json:"userDecryption"`
}

type vaultCipher struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	OrganizationID string  `json:"organizationId"`
	Key            string  `json:"key"`
	Notes          string  `json:"notes"`
	Login          *login  `json:"login"`
	SSHKey         *sshKey `json:"sshKey"`
	Card           *card   `json:"card"`
	Field          []field `json:"fields"`
}

type login struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

type field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type sshKey struct {
	PublicKey   string `json:"publicKey"`
	PrivateKey  string `json:"privateKey"`
	Fingerprint string `json:"fingerprint"`
}

type card struct {
	CardholderName string `json:"cardholderName"`
	Brand          string `json:"brand"`
	Number         string `json:"number"`
	ExpMonth       string `json:"expMonth"`
	ExpYear        string `json:"expYear"`
	Code           string `json:"code"`
}

type profile struct {
	Email         string                `json:"email"`
	Key           string                `json:"key"`
	PrivateKey    string                `json:"privateKey"`
	Organizations []profileOrganization `json:"organizations"`
}

type profileOrganization struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type userDecryption struct {
	MasterPasswordUnlock masterPasswordUnlock `json:"masterPasswordUnlock"`
}

type masterPasswordUnlock struct {
	Salt                   string `json:"salt"`
	MasterKeyEncryptedUser string `json:"masterKeyEncryptedUserKey"`
	KDF                    kdf    `json:"kdf"`
}

type kdf struct {
	KDFType    int `json:"kdfType"`
	Iterations int `json:"iterations"`
}

// ListSecrets fetches and normalizes secrets from the default Vaultwarden sync endpoint.
func (c *Client) ListSecrets(ctx context.Context) ([]Secret, error) {
	var response syncResponse
	if err := c.Get(ctx, defaultSyncPath, &response); err != nil {
		return nil, fmt.Errorf("fetch secrets from sync endpoint: %w", err)
	}

	secrets := make([]Secret, 0, len(response.Ciphers))
	for _, item := range response.Ciphers {
		secret := Secret{
			ID:             strings.TrimSpace(item.ID),
			Name:           strings.TrimSpace(item.Name),
			OrganizationID: strings.TrimSpace(item.OrganizationID),
			Notes:          strings.TrimSpace(item.Notes),
			Fields:         make(map[string]string),
		}
		if item.Login != nil {
			secret.Username = strings.TrimSpace(item.Login.Username)
			secret.Password = strings.TrimSpace(item.Login.Password)
			secret.TOTP = strings.TrimSpace(item.Login.TOTP)
		}
		if item.SSHKey != nil {
			secret.SSHPublicKey = strings.TrimSpace(item.SSHKey.PublicKey)
			secret.SSHPrivateKey = strings.TrimSpace(item.SSHKey.PrivateKey)
			secret.SSHFingerprint = strings.TrimSpace(item.SSHKey.Fingerprint)
		}
		if item.Card != nil {
			secret.CardholderName = strings.TrimSpace(item.Card.CardholderName)
			secret.CardBrand = strings.TrimSpace(item.Card.Brand)
			secret.CardNumber = strings.TrimSpace(item.Card.Number)
			secret.CardExpMonth = strings.TrimSpace(item.Card.ExpMonth)
			secret.CardExpYear = strings.TrimSpace(item.Card.ExpYear)
			secret.CardCode = strings.TrimSpace(item.Card.Code)
		}
		for _, f := range item.Field {
			name := strings.TrimSpace(f.Name)
			if name == "" {
				continue
			}
			secret.Fields[name] = strings.TrimSpace(f.Value)
		}
		if len(secret.Fields) == 0 {
			secret.Fields = nil
		}
		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// ListSecretsByOrganization returns raw secrets filtered by organization ID.
func (c *Client) ListSecretsByOrganization(ctx context.Context, organizationID string) ([]Secret, error) {
	secrets, err := c.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	return filterSecretsByOrganization(secrets, organizationID), nil
}

// GetSecretByID returns one raw secret by item ID.
func (c *Client) GetSecretByID(ctx context.Context, itemID string) (Secret, error) {
	secrets, err := c.ListSecrets(ctx)
	if err != nil {
		return Secret{}, err
	}
	secret, found := findSecretByID(secrets, itemID)
	if !found {
		return Secret{}, fmt.Errorf("%w: %s", ErrSecretNotFound, strings.TrimSpace(itemID))
	}
	return secret, nil
}

// ListDecryptedSecrets fetches sync data and decrypts secret fields with the master password.
func (c *Client) ListDecryptedSecrets(ctx context.Context) ([]Secret, error) {
	if strings.TrimSpace(c.cfg.MasterPassword) == "" {
		return nil, errors.New("master password is required for decrypted secrets (VAULTWARDEN_MASTER_PASSWORD)")
	}

	var response syncResponse
	if err := c.Get(ctx, defaultSyncPath, &response); err != nil {
		return nil, fmt.Errorf("fetch sync payload: %w", err)
	}

	salt := strings.TrimSpace(response.UserDecryption.MasterPasswordUnlock.Salt)
	if salt == "" {
		salt = strings.TrimSpace(response.Profile.Email)
	}

	encryptedUserKey := strings.TrimSpace(response.UserDecryption.MasterPasswordUnlock.MasterKeyEncryptedUser)
	if encryptedUserKey == "" {
		encryptedUserKey = strings.TrimSpace(response.Profile.Key)
	}

	saltCandidates := []string{salt}
	lowerSalt := strings.ToLower(salt)
	if lowerSalt != "" && lowerSalt != salt {
		saltCandidates = append(saltCandidates, lowerSalt)
	}

	var (
		userKey         symmetricKey
		userKeyResolved bool
		userKeyErrors   []string
	)

	for _, saltCandidate := range saltCandidates {
		masterKey, err := deriveMasterKey(
			c.cfg.MasterPassword,
			saltCandidate,
			response.UserDecryption.MasterPasswordUnlock.KDF.KDFType,
			response.UserDecryption.MasterPasswordUnlock.KDF.Iterations,
		)
		if err != nil {
			userKeyErrors = append(userKeyErrors, fmt.Sprintf("derive master key (salt=%q): %v", saltCandidate, err))
			continue
		}

		userKey, err = decryptUserSymmetricKey(encryptedUserKey, masterKey)
		if err == nil {
			userKeyResolved = true
			break
		}
		userKeyErrors = append(userKeyErrors, fmt.Sprintf("standard strategy (salt=%q): %v", saltCandidate, err))

		userKey, err = decryptUserSymmetricKeyPBKDF2Split(
			encryptedUserKey,
			c.cfg.MasterPassword,
			saltCandidate,
			response.UserDecryption.MasterPasswordUnlock.KDF.Iterations,
		)
		if err == nil {
			userKeyResolved = true
			break
		}
		userKeyErrors = append(userKeyErrors, fmt.Sprintf("pbkdf2-split strategy (salt=%q): %v", saltCandidate, err))
	}

	if !userKeyResolved {
		return nil, fmt.Errorf("decrypt user key: %s", strings.Join(userKeyErrors, "; "))
	}

	privateKey, err := decryptPrivateKey(strings.TrimSpace(response.Profile.PrivateKey), userKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt profile private key: %w", err)
	}

	orgKeys := make(map[string]symmetricKey, len(response.Profile.Organizations))
	for _, org := range response.Profile.Organizations {
		orgID := strings.TrimSpace(org.ID)
		orgEncKey := strings.TrimSpace(org.Key)
		if orgID == "" || orgEncKey == "" {
			continue
		}
		k, err := decryptOrganizationKey(orgEncKey, privateKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt organization key for %s: %w", orgID, err)
		}
		orgKeys[orgID] = k
	}

	secrets := make([]Secret, 0, len(response.Ciphers))
	for _, item := range response.Ciphers {
		baseKey := userKey
		orgID := strings.TrimSpace(item.OrganizationID)
		if orgID != "" {
			k, found := orgKeys[orgID]
			if !found {
				return nil, fmt.Errorf("missing decrypted organization key for cipher %s (org %s)", strings.TrimSpace(item.ID), orgID)
			}
			baseKey = k
		}

		cipherKey := baseKey
		if strings.TrimSpace(item.Key) != "" {
			parsedItemKey, err := parseCipherString(strings.TrimSpace(item.Key))
			if err != nil {
				return nil, fmt.Errorf("parse cipher key for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			rawItemKey, err := decryptWithSymmetricKey(parsedItemKey, baseKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt cipher key for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			if len(rawItemKey) != requiredSymmetricKeyTotalBytes {
				return nil, fmt.Errorf("invalid cipher key length for item %s: %d", strings.TrimSpace(item.ID), len(rawItemKey))
			}
			cipherKey = symmetricKey{
				encKey: rawItemKey[:32],
				macKey: rawItemKey[32:],
			}
		}

		name, err := decryptFieldValue(strings.TrimSpace(item.Name), cipherKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt name for item %s: %w", strings.TrimSpace(item.ID), err)
		}
		notes, err := decryptFieldValue(strings.TrimSpace(item.Notes), cipherKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt notes for item %s: %w", strings.TrimSpace(item.ID), err)
		}

		secret := Secret{
			ID:             strings.TrimSpace(item.ID),
			Name:           strings.TrimSpace(name),
			OrganizationID: orgID,
			Notes:          strings.TrimSpace(notes),
			Fields:         make(map[string]string),
		}

		if item.Login != nil {
			username, err := decryptFieldValue(strings.TrimSpace(item.Login.Username), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt username for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			password, err := decryptFieldValue(strings.TrimSpace(item.Login.Password), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt password for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			totp, err := decryptFieldValue(strings.TrimSpace(item.Login.TOTP), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt totp for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			secret.Username = strings.TrimSpace(username)
			secret.Password = strings.TrimSpace(password)
			secret.TOTP = strings.TrimSpace(totp)
			if secret.TOTP != "" {
				code, codeErr := generateCurrentTOTPCode(secret.TOTP)
				if codeErr == nil {
					secret.TOTPCode = code
				}
			}
		}
		if item.SSHKey != nil {
			publicKey, err := decryptFieldValue(strings.TrimSpace(item.SSHKey.PublicKey), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt ssh public key for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			privateKeyValue, err := decryptFieldValue(strings.TrimSpace(item.SSHKey.PrivateKey), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt ssh private key for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			fingerprint, err := decryptFieldValue(strings.TrimSpace(item.SSHKey.Fingerprint), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt ssh fingerprint for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			secret.SSHPublicKey = strings.TrimSpace(publicKey)
			secret.SSHPrivateKey = strings.TrimSpace(privateKeyValue)
			secret.SSHFingerprint = strings.TrimSpace(fingerprint)
		}
		if item.Card != nil {
			cardholderName, err := decryptFieldValue(strings.TrimSpace(item.Card.CardholderName), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt cardholder name for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			brand, err := decryptFieldValue(strings.TrimSpace(item.Card.Brand), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt card brand for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			number, err := decryptFieldValue(strings.TrimSpace(item.Card.Number), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt card number for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			expMonth, err := decryptFieldValue(strings.TrimSpace(item.Card.ExpMonth), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt card exp month for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			expYear, err := decryptFieldValue(strings.TrimSpace(item.Card.ExpYear), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt card exp year for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			code, err := decryptFieldValue(strings.TrimSpace(item.Card.Code), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt card code for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			secret.CardholderName = strings.TrimSpace(cardholderName)
			secret.CardBrand = strings.TrimSpace(brand)
			secret.CardNumber = strings.TrimSpace(number)
			secret.CardExpMonth = strings.TrimSpace(expMonth)
			secret.CardExpYear = strings.TrimSpace(expYear)
			secret.CardCode = strings.TrimSpace(code)
		}

		for _, f := range item.Field {
			fieldNameRaw := strings.TrimSpace(f.Name)
			if fieldNameRaw == "" {
				continue
			}
			fieldName, err := decryptFieldValue(fieldNameRaw, cipherKey)
			if err != nil {
				fieldName = fieldNameRaw
			}
			fieldValue, err := decryptFieldValue(strings.TrimSpace(f.Value), cipherKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt field value for item %s: %w", strings.TrimSpace(item.ID), err)
			}
			secret.Fields[strings.TrimSpace(fieldName)] = strings.TrimSpace(fieldValue)
		}

		if len(secret.Fields) == 0 {
			secret.Fields = nil
		}
		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// ListDecryptedSecretsByOrganization returns decrypted secrets filtered by organization ID.
func (c *Client) ListDecryptedSecretsByOrganization(ctx context.Context, organizationID string) ([]Secret, error) {
	secrets, err := c.ListDecryptedSecrets(ctx)
	if err != nil {
		return nil, err
	}
	return filterSecretsByOrganization(secrets, organizationID), nil
}

// GetDecryptedSecretByID returns one decrypted secret by item ID.
func (c *Client) GetDecryptedSecretByID(ctx context.Context, itemID string) (Secret, error) {
	secrets, err := c.ListDecryptedSecrets(ctx)
	if err != nil {
		return Secret{}, err
	}
	secret, found := findSecretByID(secrets, itemID)
	if !found {
		return Secret{}, fmt.Errorf("%w: %s", ErrSecretNotFound, strings.TrimSpace(itemID))
	}
	return secret, nil
}

func filterSecretsByOrganization(secrets []Secret, organizationID string) []Secret {
	orgID := strings.TrimSpace(organizationID)
	if orgID == "" {
		return []Secret{}
	}
	filtered := make([]Secret, 0, len(secrets))
	for _, secret := range secrets {
		if strings.TrimSpace(secret.OrganizationID) == orgID {
			filtered = append(filtered, secret)
		}
	}
	return filtered
}

func findSecretByID(secrets []Secret, itemID string) (Secret, bool) {
	targetID := strings.TrimSpace(itemID)
	if targetID == "" {
		return Secret{}, false
	}
	for _, secret := range secrets {
		if strings.TrimSpace(secret.ID) == targetID {
			return secret, true
		}
	}
	return Secret{}, false
}
