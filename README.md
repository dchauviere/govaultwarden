# 🚀 **goVaultwarden**

**goVaultwarden** is a reusable Go package for authenticating against a **Vaultwarden** instance using the Bitwarden-compatible API, calling authenticated endpoints, and retrieving encrypted or decrypted vault items.

It is designed for developers who want a clean Go connector around Vaultwarden client APIs, including native decryption support for supported vault profiles.

🔐 **Vaultwarden-compatible**
⚡ **Go-native client**
🧩 **Reusable package**
🔑 **Encrypted and decrypted secret retrieval**
⏱️ **TOTP code generation when available**

---

## ✨ **Features Overview**

| Feature                    | Description                                                            |
| -------------------------- | ---------------------------------------------------------------------- |
| 🔐 Authentication          | Authenticate against Vaultwarden using client credentials.             |
| 🌐 Authenticated API calls | Call Vaultwarden endpoints with `Authorization: Bearer <token>`.       |
| 📦 Raw vault sync          | Retrieve encrypted items from `/api/sync`.                             |
| 🔓 Native decryption       | Decrypt supported vault items directly in Go.                          |
| 🏢 Organization items      | List raw or decrypted secrets by organization.                         |
| 🔎 Item lookup             | Retrieve a specific item by ID when present in the sync payload.       |
| 🔢 TOTP support            | Return decrypted TOTP secrets and generate current verification codes. |
| 🧷 SSH key fields          | Return decrypted SSH public/private key fields when available.         |
| 💳 Card fields             | Return decrypted card fields when available.                           |
| ⚙️ Env helper              | Load configuration from environment variables for examples or scripts. |

---

## 📦 **Installation**

```sh
go get github.com/phd59fr/goVaultwarden
```

Then import the package in your Go project:

```go
import vaultwarden "github.com/phd59fr/goVaultwarden"
```

---

## ⚡ **Quick Start**

Instantiate the client directly with your own configuration source:

```go
cfg := vaultwarden.Config{
	BaseURL:        bw.URL,
	ClientID:       bw.ClientID,
	ClientSecret:   bw.ClientSecret,
	GrantType:      bw.GrantType,
	MasterPassword: bw.MasterPassword, // required only for decrypted secrets
}

client, err := vaultwarden.NewClient(cfg)
if err != nil {
	// handle error
}
```

Then use the client:

```go
secrets, err := client.ListDecryptedSecrets(ctx)
if err != nil {
	// handle error
}

for _, secret := range secrets {
	fmt.Println(secret.Name)
}
```

---

## 🔧 **Programmatic Usage**

The recommended approach is to create the client from your own configuration layer.

```go
cfg := vaultwarden.Config{
	BaseURL:      "https://vaultwarden.example.com",
	ClientID:     "my-client-id",
	ClientSecret: "my-client-secret",
	GrantType:    "client_credentials",
}

client, err := vaultwarden.NewClient(cfg)
if err != nil {
	log.Fatal(err)
}
```

### Available methods

| Method                                           | Description                                      |
| ------------------------------------------------ | ------------------------------------------------ |
| `client.Get(...)`                                | Perform a generic authenticated GET request.     |
| `client.Post(...)`                               | Perform a generic authenticated POST request.    |
| `client.ListSecrets(...)`                        | Return raw encrypted sync data.                  |
| `client.GetSecretByID(...)`                      | Return one raw encrypted item by ID.             |
| `client.ListSecretsByOrganization(...)`          | Return raw encrypted items for one organization. |
| `client.ListDecryptedSecrets(...)`               | Return normalized plaintext credentials.         |
| `client.GetDecryptedSecretByID(...)`             | Return one decrypted item by ID.                 |
| `client.ListDecryptedSecretsByOrganization(...)` | Return decrypted items for one organization.     |

---

## 🔐 **Decrypted Secrets**

`ListDecryptedSecrets()` uses the Vaultwarden master password to decrypt supported vault items locally in Go.

```go
cfg := vaultwarden.Config{
	BaseURL:        "https://vaultwarden.example.com",
	ClientID:       "my-client-id",
	ClientSecret:   "my-client-secret",
	GrantType:      "client_credentials",
	MasterPassword: "my-master-password",
}

client, err := vaultwarden.NewClient(cfg)
if err != nil {
	log.Fatal(err)
}

items, err := client.ListDecryptedSecrets(ctx)
if err != nil {
	log.Fatal(err)
}
```

When available, decrypted items may include:

| Field             | Description                                |
| ----------------- | ------------------------------------------ |
| `username`        | Decrypted login username.                  |
| `password`        | Decrypted login password.                  |
| `uri`             | Login URI.                                 |
| `notes`           | Decrypted secure notes.                    |
| `fields`          | Decrypted custom fields.                   |
| `totp`            | Decrypted TOTP secret or `otpauth://` URI. |
| `totp_code`       | Current generated TOTP verification code.  |
| `ssh_public_key`  | Decrypted SSH public key.                  |
| `ssh_private_key` | Decrypted SSH private key.                 |
| `ssh_fingerprint` | Decrypted SSH fingerprint.                 |
| `cardholder_name` | Decrypted cardholder name.                 |
| `card_brand`      | Decrypted card brand.                      |
| `card_number`     | Decrypted card number.                     |
| `card_exp_month`  | Decrypted card expiration month.           |
| `card_exp_year`   | Decrypted card expiration year.            |
| `card_code`       | Decrypted card security code.              |

---

## 🔢 **TOTP Support**

When a decrypted item contains a TOTP secret, **goVaultwarden** returns both:

| Field       | Description                                      |
| ----------- | ------------------------------------------------ |
| `totp`      | The decrypted TOTP secret or `otpauth://` URI.   |
| `totp_code` | The current verification code generated locally. |

This allows consumers to retrieve credentials and their current MFA code from the same normalized output.

> ⚠️ TOTP codes are time-sensitive and should not be logged or stored.

---

## ⚙️ **Environment Variables**

`LoadConfigFromEnv()` is provided as a convenience helper, mainly for the example app.

### Required for authentication

| Variable                    | Description                                                          |
| --------------------------- | -------------------------------------------------------------------- |
| `VAULTWARDEN_URL`           | Vaultwarden root URL, for example `https://vaultwarden.example.com`. |
| `VAULTWARDEN_CLIENT_ID`     | Bitwarden/Vaultwarden API client ID.                                 |
| `VAULTWARDEN_CLIENT_SECRET` | Bitwarden/Vaultwarden API client secret.                             |
| `VAULTWARDEN_GRANT_TYPE`    | OAuth grant type, usually `client_credentials`.                      |

### Required only for decrypted mode

| Variable                      | Description                                          |
| ----------------------------- | ---------------------------------------------------- |
| `VAULTWARDEN_MASTER_PASSWORD` | Master password used to decrypt vault items locally. |

Most required client-side values can usually be retrieved from:

```text
https://<your-vaultwarden-instance>/#/settings/security/security-keys
```

---

## 🧪 **Example Shell Exports**

```sh
export VAULTWARDEN_URL="https://vaultwarden.example.com"
export VAULTWARDEN_CLIENT_ID="my-client-id"
export VAULTWARDEN_CLIENT_SECRET="my-client-secret"
export VAULTWARDEN_GRANT_TYPE="client_credentials"
export VAULTWARDEN_MASTER_PASSWORD="my-master-password"
```

---

## ▶️ **Example App**

Run the bundled example:

```sh
go run ./example
```

By default, the example:

1. Loads configuration from environment variables.
2. Authenticates against Vaultwarden.
3. Calls `ListDecryptedSecrets()`.
4. Prints normalized decrypted secrets as JSON.

This mode decrypts vault items natively in Go, including supported organization items.

---

## 🌐 **Calling Raw API Endpoints**

You can pass an endpoint argument to perform a generic authenticated GET request:

```sh
go run ./example /api/sync
```

This is useful for inspecting raw Vaultwarden-compatible client API responses.

Internally, **goVaultwarden** uses safe defaults for:

| Setting         | Default                                     |
| --------------- | ------------------------------------------- |
| Token endpoint  | Built automatically from `VAULTWARDEN_URL`. |
| Scope           | `api`.                                      |
| Timeout         | Built-in default timeout.                   |
| Device metadata | Built-in default values.                    |

---

## 🔓 **Decryption Mode**

Vaultwarden’s `/api/sync` endpoint returns encrypted cipher payloads by design.

**goVaultwarden** supports two modes:

| Mode           | Method                   | Output                                     |
| -------------- | ------------------------ | ------------------------------------------ |
| Raw mode       | `ListSecrets()`          | Encrypted cipher strings from `/api/sync`. |
| Decrypted mode | `ListDecryptedSecrets()` | Plaintext normalized secrets.              |

Current native decryption support includes:

| KDF                 | Status                    |
| ------------------- | ------------------------- |
| PBKDF2, `kdfType=0` | ✅ Supported               |
| Argon2              | ❌ Not currently supported |

---

## 🧭 **What Is Possible**

With this connector, you can:

* Authenticate against a Vaultwarden instance.
* Call Bitwarden-compatible client endpoints.
* List encrypted items returned by `/api/sync`.
* Decrypt supported login, notes, custom fields, TOTP, SSH key, and card fields.
* Retrieve a specific item by ID if it exists in the sync payload.
* Retrieve raw or decrypted items by organization.
* Generate current TOTP verification codes when the secret is available.

---

## 🚧 **Limitations**

This connector cannot:

* Access items that are not returned by `/api/sync`.
* Force-read browser-visible items that are outside current API visibility.
* Bypass missing organization or collection permissions.
* Access vault items from another account context.
* Decrypt fields that are absent from the API payload.
* Decrypt Argon2-based vaults without additional KDF support.

> In short: **goVaultwarden can only decrypt what the authenticated account can sync.**

---

## 🛡️ **Security Considerations**

Decrypted mode returns sensitive data in plaintext, including:

* passwords;
* TOTP secrets;
* current TOTP codes;
* SSH private keys;
* payment card fields;
* secure notes;
* custom secret fields.

Recommended precautions:

* Do not log decrypted output in production.
* Avoid storing decrypted JSON on disk.
* Use short-lived processes where possible.
* Prefer secure secret injection mechanisms over long-lived shell history.
* Restrict runtime permissions for applications using decrypted mode.
* Treat `VAULTWARDEN_MASTER_PASSWORD` as highly sensitive.

> ⚠️ If you print decrypted secrets, they are no longer protected by Vaultwarden encryption.

---

## 🧯 **Troubleshooting**

### `401 Unauthorized`

Check the authentication values:

```sh
echo "$VAULTWARDEN_CLIENT_ID"
echo "$VAULTWARDEN_CLIENT_SECRET"
```

Also verify that:

* the token endpoint is reachable;
* the client ID is valid;
* the client secret is valid;
* your reverse proxy forwards the `Authorization` header.

---

### Wrong `VAULTWARDEN_URL`

`VAULTWARDEN_URL` must point to the instance root URL:

```sh
export VAULTWARDEN_URL="https://vaultwarden.example.com"
```

Do not include the token path:

```sh
# Wrong
export VAULTWARDEN_URL="https://vaultwarden.example.com/identity/connect/token"
```

The connector builds the token endpoint automatically.

---

### Wrong `grant_type`

Make sure the grant type matches your server expectations:

```sh
export VAULTWARDEN_GRANT_TYPE="client_credentials"
```

An invalid grant type usually returns a `400` response from the token endpoint.

---

### `device_identifier cannot be blank`

The connector sends built-in defaults for device metadata.

If you still see this error, make sure you are using the latest version of the package.

---

### `device_name cannot be blank`

The connector sends a built-in default device name.

If this error appears, check that your local code is not overriding the default device metadata with empty values.

---

### Encrypted values instead of plaintext credentials

This is expected when using raw sync mode.

```go
client.ListSecrets(ctx)
```

returns encrypted cipher payloads.

Use decrypted mode instead:

```go
client.ListDecryptedSecrets(ctx)
```

and provide:

```sh
export VAULTWARDEN_MASTER_PASSWORD="my-master-password"
```

---

### Unsupported KDF type

Current native decryption supports PBKDF2-based vault profiles only:

```text
kdfType=0
```

If your account uses Argon2, decryption will fail.

Possible options:

* configure the account with PBKDF2;
* add Argon2 KDF support to the connector;
* use raw mode only.

---

### Incorrect scope

The connector uses the `api` scope by default.

If your server requires a different behavior, verify your Vaultwarden or Bitwarden-compatible API configuration.

---

### Reverse proxy strips `Authorization` header

Make sure your reverse proxy forwards the `Authorization` header to Vaultwarden.

For example, with Nginx:

```nginx
proxy_set_header Authorization $http_authorization;
```

Also re-check any authentication middleware or upstream rules after proxy changes.

---

## 🧩 **Compatibility Note**

Vaultwarden is compatible with Bitwarden client APIs, but not all Bitwarden Public API endpoints are necessarily supported.

This connector targets the client API behavior needed for authentication, sync, and supported item decryption.

---

## 🤝 **Contributing**

Contributions are welcome.

You can help by:

* reporting bugs;
* suggesting features;
* improving compatibility;
* adding tests;
* extending KDF support;
* improving item type coverage.

Suggested workflow:

```sh
git checkout -b feature/my-feature
git commit -m "Add my feature"
git push origin feature/my-feature
```

Then open a pull request.

---

## 📄 **License**

This project is licensed under the MIT License.

---

## ❤️ **Support**

A simple star on this project repo is enough to keep me motivated for days. If you’re excited about this project, let me know with a tweet.
If you have any questions, feel free to reach out to me on [X](https://x.com/xxPHDxx).
If you use **goVaultwarden**, feedback, issues, and pull requests are welcome.

