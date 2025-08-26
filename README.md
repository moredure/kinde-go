# Kinde Go SDK

The Kinde SDK for Go.

> **📚 Management API**: For comprehensive information about using the Kinde Management API, see [README_MANAGEMENT_API.md](README_MANAGEMENT_API.md).

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Development

Requires Go 1.24+

### Usage

```bash
go get github.com/kinde-oss/kinde-go
go mod tidy
```

## Authorization Code Flow

For comprehensive information about the authorization code flow and device authorization flow, see [oauth2/authorization_code/README.md](oauth2/authorization_code/README.md).

The `authorization_code` package provides OAuth2 authorization code flow implementations for Go applications, including:

- Standard authorization code flow for web applications
- Device authorization flow for devices with limited input capabilities
- Session management and token validation
- Offline support with refresh token management

## Client credentials flow

`client_credentials` package, imported as `github.com/kinde-oss/kinde-go/oauth2/client_credentials`.

This flow is designed for machine-to-machine communication which doesn't involve human input. It requires Kinde M2M application. Please implement session hooks to store tokens accordingly to your security practices.

We provide a pre-built CLI session storage `cli.NewCliSession(...)`, it uses respective operating system secrets storage for securely storing tokens.

```go
kindeClient, err := client_credentials.NewClientCredentialsFlow(
  "<issuer URL>",                                                       // Kinde subdomain or any auth provider conforming to the spec
  "<client_id>",                                                        // required for client_credentials
  "<client_secret>",                                                    // required for client_credentials
  client_credentials.WithAudience("[your API audience]"),                             // optioanlly include your API audience
  client_credentials.WithScopes()                                                     // optional - request API scopes
  client_credentials.WithKindeManagementAPI("<https://my_kinde_tenant.kinde.com>"),   // adds kinde management API audience - see README_MANAGEMENT_API.md for details
  client_credentials.WithSessionHooks(<ISessionHooks implementation>),		            // example of CLI is cli.NewCliSession(...)
  client_credentials.WithTokenValidation(                                             // validates tokens when a new token is aquired
    true,                                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                                        // will validate the token alg is RS256
    jwt.WillValidateAudience("<your API audience>"),                  // will confirm that received token includes correct audience
  ),
)
```

`kindeClient` exposes the following methods:

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `GetClient` | Returns an HTTP client that uses the received token and manages refresh/access token lifetime. | ctx `context.Context` | `(*http.Client, error)` |
| `GetToken` | Returns the `*jwt.Token`; reads from session storage if present and refreshes when token expires. | ctx `context.Context` | `(*jwt.Token, error)` |

#### Using client to request an authorized endpoint

Client willl manage tokens in the background, reading/persisting them to provided the session storage.

When offline scope is requested, refresh tokens will be managed as well.

```go
// This client will cache the token and re-fetch a new one as it expires
client, err := kindeClient.GetClient(context.Background())
if err != nil {
  // handle initialization error (e.g., invalid config or token source)
  log.Fatalf("failed to init client: %v", err)
}
```

// example call to Kinde Management API (client needs WithKindeManagementAPI(...)) - see README_MANAGEMENT_API.md for details response, err := client.Get("<an authorized URL>")

### Management API

For comprehensive information about using the Kinde Management API, including authentication, setup, and usage examples, see [README_MANAGEMENT_API.md](README_MANAGEMENT_API.md).

The Management API allows you to programmatically manage your Kinde tenant, including creating applications, managing users, configuring settings, and more. It requires M2M applications with Management API enabled and appropriate scopes configured.

### JWT helpers

`jwt` package, imported with `github.com/kinde-oss/kinde-go/jwt`

The `jwt` package exposes the following methods:

| Function Name | Description | Parameters | Returns |
| --- | --- | --- | --- |
| ParseFromAuthorizationHeader | Parses the token from the HTTP Authorization header and validates it using the provided options. | r *http.Request, options ...func(*Token) | (\*Token, error) |
| ParseFromString | Parses the given raw access token string and validates it using the provided options. | rawAccessToken string, options ...func(\*Token) | (\*Token, error) |
| ParseFromSessionStorage | Parses the token from a session storage string (JSON), extracts extra fields, and validates it with options. | rawToken string, options ...func(\*Token) | (\*Token, error) |
| ParseOAuth2Token | Parses the given OAuth2 token and validates it using the provided options. | rawToken *oauth2.Token, options ...func(*Token) | (\*Token, error) |

### JWT token helpers

| Function Name | Description | Parameters | Returns |
| --- | --- | --- | --- |
| GetRawToken | Returns the raw OAuth2 token. | none | \*oauth2.Token |
| GetIdToken | Retrieves the ID token if present. | none | (string, bool) |
| GetAccessToken | Retrieves the access token if present. | none | (string, bool) |
| GetRefreshToken | Retrieves the refresh token if present. | none | (string, bool) |
| AsString | Returns the raw token as a JSON string. | none | (string, error) |
| IsValid | Indicates if the token is valid. | none | bool |
| GetSubject | Returns the subject claim from the token. | none | string |
| GetClaims | Returns all claims from the token as a map. | none | map[string]any |
| GetValidationErrors | Returns any validation errors encountered during parsing. | none | error |

## Examples

This repository includes several examples demonstrating different authentication flows:

- **CLI Example** (`examples/cli`): Demonstrates device authorization flow and secure token storage
- **Gin Chat Example** (`examples/gin-chat`): Shows how to integrate Kinde authentication with a Gin web application

For detailed documentation on each flow:

- **Authorization Code Flow**: [oauth2/authorization_code/README.md](oauth2/authorization_code/README.md)
- **Client Credentials Flow**: See the Client Credentials Flow section below
- **Management API**: [README_MANAGEMENT_API.md](README_MANAGEMENT_API.md)

For Management API examples and detailed usage, see [README_MANAGEMENT_API.md](README_MANAGEMENT_API.md).

### SDK Development

1. Clone the repository to your machine:

   ```bash
   git clone https://github.com/kinde-oss/kinde-go.git
   ```

2. Go into the project:

   ```bash
   cd kinde-go
   ```

3. Install the dependencies:

   ```bash
   go mod download
   ```

## Documentation

For details on integrating this SDK into your project, head over to the [Kinde docs](https://kinde.com/docs/) and see the [Go SDK](<[link-to-kinde-doc](https://kinde.com/docs/developer-tools/)>) doc 👍🏼.

## Publishing

The core team handles publishing.

## Contributing

Please refer to Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/489e2ca9c3307c2b2e098a885e22f2239116394a/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.

```

```
