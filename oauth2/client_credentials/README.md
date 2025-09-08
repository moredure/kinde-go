# Client Credentials Flow

The `client_credentials` package provides OAuth2 client credentials flow implementation for Go applications. This package is imported as `github.com/kinde-oss/kinde-go/oauth2/client_credentials`.

## Overview

The client credentials flow is designed for machine-to-machine communication which doesn't involve human input. It requires a Kinde M2M application and is ideal for server-to-server authentication scenarios.

## Go Imports

```go
import (
    "github.com/kinde-oss/kinde-go/oauth2/client_credentials" // required
    "github.com/kinde-oss/kinde-go/oauth2/client_credentials/cli" // optional - for CLI session storage
    "github.com/kinde-oss/kinde-go/jwt" // optional - for JWT token validation
)
```

## Basic Usage

```go
kindeClient, err := client_credentials.NewClientCredentialsFlow(
  "<issuer URL>",                                                       // Kinde subdomain or any auth provider conforming to the spec
  "<client_id>",                                                        // required for client_credentials
  "<client_secret>",                                                    // required for client_credentials
  client_credentials.WithAudience("[your API audience]"),                             // optionally include your API audience
  client_credentials.WithScopes(),                                                    // optional - request API scopes
  client_credentials.WithKindeManagementAPI("<https://my_kinde_tenant.kinde.com>"),   // adds kinde management API audience - see README_MANAGEMENT_API.md for details
  client_credentials.WithSessionHooks(<ISessionHooks implementation>),                // example of CLI is cli.NewCliSession(...)
  client_credentials.WithTokenValidation(                                             // validates tokens when a new token is acquired
    true,                                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                                        // will validate the token alg is RS256
    jwt.WillValidateAudience("<your API audience>"),                  // will confirm that received token includes correct audience
  ),
)
```

## Available Methods

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `GetClient` | Returns an HTTP client that uses the received token and manages refresh/access token lifetime. | ctx `context.Context` | `(*http.Client, error)` |
| `GetToken` | Returns the `*jwt.Token`; reads from session storage if present and refreshes when token expires. | ctx `context.Context` | `(*jwt.Token, error)` |

## Using Client to Request Authorized Endpoints

The client will manage tokens in the background, reading/persisting them to the provided session storage.

```go
// This client will cache the token and re-fetch a new one as it expires
client, err := kindeClient.GetClient(context.Background())
if err != nil {
  // handle initialization error (e.g., invalid config or token source)
  log.Fatalf("failed to init client: %v", err)
}

// example call to Kinde Management API (client needs WithKindeManagementAPI(...)) - see README_MANAGEMENT_API.md for details
response, err := client.Get("<an authorized URL>")
```

## Session Management

The client credentials flow requires session hooks to be implemented for token storage and retrieval. The session hooks interface allows you to customize how tokens are stored and retrieved based on your application's needs.

### CLI Session Storage

We provide a pre-built CLI session storage `cli.NewCliSession(...)` that uses the respective operating system secrets storage for securely storing tokens.

```go
import "github.com/kinde-oss/kinde-go/oauth2/client_credentials/cli"

// Create a CLI session storage
sessionStorage := cli.NewCliSession("your-app-name")

kindeClient, err := client_credentials.NewClientCredentialsFlow(
  "<issuer URL>",
  "<client_id>",
  "<client_secret>",
  client_credentials.WithSessionHooks(sessionStorage),
  // ... other options
)
```

## Token Validation

The client credentials flow supports comprehensive token validation options:

- **Signature Validation**: Validates token signatures using JWKS
- **Algorithm Validation**: Ensures tokens use the expected algorithm (e.g., RS256)
- **Audience Validation**: Confirms tokens include the correct API audience
- **Custom Validation**: Additional validation rules can be implemented

```go
kindeClient, err := client_credentials.NewClientCredentialsFlow(
  "<issuer URL>",
  "<client_id>",
  "<client_secret>",
  client_credentials.WithTokenValidation(
    true,                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                        // will validate the token alg is RS256
    jwt.WillValidateAudience("<your API audience>"),    // will confirm that received token includes correct audience
  ),
)
```

## Management API Integration

The client credentials flow can be configured to work with the Kinde Management API by using the `WithKindeManagementAPI` option:

```go
kindeClient, err := client_credentials.NewClientCredentialsFlow(
  "<issuer URL>",
  "<client_id>",
  "<client_secret>",
  client_credentials.WithKindeManagementAPI("<https://my_kinde_tenant.kinde.com>"),
  // ... other options
)
```

For comprehensive information about using the Kinde Management API, see [README_MANAGEMENT_API.md](../../README_MANAGEMENT_API.md).

## Configuration Options

### WithAudience

Specifies the API audience for the token request:

```go
client_credentials.WithAudience("https://api.example.com")
```

### WithScopes

Requests specific API scopes:

```go
client_credentials.WithScopes("read:users", "write:users")
```

### WithKindeManagementAPI

Enables Kinde Management API integration:

```go
client_credentials.WithKindeManagementAPI("https://my_kinde_tenant.kinde.com")
```

### WithSessionHooks

Provides custom session storage implementation:

```go
client_credentials.WithSessionHooks(mySessionHooks)
```

### WithTokenValidation

Configures token validation options:

```go
client_credentials.WithTokenValidation(
  true,                                               // enable signature validation
  jwt.WillValidateAlgorithm(),                        // validate algorithm
  jwt.WillValidateAudience("your-api"),              // validate audience
)
```

## Examples

For complete examples demonstrating the client credentials flow, see the `examples/` directory in the main repository:

- **CLI Example**: Demonstrates client credentials flow with secure token storage
- **Management API Examples**: Shows how to use the flow with Kinde Management API

## Security Considerations

- Always use HTTPS in production
- Store client credentials securely
- Implement proper session management using the provided session hooks
- Validate tokens on each request
- Use appropriate scopes and audiences for your application
- Rotate client credentials regularly
- Implement proper error handling and logging

## Dependencies

This package requires Go 1.24+ and depends on the following packages:

- `github.com/kinde-oss/kinde-go/jwt` - For JWT token handling and validation
- Standard Go packages: `context`, `net/http`, `oauth2`
