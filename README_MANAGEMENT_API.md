# Kinde Management API

This guide explains how to connect to and use the Kinde Management API with the Go SDK.

## Overview

The Kinde Management API allows you to programmatically manage your Kinde tenant, including creating applications, managing users, configuring settings, and more. This API is designed for machine-to-machine (M2M) communication and requires proper authentication and authorization.

## Prerequisites

- A Kinde account with a tenant
- A Machine-to-Machine (M2M) application configured in your Kinde tenant
- Management API access enabled for your M2M application
- Appropriate scopes configured for the operations you need to perform

## Authentication

The Management API uses the **Client Credentials flow** for authentication, which is designed for machine-to-machine communication without human interaction.

### Setting up Client Credentials Flow

```go
import (
    "github.com/kinde-oss/kinde-go/oauth2/client_credentials"
    "github.com/kinde-oss/kinde-go/oauth2/client_credentials/cli"
)

kindeClient, err := client_credentials.NewClientCredentialsFlow(
    "<issuer URL>",                                                       // Kinde subdomain or any auth provider conforming to the spec
    "<client_id>",                                                        // required for client_credentials
    "<client_secret>",                                                    // required for client_credentials
    client_credentials.WithAudience("[your API audience]"),               // optionally include your API audience
    client_credentials.WithScopes()                                       // optional - request API scopes
    client_credentials.WithKindeManagementAPI("<https://my_kinde_tenant.kinde.com>"),   // adds kinde management API audience
    client_credentials.WithSessionHooks(cli.NewCliSession("my-app-name")), // implement secure token storage
    client_credentials.WithTokenValidation(                               // validates tokens when a new token is acquired
        true,                                                             // will validate token signature via JWKS
        jwt.WillValidateAlgorithm(),                                      // will validate the token alg is RS256
        jwt.WillValidateAudience("<your API audience>"),                  // will confirm that received token includes correct audience
    ),
)
```

### Key Configuration Options

- **`WithKindeManagementAPI()`**: This is essential for Management API access. It automatically adds the correct Management API audience to your token requests.
- **`WithSessionHooks()`**: Implement secure token storage. We provide several pre-built session storage options.
- **`WithTokenValidation()`**: Ensures tokens are properly validated before use.

## Session Management

The client credentials flow requires session hooks to store and retrieve authentication tokens. The SDK provides several session storage implementations to suit different use cases:

### CLI Session (Recommended for CLI Applications)

The CLI session uses your operating system's secure keychain/keyring for token storage:

```go
import (
    "github.com/kinde-oss/kinde-go/frameworks/cli"
)

cliSession, err := cli.NewCliSession("my-app-name")
if err != nil {
    // Handle error
}

kindeClient, err := client_credentials.NewClientCredentialsFlow(
    "<issuer URL>",
    "<client_id>",
    "<client_secret>",
    client_credentials.WithSessionHooks(cliSession),
    client_credentials.WithKindeManagementAPI("<https://my_kinde_tenant.kinde.com>"),
)
```

**Features:**

- Uses OS-native secure storage (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux)
- Automatically handles token chunking for large tokens
- Secure by default with proper access controls
- Ideal for command-line tools and desktop applications

### Memory Session (Default, Good for Testing)

If no session hooks are provided, the SDK defaults to an in-memory session:

```go
// No session hooks specified - uses memory session by default
kindeClient, err := client_credentials.NewClientCredentialsFlow(
    "<issuer URL>",
    "<client_id>",
    "<client_secret>",
    client_credentials.WithKindeManagementAPI("<https://my_kinde_tenant.kinde.com>"),
)
```

**Features:**

- Tokens stored in memory (lost when process terminates)
- Thread-safe with proper locking
- Good for testing and short-lived processes
- No external dependencies

### Custom Session Implementation

For production applications, you can implement your own session storage.

**Use Cases:**

- Database-backed storage for web applications
- Redis for distributed systems
- Encrypted file storage
- Integration with existing session management systems

## Creating the Management API Client

Once you have your client credentials flow configured, you can create the Management API client:

```go
import (
    "github.com/kinde-oss/kinde-go/kinde"
)

managementApi, err := kinde.NewManagementAPI(ctx, "<kinde domain>", <client credentials flow>)
if err != nil {
    // Handle error
}
```

## Usage Examples

### Creating an Application

```go
res, err := managementApi.CreateApplication(ctx, &management_api.CreateApplicationReq{
    Name: "Backend app",
    Type: management_api.CreateApplicationReqTypeReg,
})
if err != nil {
    // Handle error
}
```

### Handling Responses

The Management API methods return interfaces that can be one of several response types. Always check the response type:

```go
switch response := res.(type) {
case management_api.CreateApplicationBadRequest:
    // Handle bad request (incorrect input parameters)
    fmt.Printf("Bad request: %v\n", response)

case management_api.CreateApplicationForbidden:
    // Handle forbidden (usually missing scope)
    fmt.Printf("Forbidden: %v\n", response)

case management_api.CreateApplicationTooManyRequests:
    // Handle throttling
    fmt.Printf("Too many requests: %v\n", response)

case management_api.CreateApplicationResponse:
    // Handle successful response
    fmt.Printf("Application created: %v\n", response)

default:
    // Handle unexpected response type
    fmt.Printf("Unexpected response type: %T\n", response)
}
```

### Using the HTTP Client

The client credentials flow provides an HTTP client that automatically manages tokens:

```go
// This client will cache the token and re-fetch a new one as it expires
client, err := kindeClient.GetClient(context.Background())
if err != nil {
    // Handle error
}

// Example call to Kinde Management API (client needs WithKindeManagementAPI(...))
response, err := client.Get("<an authorized URL>")
if err != nil {
    // Handle error
}
```

## Available Operations

The Management API provides comprehensive access to manage your Kinde tenant. Key areas include:

- **Applications**: Create, read, update, and delete applications
- **Users**: Manage user accounts and profiles
- **Organizations**: Handle multi-tenant organization structures
- **APIs**: Configure API endpoints and settings
- **Permissions**: Manage roles and permissions
- **Settings**: Configure tenant-wide settings

## Security Considerations

- **Token Storage**: Always use secure token storage. The CLI session storage uses your OS's secure storage, but for production applications, implement appropriate security measures.
- **Session Implementation**: Choose the right session storage for your use case:
  - **CLI Session**: Best for command-line tools and desktop applications
  - **Memory Session**: Only for testing and short-lived processes
  - **Custom Session**: Implement with proper encryption and access controls for production
- **Scope Limitation**: Only request the scopes your application actually needs.
- **Audience Validation**: Always validate that tokens include the correct audience.
- **Token Refresh**: The SDK automatically handles token refresh, but ensure your session storage can persist refresh tokens.
- **Token Persistence**: Ensure your session storage can handle token size and implements proper cleanup for expired tokens.

## Error Handling

The Management API uses standard HTTP status codes and provides detailed error information. Common scenarios include:

- **400 Bad Request**: Invalid input parameters
- **401 Unauthorized**: Invalid or expired token
- **403 Forbidden**: Insufficient permissions or missing scope
- **429 Too Many Requests**: Rate limiting applied
- **500 Internal Server Error**: Server-side issues

## Rate Limiting

The Management API implements rate limiting to ensure fair usage. If you encounter 429 responses, implement appropriate backoff strategies.

## Getting Help

- **Documentation**: Visit [Kinde Docs](https://kinde.com/docs/)
- **Community**: Join the [Kinde Community Slack](https://thekindecommunity.slack.com)
- **Issues**: Report bugs or request features on [GitHub](https://github.com/kinde-oss/kinde-go)

## Example CLI Application

See the `examples/cli` directory for a complete example of how to implement a CLI tool that uses the Management API with proper authentication and session management.
