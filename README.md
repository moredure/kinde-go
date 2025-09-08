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

The `authorization_code` package provides OAuth2 authorization code flow implementations for Go applications:

| Flow Type | Description | Use Case | Documentation Link |
| --- | --- | --- | --- |
| **Browser-based** | Standard authorization code flow for web applications | Web apps with user interaction | [Standard Authorization Code Flow](oauth2/authorization_code/README.md#standard-authorization-code-flow) |
| **Device Flow** | Device authorization flow for limited input devices | CLIs, TVs, IoT devices | [Device Authorization Flow](oauth2/authorization_code/README.md#device-authorization-flow) |

### Key Features

- Session management and token validation
- Offline support with refresh token management
- Middleware integration for popular Go frameworks
- Comprehensive token validation options

## Client Credentials Flow

For comprehensive information about the client credentials flow, see [oauth2/client_credentials/README.md](oauth2/client_credentials/README.md).

The `client_credentials` package provides OAuth2 client credentials flow implementation for machine-to-machine communication. This flow is designed for server-to-server authentication and doesn't involve human input. It requires a Kinde M2M application and proper session hooks implementation for secure token storage.

### Management API

For comprehensive information about using the Kinde Management API, including authentication, setup, and usage examples, see [README_MANAGEMENT_API.md](README_MANAGEMENT_API.md).

The Management API allows you to programmatically manage your Kinde tenant, including creating applications, managing users, configuring settings, and more. It requires M2M applications with Management API enabled and appropriate scopes configured.

### JWT Package

The `jwt` package provides comprehensive JWT parsing, validation, and management capabilities. For detailed documentation, examples, and use cases, see the [JWT Package README](jwt/README.md).

**Quick Overview:**

- Parse JWT tokens from HTTP headers, strings, session storage, or OAuth2 tokens
- Flexible validation options (algorithm, audience, issuer, claims, etc.)
- JWKS support for token signature validation
- Comprehensive token information access
- Seamless integration with OAuth2 flows

## Examples

This repository includes several examples demonstrating different authentication flows:

- **CLI Example** (`examples/cli`): Demonstrates device authorization flow and secure token storage
- **Gin Chat Example** (`examples/gin-chat`): Shows how to integrate Kinde authentication with a Gin web application

For detailed documentation on each flow:

- **Authorization Code Flow**: [oauth2/authorization_code/README.md](oauth2/authorization_code/README.md)
- **Client Credentials Flow**: [oauth2/client_credentials/README.md](oauth2/client_credentials/README.md)
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
