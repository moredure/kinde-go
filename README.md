# Kinde Go SDK

The Kinde SDK for Go.

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Development

Requires Go 1.24+

### Usage

```bash
go get github.com/kinde-oss/kinde-go
go mod tidy
```

## Autorization code flow

`authorization_code` package, imported as `github.com/kinde-oss/kinde-go/oauth2/authorization_code`.

This is a backend authorization flow, which requires slient secret. It is designed to be used as a server-side auth flow and not exposes tokens to the browser. The user session needs to be managed by other means, for example via the session cookie.

```go

kindeAuthFlow, err := authorization_code.NewAuthorizationCodeFlow(
  "<issuer URL>",                                       //Kinde subdomain or any auth provider conforming to the spec
  "<client_id>", "<client_secret>", "<callback URL>",
  authorization_code.WithSessionHooks(<ISessionHooks implementation>),     //example of storage for gin framework is gin_kinde.UseKindeAuth(...)
  authorization_code.WithOffline(),                                        //adds offline scope and starts managing refresh tokens
  authorization_code.WithAudience("<your API audience>"),                  //requesting an API audience
  authorization_code.WithTokenValidation(
    true,                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                        // will validate the token alg is RS256
    jwt.WillValidateAudience("<your API audience>"),    // will confirm that received token includes correct audience
  ),
)

```

`kindeAuthFlow` will now expose the following methods:

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `GetAuthURL` | Returns the URL to redirect the user to start the authentication pipeline. | none | `string` |
| `ExchangeCode` | Exchanges the authorization code for a token and establishes KindeContext. | ctx `context.Context`, authorizationCode `string`, receivedState `string` | `error` |
| `GetClient` | Returns an HTTP client for calling external services, automatically refreshing tokens if offline is requested. | ctx `context.Context` | `(*http.Client, error)` |
| `IsAuthenticated` | Checks if the user is authenticated. | ctx `context.Context` | `(bool, error)` |
| `Logout` | Clears local tokens and logs the user out. | none | `error` |
| `AuthorizationCodeReceivedHandler` | Helper handler middleware for the code exchanger. | w `http.ResponseWriter`, r `*http.Request` | none |

### Device authorization flow

`authorization_code` package, imported as `github.com/kinde-oss/kinde-go/oauth2/authorization_code`.

This is an extension of authorization code flow, which separatees token requester and receiver. It is best used for devices and environment with the limited input capabilities, e.g. CLIs, TVs etc.

```go
deviceFlow, err := authorization_code.NewDeviceAuthorizationFlow(
  "<issuer_domain>",                                    // Kinde subdomain or any auth provider conforming to the spec
  authorization_code.WithClientID(),                    // optional, when business provides a default device applicaiton, otherwise required
  authorization_code.WithClientSecret(),                // optional (used when device flow is used against backend application with a secret)
  authorization_code.WithSessionHooks(<ISessionHooks implementation>),		  // used for storing/retreiving tokens
  authorization_code.WithOffline(),                     // optional - include if you'd like to maintain refresh tokens and a long session
  authorization_code.WithTokenValidation(
    true,                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                        // will validate the token alg is RS256
)
```

`deviceFlow` will provide following methods

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `StartDeviceAuth` | Starts the device authorization flow and returns the device authorization response. | ctx `context.Context` | `(*oauth2.DeviceAuthResponse, error)` |
| `ExchangeDeviceAccessToken` | Exchanges the device code for an access token. | ctx `context.Context`, da `*oauth2.DeviceAuthResponse`, opts `...oauth2.AuthCodeOption` | `error` |
| `GetClient` | Returns an HTTP client for calling external services, automatically refreshing tokens if offline is requested. | ctx `context.Context` | `(*http.Client, error)` |
| `IsAuthenticated` | Checks if the user is authenticated. | ctx `context.Context` | `(bool, error)` |
| `Logout` | Clears local tokens and logs the user out. | none | `error` |
| `GetToken` | Returns the token for the current session. | ctx `context.Context` | `(*jwt.Token, error)` |

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
  client_credentials.WithKindeManagementAPI("<https://my_kinde_tenant.kinde.com>"),   // adds kinde management API audience
  client_credentials.WithSessionHooks(<ISessionHooks implementation>),		            // example of CLI is cli.NewCliSession(...)
  client_credentials.WithTokenValidation(                                             // validates tokens when a new token is aquired
    true,                                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                                        // will validate the token alg is RS256
    jwt.WillValidateAudience("<your API audience>"),                  // will confirm that received token includes correct audience
  ),
)
```

`kindeAuthFlow` will now expose the following methods: | Method | Description | |-------------|-------------------------------------------------------------------------------------------------------| | `GetClient` | Gets HTTP client, which uses the received token and manages refresh/access token lifetime automatically. | | `GetToken` | Gets the `*jwt.Token`, reads from session storage if already received, refreshes when token expires. |

#### Using client to request an authorized endpoint

Client willl manage tokens in the background, reading/persisting them to provided the session storage.

When offline scope is requested, refresh tokens will be managed as well.

```go
  //This client will cache the token and re-fetch a new one as it expires
  client := kindeClient.GetClient(context.Background())

  //example call to Kinde Management API (client needs WithKindeManagementAPI(...))
  response, err := client.Get("<an authorized URL>")

```

### Calling Kinde Management API

`kinde` package, imported with `github.com/kinde-oss/kinde-go/kinde`.

Please note, Kinde management API is only accessible via M2M applications with Management API enabled and limited by the authorized scopes.

You can have multiple applications configured with different levels of access.

Kinde uses generated code to map OpenAPI specification to go.

```go
	managementApi, err := kinde.NewManagementAPI(ctx, "<kinde domain>", <client credentials flow>)  //management API uses client credentials flow described earlier
```

For example to create an application

```
	res, err := managementApi.CreateApplication(ctx, &management_api.CreateApplicationReq{
		Name: "Backend app",
		Type: management_api.CreateApplicationReqTypeReg,
	})
```

This call returns `CreateApplicationRes` interface, which can be one of the following:

| Interface                          | Description                |
| ---------------------------------- | -------------------------- |
| `CreateApplicationBadRequest`      | Incorrect input parameters |
| `CreateApplicationForbidden`       | Usually missing scope      |
| `CreateApplicationTooManyRequests` | Throttled response         |
| `CreateApplicationResponse`        | Successful response        |

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
