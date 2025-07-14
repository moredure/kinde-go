package authorization_code

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

const (
	RawToken     TokenType = "raw_token"
	IDToken      TokenType = "id_token"
	AccessToken  TokenType = "access_token"
	RefreshToken TokenType = "refresh_token"
)

type (
	TokenType string

	SessionHooks interface {
		GetState() (string, error)
		SetState(state string) error
		SetToken(t TokenType, token string) error
		GetToken(t TokenType) (string, error)
		SetPostAuthRedirect(redirect string) error
		GetPostAuthRedirect() (string, error)
	}

	// AuthorizationCodeFlow represents the authorization code flow.
	AuthorizationCodeFlow struct {
		config         oauth2.Config
		authURLOptions url.Values
		JWKS_URL       string
		tokenOptions   []func(*jwt.Token)
		sessionHooks   SessionHooks
		stateGenerator func(from *AuthorizationCodeFlow) string
		stateVerifier  func(flow *AuthorizationCodeFlow, receivedState string) bool
	}
)

func (flow *AuthorizationCodeFlow) GetToken() (*jwt.Token, error) {
	return flow.parseFromSesisonStorage()
}

func (flow *AuthorizationCodeFlow) IsAuthenticated() bool {
	accessToken, err := flow.sessionHooks.GetToken(AccessToken)
	if err != nil {
		return false
	}

	refreshToken, _ := flow.sessionHooks.GetToken(RefreshToken)

	tokenSource := flow.config.TokenSource(context.Background(), &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	token, err := tokenSource.Token()
	if err != nil {
		return false
	}
	if token != nil {
		parsedToken, err := flow.validateAndStoreToken(token)
		if err != nil {
			return false
		}
		return parsedToken.IsValid()
	}
	return false
}

// Creates a new AuthorizationCodeFlow with the given baseURL, clientID, clientSecret and options to authenticate backend applications.
func NewAuthorizationCodeFlow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...func(*AuthorizationCodeFlow)) (*AuthorizationCodeFlow, error) {
	options = append([]func(*AuthorizationCodeFlow){WithScopes("openid", "profile", "email")}, options...) // prepending default openid scopes when nothing requested
	return newAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL, options...)
}

// Creates a new AuthorizationCodeFlow with the given baseURL, clientID, clientSecret and options to authenticate backend applications.
func NewDeviceAuthorizationFlow(baseURL string, options ...func(*AuthorizationCodeFlow)) (*AuthorizationCodeFlow, error) {
	return newAuthorizationCodeFlow(baseURL, "", "", "", options...)
}

func newAuthorizationCodeFlow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...func(*AuthorizationCodeFlow)) (*AuthorizationCodeFlow, error) {
	asURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := asURL.Hostname()

	if asURL.Port() != "" {
		host = fmt.Sprintf("%v:%v", host, asURL.Port())
	}

	client := &AuthorizationCodeFlow{
		JWKS_URL: fmt.Sprintf("%v://%v/.well-known/jwks", asURL.Scheme, host),
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{},
			Endpoint: oauth2.Endpoint{
				TokenURL:      fmt.Sprintf("%v://%v/oauth2/token", asURL.Scheme, host),
				AuthURL:       fmt.Sprintf("%v://%v/oauth2/auth", asURL.Scheme, host),
				DeviceAuthURL: fmt.Sprintf("%v://%v/oauth2/device/auth", asURL.Scheme, host),
				AuthStyle:     oauth2.AuthStyleInParams,
			},
		},
		authURLOptions: url.Values{},
		stateGenerator: func(flow *AuthorizationCodeFlow) string {
			state := fmt.Sprintf("ks_%v", strings.ReplaceAll(uuid.NewString(), "-", ""))
			flow.sessionHooks.SetState(state)
			return state
		},
		stateVerifier: func(flow *AuthorizationCodeFlow, receivedState string) bool {
			state, err := flow.sessionHooks.GetState()
			if err != nil {
				return false
			}
			return state == receivedState
		},
	}

	for _, o := range options {
		o(client)
	}

	if client.sessionHooks == nil {
		return nil, fmt.Errorf("session hooks are not set, please connect your session management with WithSessionHooks")
	}

	return client, nil
}

// Exchanges the authorization code for a token and established KindeContext
func (flow *AuthorizationCodeFlow) ExchangeCode(ctx context.Context, authorizationCode string, receivedState string) error {
	storedState, err := flow.sessionHooks.GetState()
	if err != nil {
		return fmt.Errorf("failed to get state from session: %w", err)
	}

	if storedState == "" {
		return fmt.Errorf("state not found in session")
	}

	if storedState != receivedState {
		return fmt.Errorf("state mismatch: expected %s, got %s", storedState, receivedState)
	}

	token, err := flow.config.Exchange(ctx, authorizationCode)

	if err != nil {
		return err
	}

	_, err = flow.validateAndStoreToken(token)
	return err
}

// ExchangeDeviceAccessToken retrieves the access token for the device authorization flow.
func (flow *AuthorizationCodeFlow) ExchangeDeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse, opts ...oauth2.AuthCodeOption) error {

	token, err := flow.config.DeviceAccessToken(ctx, da, opts...)

	if err != nil {
		return err
	}

	_, err = flow.validateAndStoreToken(token)

	return err
}

func (flow *AuthorizationCodeFlow) parseFromSesisonStorage() (*jwt.Token, error) {
	rawToken, err := flow.sessionHooks.GetToken(RawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get raw token from session: %w", err)
	}
	parsedToken, err := jwt.ParseFromSessionStorage(rawToken, flow.tokenOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw token: %w", err)
	}
	return parsedToken, nil
}

func (flow *AuthorizationCodeFlow) validateAndStoreToken(token *oauth2.Token) (*jwt.Token, error) {
	jwtToken, err := jwt.ParseOAuth2Token(token, flow.tokenOptions...)
	if err != nil {
		return jwtToken, err
	}

	rawToken, err := jwtToken.AsString()
	if err != nil {
		return nil, err
	}

	flow.sessionHooks.SetToken(RawToken, rawToken)

	if idToken, ok := jwtToken.GetIdToken(); ok {
		flow.sessionHooks.SetToken(IDToken, idToken)
	}
	if accessToken, ok := jwtToken.GetAccessToken(); ok {
		flow.sessionHooks.SetToken(AccessToken, accessToken)
	}
	if refreshToken, ok := jwtToken.GetRefreshToken(); ok {
		flow.sessionHooks.SetToken(RefreshToken, refreshToken)
	}
	return jwtToken, nil
}

// Returns the client to make requests to the backend, will refreesh token if offline is requested.
func (flow *AuthorizationCodeFlow) GetClient(ctx context.Context, tokenSource oauth2.TokenSource) *http.Client {
	return oauth2.NewClient(ctx, tokenSource)
}
