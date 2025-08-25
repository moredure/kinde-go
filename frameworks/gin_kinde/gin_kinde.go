package gin_kinde

import (
	"context"
	"fmt"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
	"golang.org/x/oauth2"
)

type SessionStorage struct {
	session sessions.Session
}

// GetCodeVerifier implements authorization_code.ISessionHooks.
func (storage *SessionStorage) GetCodeVerifier() (string, error) {
	return storage.session.Get("code_verifier").(string), nil
}

// SetCodeVerifier implements authorization_code.ISessionHooks.
func (storage *SessionStorage) SetCodeVerifier(codeVerifier string) error {
	storage.session.Set("code_verifier", codeVerifier)
	storage.session.Save()
	return nil
}

// GetRawToken implements authorization_code.ISessionHooks.
func (storage *SessionStorage) GetRawToken() (*oauth2.Token, error) {
	token := storage.session.Get("kinde_token")
	if token == nil {
		return nil, fmt.Errorf("token not found in session")
	}
	if t, ok := token.(*oauth2.Token); ok {
		return t, nil
	}
	return nil, fmt.Errorf("invalid token type in session")
}

// SetRawToken implements authorization_code.ISessionHooks.
func (storage *SessionStorage) SetRawToken(token *oauth2.Token) error {
	if token == nil {
		storage.session.Set("kinde_token", nil)
	} else {
		storage.session.Set("kinde_token", token)
	}
	storage.session.Save()
	return nil
}

// GetPostAuthRedirect implements authorization_code.SessionHooks.
func (storage *SessionStorage) GetPostAuthRedirect() (string, error) {
	return storage.session.Get("post_auth_redirect").(string), nil
}

// GetState implements authorization_code.SessionHooks.
func (storage *SessionStorage) GetState() (string, error) {
	return storage.session.Get("auth_state").(string), nil
}

// SetPostAuthRedirect implements authorization_code.SessionHooks.
func (storage *SessionStorage) SetPostAuthRedirect(redirect string) error {
	storage.session.Set("post_auth_redirect", redirect)
	storage.session.Save()
	return nil
}

// SetState implements authorization_code.SessionHooks.
func (storage *SessionStorage) SetState(state string) error {
	storage.session.Set("auth_state", state)
	storage.session.Save()
	return nil
}

func (storage *SessionStorage) GetItem(key string) string {
	value := storage.session.Get(key)
	if value == nil {
		return ""
	}
	return value.(string)
}

func (storage *SessionStorage) SetItem(key, value string) {
	storage.session.Set(key, value)
	storage.session.Save()
}

func UseKindeAuth(router *gin.RouterGroup, kindeDomain, clientID, clientSecret, baseRedirectURL string, options ...authorization_code.Option) error {

	router.Use(func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		sessionStorage := &SessionStorage{session: session}

		basePath := router.BasePath()
		if basePath == "/" {
			basePath = ""
		}

		options = append(options,
			authorization_code.WithSessionHooks(sessionStorage),
			authorization_code.WithTokenValidation(true),
		)

		redirectURI := fmt.Sprintf("%s%s%s", baseRedirectURL, basePath, "/kinde/callback")
		kindeClient, err := authorization_code.NewAuthorizationCodeFlow(kindeDomain,
			clientID,
			clientSecret,
			redirectURI,
			options...,
		)

		if err != nil {
			fmt.Printf("Error creating Kinde client: %v", err)
			ctx.String(500, "Error creating Kinde client")
			ctx.Abort()
			return
		}

		ctx.Set("kinde_client", kindeClient)
	})

	router.GET("/kinde/callback", func(ctx *gin.Context) {
		if client, ok := ctx.Get("kinde_client"); ok {
			if kindeClient, ok := client.(*authorization_code.AuthorizationCodeFlow); ok {
				err := kindeClient.ExchangeCode(context.Background(), ctx.Query("code"), ctx.Query("state"))
				if err != nil {
					ctx.AbortWithError(500, err)
					return
				}
				ctx.Redirect(302, "/")
				return
			}
		}
		ctx.AbortWithError(500, fmt.Errorf("kinde client not found"))
	})

	router.Use(func(ctx *gin.Context) {

		if client, ok := ctx.Get("kinde_client"); ok {
			if kindeClient, ok := client.(*authorization_code.AuthorizationCodeFlow); ok {

				if isAuthenticated, _ := kindeClient.IsAuthenticated(context.Background()); !isAuthenticated {
					authURL := kindeClient.GetAuthURL()
					ctx.Redirect(302, authURL)
					ctx.Abort()
				}
				return
			}
		}

		ctx.AbortWithError(401, fmt.Errorf("unauthorized"))

	})

	return nil
}
