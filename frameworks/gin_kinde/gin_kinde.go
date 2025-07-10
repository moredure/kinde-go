package gin_kinde

import (
	"context"
	"fmt"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)

type SessionStorage struct {
	session sessions.Session
}

// GetPostAuthRedirect implements authorization_code.SessionHooks.
func (storage *SessionStorage) GetPostAuthRedirect() string {
	return storage.session.Get("post_auth_redirect").(string)
}

// GetState implements authorization_code.SessionHooks.
func (storage *SessionStorage) GetState() string {
	return storage.session.Get("auth_state").(string)
}

// GetToken implements authorization_code.SessionHooks.
func (storage *SessionStorage) GetToken(t authorization_code.TokenType) string {
	if token, ok := storage.session.Get(fmt.Sprintf("kinde_%v", t)).(string); ok {
		return token
	}
	return ""
}

// SetPostAuthRedirect implements authorization_code.SessionHooks.
func (storage *SessionStorage) SetPostAuthRedirect(redirect string) {
	storage.session.Set("post_auth_redirect", redirect)
	storage.session.Save()
}

// SetState implements authorization_code.SessionHooks.
func (storage *SessionStorage) SetState(state string) {
	storage.session.Set("auth_state", state)
	storage.session.Save()
}

// SetToken implements authorization_code.SessionHooks.
func (storage *SessionStorage) SetToken(t authorization_code.TokenType, token string) {
	storage.session.Set(fmt.Sprintf("kinde_%v", t), token)
	storage.session.Save()
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

func UseKindeAuth(router *gin.RouterGroup, kindeDomain, clientID, clientSecret, baseRedirectURL string, options ...func(*authorization_code.AuthorizationCodeFlow)) error {

	router.Use(func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		sessionStorage := &SessionStorage{session: session}

		basePath := router.BasePath()
		if basePath == "/" {
			basePath = ""
		}
		redirectURI := fmt.Sprintf("%s%s%s", baseRedirectURL, basePath, "/kinde/callback")
		kindeClient, err := authorization_code.NewAuthorizationCodeFlow(kindeDomain,
			clientID,
			clientSecret,
			redirectURI,
			authorization_code.WithSessionHooks(sessionStorage),
			authorization_code.WithTokenValidation(true),
		)

		for _, option := range options {
			option(kindeClient)
		}

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

				if !kindeClient.IsAuthenticated() {
					authURL := kindeClient.GetAuthURL()
					ctx.Redirect(302, authURL)
				}
				return
			}
		}

		ctx.AbortWithError(401, fmt.Errorf("unauthorized"))

	})

	return nil
}
