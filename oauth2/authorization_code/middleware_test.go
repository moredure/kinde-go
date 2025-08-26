package authorization_code

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

// MockSessionHooks is a mock implementation of ISessionHooks for testing
type MockSessionHooks struct {
	mock.Mock
}

// MockAuthorizationCodeFlow is a mock implementation of IAuthorizationCodeFlow for testing
type MockAuthorizationCodeFlow struct {
	token *jwt.Token
}

// Middleware implements the IAuthorizationCodeFlow interface
func (m *MockAuthorizationCodeFlow) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a new context with the token using the correct contextKey type
		ctx := context.WithValue(r.Context(), contextKey("kinde_token"), m.token)

		// Create a new request with the updated context
		newReq := r.WithContext(ctx)

		// Call the next handler with the updated request
		next.ServeHTTP(w, newReq)
	})
}

func (m *MockSessionHooks) SetRawToken(token *oauth2.Token) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockSessionHooks) GetRawToken() (*oauth2.Token, error) {
	args := m.Called()
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *MockSessionHooks) GetState() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockSessionHooks) SetState(state string) error {
	args := m.Called(state)
	return args.Error(0)
}

func (m *MockSessionHooks) SetPostAuthRedirect(redirect string) error {
	args := m.Called(redirect)
	return args.Error(0)
}

func (m *MockSessionHooks) GetPostAuthRedirect() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockSessionHooks) SetCodeVerifier(codeVerifier string) error {
	args := m.Called(codeVerifier)
	return args.Error(0)
}

func (m *MockSessionHooks) GetCodeVerifier() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func TestMiddleware(t *testing.T) {
	t.Run("successfully injects token into context", func(t *testing.T) {
		// Create a mock token
		mockJWTToken := &jwt.Token{}

		// Create a mock flow that implements the interface
		mockFlow := &MockAuthorizationCodeFlow{
			token: mockJWTToken,
		}

		// Create a test handler that checks for token in context
		var tokenFromContext *jwt.Token
		var tokenFound bool

		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenFromContext, tokenFound = TokenFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		// Create middleware
		middleware := mockFlow.Middleware(testHandler)

		// Create test request
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		// Call middleware
		middleware.ServeHTTP(w, req)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, tokenFound, "Token should be found in context")
		assert.NotNil(t, tokenFromContext, "Token should not be nil")
		assert.Equal(t, mockJWTToken, tokenFromContext, "Token should match the mock token")
	})

	t.Run("continues without token when session error occurs", func(t *testing.T) {
		// Create mock session hooks that return error
		mockHooks := &MockSessionHooks{}

		// Setup mock expectations to return error
		mockHooks.On("GetRawToken").Return((*oauth2.Token)(nil), assert.AnError)

		// Create flow with mock hooks
		flow := &AuthorizationCodeFlow{
			sessionHooks: mockHooks,
		}

		// Create a test handler
		var tokenFromContext *jwt.Token
		var tokenFound bool

		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenFromContext, tokenFound = TokenFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		// Create middleware
		middleware := flow.InjectTokenMiddleware(testHandler)

		// Create test request
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		// Call middleware
		middleware.ServeHTTP(w, req)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)
		assert.False(t, tokenFound, "Token should not be found in context")
		assert.Nil(t, tokenFromContext, "Token should be nil")

		mockHooks.AssertExpectations(t)
	})
}

func TestTokenFromContext(t *testing.T) {
	t.Run("returns token when present in context", func(t *testing.T) {
		// Create a mock token
		mockToken := &jwt.Token{}

		// Create context with token using the correct contextKey type
		ctx := context.WithValue(context.Background(), contextKey("kinde_token"), mockToken)

		// Extract token from context
		token, found := TokenFromContext(ctx)

		// Assertions
		assert.True(t, found, "Token should be found")
		assert.Equal(t, mockToken, token, "Token should match")
	})

	t.Run("returns false when token not present in context", func(t *testing.T) {
		// Create context without token
		ctx := context.Background()

		// Extract token from context
		token, found := TokenFromContext(ctx)

		// Assertions
		assert.False(t, found, "Token should not be found")
		assert.Nil(t, token, "Token should be nil")
	})

	t.Run("returns false when wrong type in context", func(t *testing.T) {
		// Create context with wrong type
		ctx := context.WithValue(context.Background(), contextKey("kinde_token"), "not_a_token")

		// Extract token from context
		token, found := TokenFromContext(ctx)

		// Assertions
		assert.False(t, found, "Token should not be found")
		assert.Nil(t, token, "Token should be nil")
	})
}
