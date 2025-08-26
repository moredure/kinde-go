package client_credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestNewMemorySessionHooks(t *testing.T) {
	hooks := NewMemorySessionHooks()

	assert.NotNil(t, hooks)
	assert.NotNil(t, hooks.sessionState)
	assert.Equal(t, 0, len(hooks.sessionState))
}

func TestMemorySessionHooks_SetPostAuthRedirect(t *testing.T) {
	hooks := NewMemorySessionHooks()

	tests := []struct {
		name        string
		redirect    string
		expectError bool
	}{
		{
			name:        "valid redirect",
			redirect:    "https://example.com/callback",
			expectError: false,
		},
		{
			name:        "empty redirect",
			redirect:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hooks.SetPostAuthRedirect(tt.redirect)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "redirect cannot be empty")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMemorySessionHooks_GetPostAuthRedirect(t *testing.T) {
	hooks := NewMemorySessionHooks()

	// Test getting non-existent redirect
	redirect, err := hooks.GetPostAuthRedirect()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "post_auth_redirect not found in session state")
	assert.Equal(t, "", redirect)

	// Test setting and getting valid redirect
	expectedRedirect := "https://example.com/callback"
	err = hooks.SetPostAuthRedirect(expectedRedirect)
	assert.NoError(t, err)

	redirect, err = hooks.GetPostAuthRedirect()
	assert.NoError(t, err)
	assert.Equal(t, expectedRedirect, redirect)
}

func TestMemorySessionHooks_SetState(t *testing.T) {
	hooks := NewMemorySessionHooks()

	tests := []struct {
		name        string
		state       string
		expectError bool
	}{
		{
			name:        "valid state",
			state:       "random_state_string",
			expectError: false,
		},
		{
			name:        "empty state",
			state:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hooks.SetState(tt.state)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "state cannot be empty")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMemorySessionHooks_GetState(t *testing.T) {
	hooks := NewMemorySessionHooks()

	// Test getting non-existent state
	state, err := hooks.GetState()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "state not found in session state")
	assert.Equal(t, "", state)

	// Test setting and getting valid state
	expectedState := "random_state_string"
	err = hooks.SetState(expectedState)
	assert.NoError(t, err)

	state, err = hooks.GetState()
	assert.NoError(t, err)
	assert.Equal(t, expectedState, state)
}

func TestMemorySessionHooks_SetRawToken(t *testing.T) {
	hooks := NewMemorySessionHooks()

	// Test setting nil token
	err := hooks.SetRawToken(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token cannot be nil")

	// Test setting valid token
	validToken := &oauth2.Token{
		AccessToken: "test_access_token",
		TokenType:   "Bearer",
	}

	err = hooks.SetRawToken(validToken)
	assert.NoError(t, err)
}

func TestMemorySessionHooks_GetRawToken(t *testing.T) {
	hooks := NewMemorySessionHooks()

	// Test getting non-existent token
	token, err := hooks.GetRawToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kinde_token not found in session state")
	assert.Nil(t, token)

	// Test setting and getting valid token
	expectedToken := &oauth2.Token{
		AccessToken: "test_access_token",
		TokenType:   "Bearer",
	}

	err = hooks.SetRawToken(expectedToken)
	assert.NoError(t, err)

	token, err = hooks.GetRawToken()
	assert.NoError(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestMemorySessionHooks_Concurrency(t *testing.T) {
	hooks := NewMemorySessionHooks()

	// Test concurrent access to ensure thread safety
	done := make(chan bool)

	// Goroutine 1: Set operations
	go func() {
		for i := 0; i < 100; i++ {
			hooks.SetState("state")
			hooks.SetPostAuthRedirect("redirect")
			hooks.SetRawToken(&oauth2.Token{AccessToken: "token"})
		}
		done <- true
	}()

	// Goroutine 2: Get operations
	go func() {
		for i := 0; i < 100; i++ {
			hooks.GetState()
			hooks.GetPostAuthRedirect()
			hooks.GetRawToken()
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Verify final state
	state, err := hooks.GetState()
	assert.NoError(t, err)
	assert.Equal(t, "state", state)

	redirect, err := hooks.GetPostAuthRedirect()
	assert.NoError(t, err)
	assert.Equal(t, "redirect", redirect)

	token, err := hooks.GetRawToken()
	assert.NoError(t, err)
	assert.Equal(t, "token", token.AccessToken)
}

func TestMemorySessionHooks_Isolation(t *testing.T) {
	// Test that different instances don't share state
	hooks1 := NewMemorySessionHooks()
	hooks2 := NewMemorySessionHooks()

	// Set values in first instance
	err := hooks1.SetState("state1")
	assert.NoError(t, err)
	err = hooks1.SetPostAuthRedirect("redirect1")
	assert.NoError(t, err)

	// Verify second instance is empty
	state, err := hooks2.GetState()
	assert.Error(t, err)
	assert.Equal(t, "", state)

	redirect, err := hooks2.GetPostAuthRedirect()
	assert.Error(t, err)
	assert.Equal(t, "", redirect)

	// Verify first instance still has values
	state, err = hooks1.GetState()
	assert.NoError(t, err)
	assert.Equal(t, "state1", state)

	redirect, err = hooks1.GetPostAuthRedirect()
	assert.NoError(t, err)
	assert.Equal(t, "redirect1", redirect)
}

func TestMemorySessionHooks_TypeSafety(t *testing.T) {
	hooks := NewMemorySessionHooks()

	// Test that setting wrong types doesn't break the interface
	// This simulates what could happen if the internal map is accessed directly

	// Manually set wrong type in session state (simulating external tampering)
	hooks.mu.Lock()
	hooks.sessionState["post_auth_redirect"] = 123 // wrong type
	hooks.sessionState["state"] = true             // wrong type
	hooks.sessionState["kinde_token"] = "string"   // wrong type
	hooks.mu.Unlock()

	// Test that GetPostAuthRedirect handles wrong type gracefully
	redirect, err := hooks.GetPostAuthRedirect()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "post_auth_redirect is not of type string")
	assert.Equal(t, "", redirect)

	// Test that GetState handles wrong type gracefully
	state, err := hooks.GetState()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "state is not of type string")
	assert.Equal(t, "", state)

	// Test that GetRawToken handles wrong type gracefully
	token, err := hooks.GetRawToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kinde_token is not of type *oauth2.Token")
	assert.Nil(t, token)
}
