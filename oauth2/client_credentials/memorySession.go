package client_credentials

import (
	"fmt"
	"sync"

	"golang.org/x/oauth2"
)

type memorySessionHooks struct {
	mu           sync.RWMutex
	sessionState map[string]any
}

func NewMemorySessionHooks() *memorySessionHooks {
	return &memorySessionHooks{
		sessionState: make(map[string]any),
	}
}

// GetPostAuthRedirect implements SessionHooks.
func (t *memorySessionHooks) GetPostAuthRedirect() (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	val, exists := t.sessionState["post_auth_redirect"]
	if !exists || val == nil {
		return "", fmt.Errorf("post_auth_redirect not found in session state")
	}
	redirect, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("post_auth_redirect is not of type string")
	}
	return redirect, nil
}

// SetPostAuthRedirect implements SessionHooks.
func (t *memorySessionHooks) SetPostAuthRedirect(redirect string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if redirect == "" {
		return fmt.Errorf("redirect cannot be empty")
	}
	t.sessionState["post_auth_redirect"] = redirect
	return nil
}

// GetState implements SessionHooks.
func (t *memorySessionHooks) GetState() (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	val, exists := t.sessionState["state"]
	if !exists || val == nil {
		return "", fmt.Errorf("state not found in session state")
	}
	state, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("state is not of type string")
	}
	return state, nil
}

// GetToken implements SessionHooks.
func (t *memorySessionHooks) GetRawToken() (*oauth2.Token, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	val, exists := t.sessionState["kinde_token"]
	if !exists || val == nil {
		return nil, fmt.Errorf("kinde_token not found in session state")
	}
	token, ok := val.(*oauth2.Token)
	if !ok {
		return nil, fmt.Errorf("kinde_token is not of type *oauth2.Token")
	}
	return token, nil
}

// SetState implements SessionHooks.
func (t *memorySessionHooks) SetState(state string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state == "" {
		return fmt.Errorf("state cannot be empty")
	}
	t.sessionState["state"] = state
	return nil
}

// SetToken implements SessionHooks.
func (t *memorySessionHooks) SetRawToken(token *oauth2.Token) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessionState["kinde_token"] = token
	return nil
}
