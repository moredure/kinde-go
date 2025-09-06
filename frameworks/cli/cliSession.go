package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/99designs/keyring"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

const (
	keyPrefix = "kinde"
)

type (
	cliSession struct {
		keyring keyring.Keyring
	}

	ICliSession interface {
		authorization_code.ISessionHooks
		SetKey(key string, value []byte) error
		GetKey(key string) ([]byte, error)
		DeleteKey(key string) error
	}
)

// DeleteKey removes key from keyring.
func (c *cliSession) DeleteKey(key string) error {
	countKey := fmt.Sprintf("%s_chunk_count", key)
	errs := make([]error, 0)
	err := c.keyring.Remove(key)
	if err != nil {
		// If the key doesn't exist, it's not an error
		if errors.Is(err, keyring.ErrKeyNotFound) {
			err = nil
		}
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to remove key %q: %w", key, err))
	}
	// Remove chunked keys and chunk count
	if chunks, err := c.getChunkCount(countKey); err == nil {
		for i := range chunks {
			chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
			if err := c.keyring.Remove(chunkKey); err != nil {
				break
			}
		}
	}
	err = c.keyring.Remove(countKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to remove chunk count: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("error while deleting a key %q: %v", key, errs)
	}
	return nil
}

// GetKey reads key from keyring.
func (c *cliSession) GetKey(key string) ([]byte, error) {
	countKey := fmt.Sprintf("%s_chunk_count", key)

	// Try to get chunk count
	chunks, err := c.getChunkCount(countKey)
	if err != nil {
		// fallback to single ringItem (old format)
		ringItem, err := c.keyring.Get(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get token: %w", err)
		}
		return ringItem.Data, nil
	}

	var keyData []byte
	for i := range chunks {
		chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
		chunkItem, err := c.keyring.Get(chunkKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get token chunk %d: %w", i, err)
		}
		keyData = append(keyData, chunkItem.Data...)
	}
	return keyData, nil
}

// GetCodeVerifier implements authorization_code.ISessionHooks.
func (c *cliSession) GetCodeVerifier() (string, error) {
	key := fmt.Sprintf("%s_code_verifier", keyPrefix)
	item, err := c.keyring.Get(key)
	if err != nil {
		return "", fmt.Errorf("code_verifier not found: %w", err)
	}
	return string(item.Data), nil
}

// SetCodeVerifier implements authorization_code.ISessionHooks.
func (c *cliSession) SetCodeVerifier(codeVerifier string) error {
	key := fmt.Sprintf("%s_code_verifier", keyPrefix)
	if codeVerifier == "" {
		// remove when empty to avoid leaving secrets behind
		_ = c.keyring.Remove(key)
		return nil
	}
	return c.keyring.Set(keyring.Item{
		Key:  key,
		Data: []byte(codeVerifier),
	})
}

func (c *cliSession) getChunkCount(key string) (int, error) {
	countItem, err := c.keyring.Get(key)
	if err != nil {
		return 0, fmt.Errorf("failed to get token chunk count: %w", err)
	}

	var chunks int
	if _, err := fmt.Sscanf(string(countItem.Data), "%d", &chunks); err != nil {
		return 0, fmt.Errorf("failed to parse token chunk count: %w", err)
	}
	return chunks, nil
}

// GetRawToken implements authorization_code.ISessionHooks.
func (c *cliSession) GetRawToken() (*oauth2.Token, error) {
	key := fmt.Sprintf("%s_token", keyPrefix)

	tokenData, err := c.GetKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %w", err)
	}

	var t oauth2.Token
	if err := json.Unmarshal(tokenData, &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	return &t, nil
}

// SetRawToken implements authorization_code.ISessionHooks.
func (c *cliSession) SetRawToken(token *oauth2.Token) error {
	key := fmt.Sprintf("%s_token", keyPrefix)

	if token == nil {
		return c.DeleteKey(key)
	}

	t, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	err = c.SetKey(key, t)
	if err != nil {
		return err
	}

	return nil
}

func (c *cliSession) SetKey(key string, value []byte) error {
	countKey := fmt.Sprintf("%s_chunk_count", key)

	if len(value) == 0 {
		// Remove legacy single-key entry
		return c.DeleteKey(key)
	}

	const chunkSize = 1024
	chunks := (len(value) + chunkSize - 1) / chunkSize

	// Try to get chunk count
	if chunks, err := c.getChunkCount(countKey); err == nil {
		// Remove any existing chunks
		for i := range chunks {
			chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
			if err := c.keyring.Remove(chunkKey); err != nil {
				break
			}
		}
	}

	// Save chunks
	for i := range chunks {
		start := i * chunkSize
		end := min(start+chunkSize, len(value))
		chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
		if err := c.keyring.Set(keyring.Item{
			Key:  chunkKey,
			Data: value[start:end],
		}); err != nil {
			return fmt.Errorf("failed to save token chunk %d: %w", i, err)
		}
	}

	// Save chunk count
	countKey = fmt.Sprintf("%s_chunk_count", key)
	countData := fmt.Appendf(nil, "%d", chunks)
	if err := c.keyring.Set(keyring.Item{
		Key:  countKey,
		Data: countData,
	}); err != nil {
		return fmt.Errorf("failed to save chunk count: %w", err)
	}
	return nil
}

// GetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) GetPostAuthRedirect() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// GetState implements authorization_code.SessionHooks.
func (c *cliSession) GetState() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// SetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) SetPostAuthRedirect(redirect string) error {
	return fmt.Errorf("not supported in CLI session")
}

// SetState implements authorization_code.SessionHooks.
func (c *cliSession) SetState(state string) error {
	return fmt.Errorf("not supported in CLI session")
}

func normalizeServiceName(name string) string {
	// Replace special characters and spaces that could cause issues in keychain
	normalized := strings.ReplaceAll(name, "/", "_")
	normalized = strings.ReplaceAll(normalized, ":", "_")
	normalized = strings.ReplaceAll(normalized, ".", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	return normalized
}

func NewCliSession(serviceName string, opts ...Option) (ICliSession, error) {

	// In NewCliSession:
	getPassFunc := func(prompt string) (string, error) {
		if pass := os.Getenv("KINDE_KEYCHAIN_PASS"); pass != "" {
			return pass, nil
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", fmt.Errorf("Cannot initialize keychain, please run in interactive terminal first to provide password or provide KINDE_KEYCHAIN_PASS environment variable")
		}
		fmt.Printf("%s", prompt)
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("\nError reading password:", err)
			return "", err
		}
		return string(password), nil
	}

	// Default values
	keychainName := fmt.Sprintf("kinde_cli/%s", normalizeServiceName(serviceName))
	serviceNameNorm := normalizeServiceName(serviceName)

	// Collect options (could be passed in as variadic args to NewCliSession)
	defaultOpts := []Option{
		WithAllowedBackends([]keyring.BackendType{keyring.WinCredBackend, keyring.KeychainBackend, keyring.FileBackend}),
		WithKeychainTrustApplication(true),
		WithServiceName(serviceNameNorm),
		WithKeychainName(keychainName),
		WithKeychainPasswordFunc(getPassFunc),
		WithFilePasswordFunc(getPassFunc),
		WithFileDir(fmt.Sprintf("~/.config/%s", serviceNameNorm)),
	}

	opts = append(defaultOpts, opts...)

	// Build config using options
	var cfg keyring.Config
	for _, opt := range opts {
		opt(&cfg)
	}

	ring, err := keyring.Open(cfg)

	if err != nil {
		return nil, err
	}

	return &cliSession{
		keyring: ring,
	}, nil
}
