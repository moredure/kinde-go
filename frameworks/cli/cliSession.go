package cli

import (
	"encoding/json"
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
)

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
		return 0, fmt.Errorf("failed to get chunk count: %w", err)
	}

	var chunks int
	if _, err := fmt.Sscanf(string(countItem.Data), "%d", &chunks); err != nil {
		return 0, fmt.Errorf("failed to parse chunk count: %w", err)
	}
	return chunks, nil
}

// GetRawToken implements authorization_code.ISessionHooks.
func (c *cliSession) GetRawToken() (*oauth2.Token, error) {
	key := fmt.Sprintf("%s_token", keyPrefix)
	countKey := fmt.Sprintf("%s_chunk_count", key)

	// Try to get chunk count
	chunks, err := c.getChunkCount(countKey)
	if err != nil {
		// fallback to single token (old format)
		token, err := c.keyring.Get(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get token: %w", err)
		}
		var t oauth2.Token
		if err := json.Unmarshal(token.Data, &t); err != nil {
			return nil, fmt.Errorf("failed to unmarshal token: %w", err)
		}
		return &t, nil
	}

	var tokenData []byte
	for i := 0; i < chunks; i++ {
		chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
		chunkItem, err := c.keyring.Get(chunkKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get token chunk %d: %w", i, err)
		}
		tokenData = append(tokenData, chunkItem.Data...)
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
	countKey := fmt.Sprintf("%s_chunk_count", key)

	if token == nil {
		// Remove legacy single-key entry
		_ = c.keyring.Remove(key)
		// Remove chunked keys and chunk count
		if chunks, err := c.getChunkCount(countKey); err == nil {
			for i := range chunks {
				chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
				if err := c.keyring.Remove(chunkKey); err != nil {
					break
				}
			}
		}
		_ = c.keyring.Remove(countKey)
		return nil
	}

	t, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	const chunkSize = 1024
	chunks := (len(t) + chunkSize - 1) / chunkSize

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
		end := min(start+chunkSize, len(t))
		chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
		if err := c.keyring.Set(keyring.Item{
			Key:  chunkKey,
			Data: t[start:end],
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

func NewCliSession(serviceName string) (authorization_code.ISessionHooks, error) {
	ring, err := keyring.Open(keyring.Config{
		KeychainTrustApplication: true,
		ServiceName:              serviceName,
		KeychainName:             strings.ReplaceAll(serviceName, ".", "_"),
		KeychainPasswordFunc: func(prompt string) (string, error) {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return "", fmt.Errorf("cannot initialize keychain, please run in interactive terminal first to provide password")
			}
			fmt.Printf("%s", prompt)
			password, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Println("\nError reading password:", err)
				return "", err
			}
			return string(password), nil
		}})

	if err != nil {
		return nil, err
	}

	return &cliSession{
		keyring: ring,
	}, nil
}
