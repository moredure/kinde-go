package cli

import (
	"encoding/json"
	"errors"
	"path"
	"testing"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestNewCliSession(t *testing.T) {

	assert := assert.New(t)

	opts := []Option{WithFileDir(path.Join(t.TempDir(), ".test_keyring")), WithAllowedBackends([]keyring.BackendType{keyring.FileBackend})}
	session, err := NewCliSession("test-cli", opts...)
	assert.Nil(err)
	assert.NotNil(session)

}

// mockKeyring implements keyring.Keyring for testing
type mockKeyring struct {
	items      map[string]keyring.Item
	getErrs    map[string]error
	RemoveFunc func(key string) error
}

func (m *mockKeyring) Get(key string) (keyring.Item, error) {
	if err, ok := m.getErrs[key]; ok {
		return keyring.Item{}, err
	}
	item, ok := m.items[key]
	if !ok {
		return keyring.Item{}, keyring.ErrKeyNotFound
	}
	return item, nil
}
func (m *mockKeyring) Remove(key string) error {
	if m.RemoveFunc != nil {
		return m.RemoveFunc(key)
	}
	delete(m.items, key)
	return nil
}
func (m *mockKeyring) Set(item keyring.Item) error {
	m.items[item.Key] = item
	return nil
}
func (m *mockKeyring) Keys() ([]string, error) { return nil, nil }
func (m *mockKeyring) Reset() error            { m.items = map[string]keyring.Item{}; return nil }

// GetMetadata implements keyring.Keyring for testing.
func (m *mockKeyring) GetMetadata(key string) (keyring.Metadata, error) {
	return keyring.Metadata{}, nil
}

func TestCliSession_GetRawToken_SingleToken(t *testing.T) {
	assert := assert.New(t)
	token := &oauth2.Token{AccessToken: "abc", TokenType: "Bearer"}
	data, _ := json.Marshal(token)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token": {Key: "kinde_token", Data: data},
		},
		getErrs: map[string]error{
			"kinde_chunk_count": keyring.ErrKeyNotFound,
		},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.Nil(err)
	assert.Equal(token.AccessToken, got.AccessToken)
}

func TestCliSession_GetRawToken_ChunkedToken(t *testing.T) {
	assert := assert.New(t)
	token := &oauth2.Token{AccessToken: "chunked", TokenType: "Bearer"}
	data, _ := json.Marshal(token)
	// Split into 2 chunks
	chunk1 := data[:len(data)/2]
	chunk2 := data[len(data)/2:]
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token_chunk_count": {Key: "kinde_token_chunk_count", Data: []byte("2")},
			"kinde_token_chunk_0":     {Key: "kinde_token_chunk_0", Data: chunk1},
			"kinde_token_chunk_1":     {Key: "kinde_token_chunk_1", Data: chunk2},
		},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.Nil(err)
	assert.Equal(token.AccessToken, got.AccessToken)
}

func TestCliSession_GetRawToken_TokenNotFound(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items:   map[string]keyring.Item{},
		getErrs: map[string]error{"kinde_chunk_count": keyring.ErrKeyNotFound, "kinde_token": keyring.ErrKeyNotFound},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to get token")
}

func TestCliSession_GetRawToken_ChunkCountParseError(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token_chunk_count": {Key: "kinde_token_chunk_count", Data: []byte("notanint")},
		},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to get token")
}

func TestCliSession_GetRawToken_ChunkMissing(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token_chunk_count": {Key: "kinde_token_chunk_count", Data: []byte("1")},
		},
		getErrs: map[string]error{
			"kinde_token_chunk_0": errors.New("not found"),
		},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to get token chunk 0")
}

func TestCliSession_GetRawToken_UnmarshalError(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token": {Key: "kinde_token", Data: []byte("notjson")},
		},
		getErrs: map[string]error{
			"kinde_chunk_count": keyring.ErrKeyNotFound,
		},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to unmarshal token")
}

func TestCliSession_DeleteKey_KeyNotFound(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items:   map[string]keyring.Item{},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	err := cs.DeleteKey("missingkey")
	assert.Nil(err) // Remove should not error if key doesn't exist
}
func TestCliSession_GetKey_SingleKey(t *testing.T) {
	assert := assert.New(t)
	expected := []byte("single_value")
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"mykey": {Key: "mykey", Data: expected},
		},
		getErrs: map[string]error{
			"mykey_chunk_count": keyring.ErrKeyNotFound,
		},
	}
	cs := &cliSession{keyring: mk}
	val, err := cs.GetKey("mykey")
	assert.Nil(err)
	assert.Equal(expected, val)
}

func TestCliSession_GetKey_ChunkedKey(t *testing.T) {
	assert := assert.New(t)
	chunk1 := []byte("chunk1_")
	chunk2 := []byte("chunk2")
	expected := append(chunk1, chunk2...)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"mykey_chunk_count": {Key: "mykey_chunk_count", Data: []byte("2")},
			"mykey_chunk_0":     {Key: "mykey_chunk_0", Data: chunk1},
			"mykey_chunk_1":     {Key: "mykey_chunk_1", Data: chunk2},
		},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	val, err := cs.GetKey("mykey")
	assert.Nil(err)
	assert.Equal(expected, val)
}

func TestCliSession_GetKey_ChunkCountParseError(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"mykey_chunk_count": {Key: "mykey_chunk_count", Data: []byte("notanint")},
		},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	val, err := cs.GetKey("mykey")
	assert.NotNil(err)
	assert.Nil(val)
	assert.Contains(err.Error(), "failed to get token")
}

func TestCliSession_GetKey_ChunkMissing(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"mykey_chunk_count": {Key: "mykey_chunk_count", Data: []byte("1")},
		},
		getErrs: map[string]error{
			"mykey_chunk_0": errors.New("not found"),
		},
	}
	cs := &cliSession{keyring: mk}
	val, err := cs.GetKey("mykey")
	assert.NotNil(err)
	assert.Nil(val)
	assert.Contains(err.Error(), "failed to get token chunk 0")
}

func TestCliSession_GetKey_SingleKeyNotFound(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{},
		getErrs: map[string]error{
			"mykey_chunk_count": keyring.ErrKeyNotFound,
			"mykey":             keyring.ErrKeyNotFound,
		},
	}
	cs := &cliSession{keyring: mk}
	val, err := cs.GetKey("mykey")
	assert.NotNil(err)
	assert.Nil(val)
	assert.Contains(err.Error(), "failed to get token")
}
func TestCliSession_DeleteKey_SingleKey(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"mykey": {Key: "mykey", Data: []byte("value")},
		},
		getErrs: map[string]error{
			"mykey_chunk_count": keyring.ErrKeyNotFound,
		},
	}
	cs := &cliSession{keyring: mk}
	err := cs.DeleteKey("mykey")
	assert.Nil(err)
	_, exists := mk.items["mykey"]
	assert.False(exists)
}

func TestCliSession_DeleteKey_ChunkedKey(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"mykey_chunk_count": {Key: "mykey_chunk_count", Data: []byte("2")},
			"mykey_chunk_0":     {Key: "mykey_chunk_0", Data: []byte("chunk1")},
			"mykey_chunk_1":     {Key: "mykey_chunk_1", Data: []byte("chunk2")},
			"mykey":             {Key: "mykey", Data: []byte("legacy")},
		},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	err := cs.DeleteKey("mykey")
	assert.Nil(err)
	_, exists0 := mk.items["mykey_chunk_0"]
	_, exists1 := mk.items["mykey_chunk_1"]
	_, existsCount := mk.items["mykey_chunk_count"]
	_, existsLegacy := mk.items["mykey"]
	assert.False(exists0)
	assert.False(exists1)
	assert.False(existsCount)
	assert.False(existsLegacy)
}

func TestCliSession_DeleteKey_ChunkRemoveError(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"mykey_chunk_count": {Key: "mykey_chunk_count", Data: []byte("2")},
			"mykey_chunk_0":     {Key: "mykey_chunk_0", Data: []byte("chunk1")},
			"mykey_chunk_1":     {Key: "mykey_chunk_1", Data: []byte("chunk2")},
		},
		getErrs: map[string]error{},
	}
	// Simulate error on removing chunk_0, allow chunk_1 to be removed
	mk.RemoveFunc = func(key string) error {
		if key == "mykey_chunk_0" {
			return errors.New("remove error")
		}
		delete(mk.items, key)
		return nil
	}
	cs := &cliSession{keyring: mk}
	err := cs.DeleteKey("mykey")
	assert.NotNil(err) // Should propagate error
	assert.Contains(err.Error(), "failed to remove chunk 0")
	_, exists0 := mk.items["mykey_chunk_0"]
	_, exists1 := mk.items["mykey_chunk_1"]
	assert.True(exists0)  // chunk_0 not removed due to error
	assert.False(exists1) // chunk_1 should be removed
}

func TestCliSession_DeleteKey_KeyAndChunksNotExist(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items:   map[string]keyring.Item{},
		getErrs: map[string]error{"mykey_chunk_count": keyring.ErrKeyNotFound},
	}
	cs := &cliSession{keyring: mk}
	err := cs.DeleteKey("mykey")
	assert.Nil(err)
}
