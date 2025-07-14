package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type configMock struct {
	SomeField string `mapstructure:"some_field"`
}

func TestNewCliSession(t *testing.T) {

	assert := assert.New(t)

	session, err := NewCliSession("test-cli")
	assert.Nil(err)
	assert.NotNil(session)

}
