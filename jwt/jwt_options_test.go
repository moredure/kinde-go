package jwt

import (
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
)

func TestWillValidateClaims(t *testing.T) {
	tests := []struct {
		name          string
		claimsFunc    func(golangjwt.MapClaims) (bool, error)
		expectedValid bool
	}{
		{
			name: "valid claims",
			claimsFunc: func(claims golangjwt.MapClaims) (bool, error) {
				return true, nil
			},
			expectedValid: true,
		},
		{
			name: "invalid claims",
			claimsFunc: func(claims golangjwt.MapClaims) (bool, error) {
				return false, nil
			},
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateClaims(tt.claimsFunc)
			opt(token)

			if len(token.processing.validations) != 1 {
				t.Errorf("expected 1 validation function, got %d", len(token.processing.validations))
			}

			result, err := token.processing.validations[0](golangjwt.MapClaims{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expectedValid {
				t.Errorf("expected validation result %v, got %v", tt.expectedValid, result)
			}
		})
	}
}
func TestWillValidateAudience(t *testing.T) {
	tests := []struct {
		name           string
		expectedAud    string
		claims         golangjwt.MapClaims
		expectedValid  bool
		expectedErrMsg string
	}{
		{
			name:          "valid audience",
			expectedAud:   "test-aud",
			claims:        golangjwt.MapClaims{"aud": []string{"test-aud"}},
			expectedValid: true,
		},
		{
			name:           "invalid audience",
			expectedAud:    "test-aud",
			claims:         golangjwt.MapClaims{"aud": []string{"wrong-aud"}},
			expectedValid:  false,
			expectedErrMsg: "audience not valid test-aud",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateAudience(tt.expectedAud)
			opt(token)

			if len(token.processing.validations) != 1 {
				t.Errorf("expected 1 validation function, got %d", len(token.processing.validations))
			}

			result, err := token.processing.validations[0](tt.claims)
			if tt.expectedErrMsg != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedErrMsg)
				} else if err.Error() != tt.expectedErrMsg {
					t.Errorf("expected error %q, got %q", tt.expectedErrMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expectedValid {
				t.Errorf("expected validation result %v, got %v", tt.expectedValid, result)
			}
		})
	}
}
func TestWillValidateIssuer(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
	}{
		{
			name:   "sets issuer validation",
			issuer: "test-issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateIssuer(tt.issuer)
			opt(token)

			if len(token.processing.parsingOptions) != 1 {
				t.Errorf("expected 1 parsing option, got %d", len(token.processing.parsingOptions))
			}
		})
	}
}
func TestWillValidateAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		algs     []string
		expected []string
	}{
		{
			name:     "no algorithms provided - defaults to RS256",
			algs:     []string{},
			expected: []string{"RS256"},
		},
		{
			name:     "single algorithm provided",
			algs:     []string{"HS256"},
			expected: []string{"HS256"},
		},
		{
			name:     "multiple algorithms provided",
			algs:     []string{"RS256", "HS256", "ES256"},
			expected: []string{"RS256", "HS256", "ES256"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateAlgorithm(tt.algs...)
			opt(token)

			if len(token.processing.parsingOptions) != 1 {
				t.Errorf("expected 1 parsing option, got %d", len(token.processing.parsingOptions))
			}
		})
	}
}
func TestWillValidateWithClockSkew(t *testing.T) {
	tests := []struct {
		name   string
		leeway time.Duration
	}{
		{
			name:   "sets clock skew validation with 5 minutes",
			leeway: 5 * time.Minute,
		},
		{
			name:   "sets clock skew validation with 1 second",
			leeway: time.Second,
		},
		{
			name:   "sets clock skew validation with zero duration",
			leeway: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateWithClockSkew(tt.leeway)
			opt(token)

			if len(token.processing.parsingOptions) != 1 {
				t.Errorf("expected 1 parsing option, got %d", len(token.processing.parsingOptions))
			}
		})
	}
}
func TestWillValidateWithTimeFunc(t *testing.T) {
	tests := []struct {
		name     string
		timeFunc func() time.Time
	}{
		{
			name: "sets time validation function",
			timeFunc: func() time.Time {
				return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateWithTimeFunc(tt.timeFunc)
			opt(token)

			if len(token.processing.parsingOptions) != 1 {
				t.Errorf("expected 1 parsing option, got %d", len(token.processing.parsingOptions))
			}
		})
	}
}
func TestWillValidateWithKeyFunc(t *testing.T) {
	tests := []struct {
		name    string
		keyFunc func(*golangjwt.Token) (interface{}, error)
	}{
		{
			name: "sets key validation function",
			keyFunc: func(token *golangjwt.Token) (interface{}, error) {
				return []byte("test-key"), nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateWithKeyFunc(tt.keyFunc)
			opt(token)

			if token.processing.keyFunc == nil {
				t.Error("expected keyFunc to be set, got nil")
			}

			result, err := token.processing.keyFunc(&golangjwt.Token{})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result == nil {
				t.Error("expected non-nil result from keyFunc")
			}
		})
	}
}
func TestWillValidateWithPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		keyFunc func(string) (*rsa.PublicKey, error)
		token   *golangjwt.Token
		wantErr bool
	}{
		{
			name: "valid public key function",
			keyFunc: func(raw string) (*rsa.PublicKey, error) {
				return &rsa.PublicKey{}, nil
			},
			token:   &golangjwt.Token{Raw: "test-token"},
			wantErr: false,
		},
		{
			name: "error from public key function",
			keyFunc: func(raw string) (*rsa.PublicKey, error) {
				return nil, fmt.Errorf("key error")
			},
			token:   &golangjwt.Token{Raw: "test-token"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{}
			opt := WillValidateWithPublicKey(tt.keyFunc)
			opt(token)

			if token.processing.keyFunc == nil {
				t.Error("expected keyFunc to be set, got nil")
			}

			result, err := token.processing.keyFunc(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == nil {
					t.Error("expected non-nil result from keyFunc")
				}
			}
		})
	}
}
