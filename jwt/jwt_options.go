package jwt

import (
	"crypto/rsa"
	"fmt"
	"slices"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

type Option func(*Token)

// WillValidateWithPublicKey receives a token and needs to return a public RSA key to validate the token signature.
func WillValidateWithPublicKey(keyFunc func(rawToken string) (*rsa.PublicKey, error)) Option {
	return func(s *Token) {
		wrapped := func(token *golangjwt.Token) (interface{}, error) {
			return keyFunc(token.Raw)
		}
		s.processing.keyFunc = wrapped
	}
}

// WillValidateWithJWKSUrl will validate the token with the given JWKS URL.
func WillValidateWithJWKSUrl(url string) Option {
	client, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		PrioritizeHTTP:    false,
		HTTPURLs:          map[string]jwkset.Storage{url: nil},
		RateLimitWaitMax:  time.Minute,
		RefreshUnknownKID: rate.NewLimiter(rate.Every(5*time.Minute), 1),
	})
	if err != nil {
		return func(s *Token) {
			s.validationErrors = append(s.validationErrors, fmt.Errorf("failed to create JWK client: %w", err))
		}
	}

	options := keyfunc.Options{
		Storage: client,
	}

	jwks, err := keyfunc.New(options)
	if err != nil {
		return nil
	}

	return func(s *Token) {
		s.processing.keyFunc = jwks.Keyfunc
	}
}

// WillValidateWithKeyFunc will validate the token with the given keyFunc.
func WillValidateWithKeyFunc(keyFunc func(*golangjwt.Token) (interface{}, error)) Option {
	return func(s *Token) {
		s.processing.keyFunc = keyFunc
	}
}

// WillValidateWithTimeFunc will validate the token with the given time, used for testing.
func WillValidateWithTimeFunc(timeFunc func() time.Time) Option {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithTimeFunc(timeFunc))
	}
}

// WillValidateWithClockSkew will validate the token with the allowed clock skew.
func WillValidateWithClockSkew(leeway time.Duration) Option {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithLeeway(leeway))
	}
}

// WillValidateAlgorithm will validate the token with the given algorithm, defaults to RS256.
func WillValidateAlgorithm(alg ...string) func(*Token) {
	return func(s *Token) {
		if len(alg) > 0 {
			s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithValidMethods(alg))
		} else {
			s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithValidMethods([]string{"RS256"}))
		}
	}
}

func WillValidateIssuer(issuer string) Option {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithIssuer(issuer))
	}
}

// WillValidateAudience will validate the audience is present in the token.
func WillValidateAudience(expectedAudience string) Option {
	return func(s *Token) {
		f := func(receivedClaims golangjwt.MapClaims) (bool, error) {
			aud, err := receivedClaims.GetAudience()
			if err != nil {
				return false, err
			}
			if !slices.Contains(aud, expectedAudience) {
				return false, fmt.Errorf("audience not valid %v", expectedAudience)
			}
			return true, nil
		}
		s.processing.validations = append(s.processing.validations, f)
	}
}

// WillValidateClaims will validate the claims with the given function.
func WillValidateClaims(f func(golangjwt.MapClaims) (bool, error)) Option {
	return func(s *Token) {
		s.processing.validations = append(s.processing.validations, f)
	}
}

func newError(message string, err error, more ...error) error {
	var format string
	var args []any
	if message != "" {
		format = "%w: %s"
		args = []any{err, message}
	} else {
		format = "%w"
		args = []any{err}
	}

	for _, e := range more {
		format += ": %w"
		args = append(args, e)
	}

	err = fmt.Errorf(format, args...)
	return err
}
