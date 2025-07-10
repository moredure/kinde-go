package kinde

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kinde-oss/kinde-go/kinde/management_api"
	"github.com/stretchr/testify/assert"
)

type (
	testKeys struct {
		PrivateKey  string
		PublicKey   string
		Fingerprint string
		JwkKeySet   string
	}
)

func TestManagementAPI(t *testing.T) {
	assert := assert.New(t)

	tokenCallCount := 0
	issuerURL := ""
	kindeAPIUrl := ""
	validBearerHeaders := []string{}
	authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		switch r.URL.Path {
		case "/.well-known/jwks":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(testSigningKeys.JwkKeySet))
			return
		case "/oauth2/token":
			r.ParseForm()
			testTime := r.FormValue("test_time")
			i, err := strconv.ParseInt(testTime, 10, 64)
			testTimeTravel := time.Now()
			if err == nil {
				tt := time.Unix(i, 0)
				testTimeTravel = tt
			}
			jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss":   issuerURL,
				"aud":   kindeAPIUrl,
				"sub":   "test_user",
				"exp":   testTimeTravel.Add(24 * time.Hour).Unix(),
				"iat":   testTimeTravel.Add(-1 * time.Hour).Add(-5 * time.Minute).Unix(), //so we don't get: Token used before issued
				"nonce": "TEST_NONCE",
				"jti":   uuid.New().String(),
			})
			jwtToken.Header["kid"] = testSigningKeys.Fingerprint
			privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(testSigningKeys.PrivateKey))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			accessToken, err := jwtToken.SignedString(privateKey)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			validBearerHeaders = append(validBearerHeaders, fmt.Sprintf("Bearer %v", accessToken))
			w.Header().Set("Content-Type", "application/json")
			w.Write(fmt.Appendf(nil, `{"access_token": "%v", "id_token": "test_id_token"}`, accessToken))
			tokenCallCount++
			return
		case "/api/v1/applications":
			headerAuth := r.Header.Get("Authorization")
			if !slices.Contains(validBearerHeaders, headerAuth) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error": "invalid_token"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"code": "test code", "message": "test message", "application": {"id": "test_id", "client_id": "test_client_id", "client_secret": "test_client_secret"}}`))
			return
		default:
			panic(fmt.Sprintf("unknown path %s", r.URL.Path))
		}

	}))
	defer authorizationServer.Close()
	issuerURL = authorizationServer.URL
	kindeAPIUrl = fmt.Sprintf("%s/api", authorizationServer.URL)

	ctx := context.Background()
	kindeManagementAPI, err := NewManagementAPI(ctx, issuerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret")
	assert.NotNil(kindeManagementAPI, "management API client should not be nil")
	assert.Nil(err, "error creating management API client")

	res, err := kindeManagementAPI.CreateApplication(ctx, &management_api.CreateApplicationReq{
		Name: "Backend app",
		Type: management_api.CreateApplicationReqTypeReg,
	})
	assert.Nil(err, "error creating application")
	assert.NotNil(res, "response should not be nil")
}

var testSigningKeys = &testKeys{
	PrivateKey:  "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtm8LFy10tmMGf9v00djsnDUPkLG3WIOGq8fUr6UhF6E7vezP\nVI4OTfPrU37yRJx2ApvVhxT27xXxTV4kf0iD1qNaMbIR/07/E5g7djA8IuyWnPAE\nul5KIIm1bU+BVw+LZw7hTrHkXrqO4qZDtApiM1nsiETMNdJ8BVj4cLBdTJTgxz2e\ninvyD7sB+zRqKEFp1WjV3IPIwz69H8nidNoRLfi/plkcpAsZakknHdzTD6s+73Aa\npypeR4m2ff/kfabjyJweTq+WtIzU79jAfgd6zTWGuawDZy5BRDiB8fJw+yN77n9x\nHZnXhJqzCbNhQ02FAx6Kw0XfFKSqHOaVoIFApQIDAQABAoIBAQCvjATZBbWUN4+u\ngyJ+t0VfPrO+oTPzKYTyUXT4m2ZPjaemJ3SOQa/EFR3yF2ra2M+5zOhYdrTy9WNf\n9mIaVNYAOOn2fgpRaVuMKGW3YczMMmrvkwqJp2efDcQV7nZgJyYWQjxN9GHzQYNy\n11i4q3E5RqOTsNfsRqFup+FQ1nTA1bSBafFbtUf+SdHVyXr5psQjqMCRlQd+gsV2\n3dD1YJkDGIcfycWOwJfMkY+3eXXvB/IrBjANKzSkKOeEFJOa4f7aQveLJ0qydEdV\nqddzm9Jskk3joQweMEtY095CNhybxxCps21Z2ap5kL+II2sFCdY70A6/2+cEUbow\ngv+0nIX1AoGBAMdqJrU7S+Gcig7rhmS3R+kgk/7bI94Sy77Y1I27cdLodsVLhno/\nzUe8aQBK/RhkWIzRAUz0NPJrRCG4uKPMGY/mS+WjjjDYmlosLjZGH420BVsXg2Qh\naBsYf1bQHJkbBUVDxSkH9SH1hfT1ZJ1+rx5eUZa26MYeLqGcrx3bLS0TAoGBAOoz\nXm94jxOU34I04Q6yP044tvYl4f4rFFsW5tCslt0/je2TC93ryAED/a3GffCZ0boP\nKvx/sfNE+oT808Vwb7LuOGz+e8P5XbGvQ0NvsIfwljoNhMz8IElgtMact4c09RoU\n0hDKNgDLpZhHQgBQCE1lP75g/fgiGduP3GfhNSpnAoGAIKSXwYL7YOsnDlovnb0C\n4H6cu1NUA74/6/XClZDhiQzUpGdAlDJtgBivd4TO+Xczp5lvBRHUuPomJP7/+pAm\nfw/LzMOBOy251pj0152S/LdDSS4ILBPr3sOb1LIsfEOYEUaOt7C9x9lRHFAvMDjU\nobv+zxUR9ZxrNblYUSLXulECgYEAwrARQPknd0+6vbLXpC/pEE11SwoS5AdL1K0l\nEzNl9mZuxaAHrWPjz3RR3bOz3d8AyXrycRR2CZS97O9/3BGryULfBTxIBpG1oY/g\nip6+UUNensO+MeklrdoGbVS5/Fu5pQTJ28s9OUwRTJVv+HKPdEdGxiw685rlg/AD\neRdt6uECgYBZ/iyW0/+X7QcmKTqgTfRt/D8OmzFNX2ba6NZgUCshldizLHoXPwmn\ndKNNEc0kP+JtnnylX0rSrVQ9P1hC47YgLck/JApbDQ+HWLIQAwFJljd8qWWIYPqX\nCqzEzSVEcZVri0r8fPzQGHwGJ4xmXDesQIb5jsjIGELp6AXn26EWQQ==\n-----END PRIVATE KEY-----\n",
	PublicKey:   "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtm8LFy10tmMGf9v00djs\nnDUPkLG3WIOGq8fUr6UhF6E7vezPVI4OTfPrU37yRJx2ApvVhxT27xXxTV4kf0iD\n1qNaMbIR/07/E5g7djA8IuyWnPAEul5KIIm1bU+BVw+LZw7hTrHkXrqO4qZDtApi\nM1nsiETMNdJ8BVj4cLBdTJTgxz2einvyD7sB+zRqKEFp1WjV3IPIwz69H8nidNoR\nLfi/plkcpAsZakknHdzTD6s+73AapypeR4m2ff/kfabjyJweTq+WtIzU79jAfgd6\nzTWGuawDZy5BRDiB8fJw+yN77n9xHZnXhJqzCbNhQ02FAx6Kw0XfFKSqHOaVoIFA\npQIDAQAB\n-----END PUBLIC KEY-----\n",
	Fingerprint: "5e:99:54:a3:11:cc:56:52:09:3f:4a:d8:38:99:5e:12",
	JwkKeySet: `{
        "keys": [{
            "e": "AQAB",
            "kty": "RSA",
            "n": "tm8LFy10tmMGf9v00djsnDUPkLG3WIOGq8fUr6UhF6E7vezPVI4OTfPrU37yRJx2ApvVhxT27xXxTV4kf0iD1qNaMbIR_07_E5g7djA8IuyWnPAEul5KIIm1bU-BVw-LZw7hTrHkXrqO4qZDtApiM1nsiETMNdJ8BVj4cLBdTJTgxz2einvyD7sB-zRqKEFp1WjV3IPIwz69H8nidNoRLfi_plkcpAsZakknHdzTD6s-73AapypeR4m2ff_kfabjyJweTq-WtIzU79jAfgd6zTWGuawDZy5BRDiB8fJw-yN77n9xHZnXhJqzCbNhQ02FAx6Kw0XfFKSqHOaVoIFApQ",
            "alg": "RS256",
            "kid": "5e:99:54:a3:11:cc:56:52:09:3f:4a:d8:38:99:5e:12",
            "use": "sig"
            }]
        }`,
}
