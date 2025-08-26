package jwt

import (
	"encoding/json"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// GetRawToken returns the raw token.
func (j *Token) GetRawToken() *oauth2.Token {
	return j.rawToken
}

// GetIdToken returns the ID token if it exists.
func (j *Token) GetIdToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	if token, ok := j.rawToken.Extra("id_token").(string); ok {
		return token, true
	}
	return "", false
}

// GetAccessToken returns the access token.
func (j *Token) GetAccessToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	return j.rawToken.AccessToken, j.rawToken.AccessToken != ""
}

// GetRefreshToken returns the refresh token if it exists.
func (j *Token) GetRefreshToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	return j.rawToken.RefreshToken, j.rawToken.RefreshToken != ""
}

// AsString returns the token as a JSON string.
func (j *Token) AsString() (string, error) {
	marshalledToken, err := json.Marshal(j.rawToken)
	if err != nil {
		return "", err
	}
	return string(marshalledToken), nil
}

// IsValid returns if the token is valid.
func (j *Token) IsValid() bool {
	return j.isValid
}

// GetSubject returns the sub claim of the token.
func (j *Token) GetSubject() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	subject, _ := j.processing.parsed.Claims.GetSubject()
	return subject
}

// GetIssuer returns the iss claim of the token.
func (j *Token) GetIssuer() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if issuer, exists := claims["iss"]; exists {
			if issuerStr, ok := issuer.(string); ok {
				return issuerStr
			}
		}
	}
	return ""
}

// GetAudience returns the aud claim of the token.
func (j *Token) GetAudience() []string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if audience, exists := claims["aud"]; exists {
			switch aud := audience.(type) {
			case string:
				return []string{aud}
			case []interface{}:
				result := make([]string, 0, len(aud))
				for _, a := range aud {
					if aStr, ok := a.(string); ok {
						result = append(result, aStr)
					}
				}
				return result
			}
		}
	}
	return nil
}

// GetExpiration returns the exp claim of the token.
func (j *Token) GetExpiration() (int64, bool) {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return 0, false
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if exp, exists := claims["exp"]; exists {
			switch expVal := exp.(type) {
			case float64:
				return int64(expVal), true
			case int64:
				return expVal, true
			case int:
				return int64(expVal), true
			}
		}
	}
	return 0, false
}

// GetIssuedAt returns the iat claim of the token.
func (j *Token) GetIssuedAt() (int64, bool) {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return 0, false
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if iat, exists := claims["iat"]; exists {
			switch iatVal := iat.(type) {
			case float64:
				return int64(iatVal), true
			case int64:
				return iatVal, true
			case int:
				return int64(iatVal), true
			}
		}
	}
	return 0, false
}

// GetJWTID returns the jti claim of the token.
func (j *Token) GetJWTID() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if jti, exists := claims["jti"]; exists {
			if jtiStr, ok := jti.(string); ok {
				return jtiStr
			}
		}
	}
	return ""
}

// GetPermissions returns the permissions claim of the token.
func (j *Token) GetPermissions() []string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if permissions, exists := claims["permissions"]; exists {
			if perms, ok := permissions.([]interface{}); ok {
				result := make([]string, 0, len(perms))
				for _, p := range perms {
					if pStr, ok := p.(string); ok {
						result = append(result, pStr)
					}
				}
				return result
			}
		}
	}
	return nil
}

// GetScopes returns the scp claim of the token.
func (j *Token) GetScopes() []string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if scopes, exists := claims["scp"]; exists {
			if scps, ok := scopes.([]interface{}); ok {
				result := make([]string, 0, len(scps))
				for _, s := range scps {
					if sStr, ok := s.(string); ok {
						result = append(result, sStr)
					}
				}
				return result
			}
		}
	}
	return nil
}

// GetOrganizationCode returns the org_code claim of the token.
func (j *Token) GetOrganizationCode() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if orgCode, exists := claims["org_code"]; exists {
			if orgCodeStr, ok := orgCode.(string); ok {
				return orgCodeStr
			}
		}
	}
	return ""
}

// GetAuthorizedParty returns the azp claim of the token.
func (j *Token) GetAuthorizedParty() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if azp, exists := claims["azp"]; exists {
			if azpStr, ok := azp.(string); ok {
				return azpStr
			}
		}
	}
	return ""
}

// FeatureFlag represents a single feature flag with its type and value.
type FeatureFlag struct {
	Type  string      `json:"t"`
	Value interface{} `json:"v"`
}

// GetFeatureFlags returns the feature_flags claim of the token.
// The feature flags use short codes: t=type, v=value, b=boolean, i=integer, s=string
func (j *Token) GetFeatureFlags() map[string]FeatureFlag {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if featureFlags, exists := claims["feature_flags"]; exists {
			if flagsMap, ok := featureFlags.(map[string]interface{}); ok {
				result := make(map[string]FeatureFlag)
				for key, flagData := range flagsMap {
					if flag, ok := flagData.(map[string]interface{}); ok {
						if flagType, exists := flag["t"]; exists {
							if flagValue, exists := flag["v"]; exists {
								result[key] = FeatureFlag{
									Type:  toString(flagType),
									Value: flagValue,
								}
							}
						}
					}
				}
				return result
			}
		}
	}
	return nil
}

// GetFeatureFlag returns a specific feature flag by name.
func (j *Token) GetFeatureFlag(name string) (FeatureFlag, bool) {
	flags := j.GetFeatureFlags()
	if flags == nil {
		return FeatureFlag{}, false
	}
	flag, exists := flags[name]
	return flag, exists
}

// GetFeatureFlagBool returns a boolean feature flag value.
func (j *Token) GetFeatureFlagBool(name string) (bool, bool) {
	flag, exists := j.GetFeatureFlag(name)
	if !exists || flag.Type != "b" {
		return false, false
	}
	if boolVal, ok := flag.Value.(bool); ok {
		return boolVal, true
	}
	return false, false
}

// GetFeatureFlagString returns a string feature flag value.
func (j *Token) GetFeatureFlagString(name string) (string, bool) {
	flag, exists := j.GetFeatureFlag(name)
	if !exists || flag.Type != "s" {
		return "", false
	}
	if strVal, ok := flag.Value.(string); ok {
		return strVal, true
	}
	return "", false
}

// GetFeatureFlagInt returns an integer feature flag value.
func (j *Token) GetFeatureFlagInt(name string) (int64, bool) {
	flag, exists := j.GetFeatureFlag(name)
	if !exists || flag.Type != "i" {
		return 0, false
	}
	switch val := flag.Value.(type) {
	case int64:
		return val, true
	case int:
		return int64(val), true
	case float64:
		return int64(val), true
	}
	return 0, false
}

// toString converts interface{} to string safely.
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

// GetClaims returns the claims of the token.
func (j *Token) GetClaims() map[string]any {
	if j.processing.parsed == nil {
		return make(map[string]any)
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		return claims
	}
	return make(map[string]any)
}

func (j *Token) GetValidationErrors() error {
	return newError("token validation errors", nil, j.validationErrors...)
}
