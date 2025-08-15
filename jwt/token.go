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

// GetRawToken returns the raw token.
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

// GetIssuer returns the sub claim of the token.
func (j *Token) GetSubject() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	subject, _ := j.processing.parsed.Claims.GetSubject()
	return subject
}

// GetIssuer returns the claims of the token.
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
