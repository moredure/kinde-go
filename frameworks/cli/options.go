package cli

import "github.com/99designs/keyring"

type Option func(*keyring.Config)

// WithAllowedBackends sets the allowed backends for the keyring.
func WithAllowedBackends(backends []keyring.BackendType) Option {
	return func(cfg *keyring.Config) {
		cfg.AllowedBackends = backends
	}
}

// WithFileDir sets the file directory for the file backend.
func WithFileDir(dir string) Option {
	return func(cfg *keyring.Config) {
		cfg.FileDir = dir
	}
}

// WithServiceName sets the service name for the keyring.
func WithServiceName(name string) Option {
	return func(cfg *keyring.Config) {
		cfg.ServiceName = name
	}
}

// WithKeychainName sets the keychain name for the keyring.
func WithKeychainName(name string) Option {
	return func(cfg *keyring.Config) {
		cfg.KeychainName = name
	}
}

// WithKeychainPasswordFunc sets the password function for the keychain backend.
func WithKeychainPasswordFunc(fn keyring.PromptFunc) Option {
	return func(cfg *keyring.Config) {
		cfg.KeychainPasswordFunc = fn
	}
}

// WithFilePasswordFunc sets the password function for the file backend.
func WithFilePasswordFunc(fn keyring.PromptFunc) Option {
	return func(cfg *keyring.Config) {
		cfg.FilePasswordFunc = fn
	}
}

// WithKeychainTrustApplication sets whether to trust the application for the keychain backend.
func WithKeychainTrustApplication(trust bool) Option {
	return func(cfg *keyring.Config) {
		cfg.KeychainTrustApplication = trust
	}
}
