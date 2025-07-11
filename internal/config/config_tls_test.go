package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateTLSMode tests the main TLS mode validation function
func TestValidateTLSMode(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "disabled mode",
			tls: TLSConfig{
				Mode: "disabled",
			},
			expectError: false,
		},
		{
			name: "server mode valid",
			tls: TLSConfig{
				Mode:     "server",
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			expectError: false,
		},
		{
			name: "mutual mode valid",
			tls: TLSConfig{
				Mode:     "mutual",
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				CAFile:   "/path/to/ca.pem",
			},
			expectError: false,
		},
		{
			name: "invalid mode",
			tls: TLSConfig{
				Mode: "invalid",
			},
			expectError: true,
			errorMsg:    "invalid TLS mode: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTLSMode(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateServerModeTLS tests server mode specific validation
func TestValidateServerModeTLS(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid with files",
			tls: TLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			expectError: false,
		},
		{
			name: "valid with content",
			tls: TLSConfig{
				CertContent: "cert-content",
				KeyContent:  "key-content",
			},
			expectError: false,
		},
		{
			name: "missing certificate",
			tls: TLSConfig{
				KeyFile: "/path/to/key.pem",
			},
			expectError: true,
			errorMsg:    "TLS certificate and key are required for server mode",
		},
		{
			name: "missing key",
			tls: TLSConfig{
				CertFile: "/path/to/cert.pem",
			},
			expectError: true,
			errorMsg:    "TLS certificate and key are required for server mode",
		},
		{
			name: "duplicate cert sources",
			tls: TLSConfig{
				CertFile:    "/path/to/cert.pem",
				CertContent: "cert-content",
				KeyFile:     "/path/to/key.pem",
			},
			expectError: true,
			errorMsg:    "cannot specify both certFile and certContent",
		},
		{
			name: "duplicate key sources",
			tls: TLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				KeyContent: "key-content",
			},
			expectError: true,
			errorMsg:    "cannot specify both keyFile and keyContent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServerModeTLS(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateMutualModeTLS tests mutual mode specific validation
func TestValidateMutualModeTLS(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid with files",
			tls: TLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				CAFile:   "/path/to/ca.pem",
			},
			expectError: false,
		},
		{
			name: "valid with content",
			tls: TLSConfig{
				CertContent: "cert-content",
				KeyContent:  "key-content",
				CAContent:   "ca-content",
			},
			expectError: false,
		},
		{
			name: "valid with require policy",
			tls: TLSConfig{
				CertFile:         "/path/to/cert.pem",
				KeyFile:          "/path/to/key.pem",
				CAFile:           "/path/to/ca.pem",
				ClientAuthPolicy: "require",
			},
			expectError: false,
		},
		{
			name: "missing CA",
			tls: TLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			expectError: true,
			errorMsg:    "CA certificate is required for mutual TLS mode",
		},
		{
			name: "duplicate CA sources",
			tls: TLSConfig{
				CertFile:  "/path/to/cert.pem",
				KeyFile:   "/path/to/key.pem",
				CAFile:    "/path/to/ca.pem",
				CAContent: "ca-content",
			},
			expectError: true,
			errorMsg:    "cannot specify both caFile and caContent",
		},
		{
			name: "invalid client auth policy",
			tls: TLSConfig{
				CertFile:         "/path/to/cert.pem",
				KeyFile:          "/path/to/key.pem",
				CAFile:           "/path/to/ca.pem",
				ClientAuthPolicy: "invalid",
			},
			expectError: true,
			errorMsg:    "invalid clientAuthPolicy: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMutualModeTLS(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateCertAndKeyRequired tests certificate and key requirement validation
func TestValidateCertAndKeyRequired(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		mode        string
		expectError bool
	}{
		{
			name: "both files provided",
			tls: TLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			mode:        "server mode",
			expectError: false,
		},
		{
			name: "both content provided",
			tls: TLSConfig{
				CertContent: "cert-content",
				KeyContent:  "key-content",
			},
			mode:        "mutual mode",
			expectError: false,
		},
		{
			name: "mixed sources valid",
			tls: TLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyContent: "key-content",
			},
			mode:        "server mode",
			expectError: false,
		},
		{
			name: "missing certificate",
			tls: TLSConfig{
				KeyFile: "/path/to/key.pem",
			},
			mode:        "server mode",
			expectError: true,
		},
		{
			name: "missing key",
			tls: TLSConfig{
				CertFile: "/path/to/cert.pem",
			},
			mode:        "mutual mode",
			expectError: true,
		},
		{
			name:        "both missing",
			tls:         TLSConfig{},
			mode:        "server mode",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertAndKeyRequired(tt.tls, tt.mode)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "TLS certificate and key are required")
				assert.Contains(t, err.Error(), tt.mode)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateCARequired tests CA certificate requirement validation
func TestValidateCARequired(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
	}{
		{
			name: "CA file provided",
			tls: TLSConfig{
				CAFile: "/path/to/ca.pem",
			},
			expectError: false,
		},
		{
			name: "CA content provided",
			tls: TLSConfig{
				CAContent: "ca-content",
			},
			expectError: false,
		},
		{
			name:        "no CA provided",
			tls:         TLSConfig{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCARequired(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "CA certificate is required for mutual TLS mode")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateNoDuplicateCertSources tests duplicate certificate source validation
func TestValidateNoDuplicateCertSources(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "no duplicates",
			tls: TLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			expectError: false,
		},
		{
			name: "content only",
			tls: TLSConfig{
				CertContent: "cert-content",
				KeyContent:  "key-content",
			},
			expectError: false,
		},
		{
			name: "mixed sources valid",
			tls: TLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyContent: "key-content",
			},
			expectError: false,
		},
		{
			name: "duplicate cert sources",
			tls: TLSConfig{
				CertFile:    "/path/to/cert.pem",
				CertContent: "cert-content",
			},
			expectError: true,
			errorMsg:    "cannot specify both certFile and certContent",
		},
		{
			name: "duplicate key sources",
			tls: TLSConfig{
				KeyFile:    "/path/to/key.pem",
				KeyContent: "key-content",
			},
			expectError: true,
			errorMsg:    "cannot specify both keyFile and keyContent",
		},
		{
			name: "both duplicates",
			tls: TLSConfig{
				CertFile:    "/path/to/cert.pem",
				CertContent: "cert-content",
				KeyFile:     "/path/to/key.pem",
				KeyContent:  "key-content",
			},
			expectError: true,
			errorMsg:    "cannot specify both certFile and certContent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNoDuplicateCertSources(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateCANoDuplicateSource tests CA duplicate source validation
func TestValidateCANoDuplicateSource(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
	}{
		{
			name: "CA file only",
			tls: TLSConfig{
				CAFile: "/path/to/ca.pem",
			},
			expectError: false,
		},
		{
			name: "CA content only",
			tls: TLSConfig{
				CAContent: "ca-content",
			},
			expectError: false,
		},
		{
			name:        "no CA",
			tls:         TLSConfig{},
			expectError: false,
		},
		{
			name: "duplicate CA sources",
			tls: TLSConfig{
				CAFile:    "/path/to/ca.pem",
				CAContent: "ca-content",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCANoDuplicateSource(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot specify both caFile and caContent")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateClientAuthPolicy tests client authentication policy validation
func TestValidateClientAuthPolicy(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
	}{
		{
			name: "require policy",
			tls: TLSConfig{
				ClientAuthPolicy: "require",
			},
			expectError: false,
		},
		{
			name: "request policy",
			tls: TLSConfig{
				ClientAuthPolicy: "request",
			},
			expectError: false,
		},
		{
			name: "verify policy",
			tls: TLSConfig{
				ClientAuthPolicy: "verify",
			},
			expectError: false,
		},
		{
			name: "empty policy (default)",
			tls: TLSConfig{
				ClientAuthPolicy: "",
			},
			expectError: false,
		},
		{
			name: "invalid policy",
			tls: TLSConfig{
				ClientAuthPolicy: "invalid",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClientAuthPolicy(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid clientAuthPolicy")
				assert.Contains(t, err.Error(), "must be 'require', 'request', or 'verify'")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateTLSVersion tests TLS version validation
func TestValidateTLSVersion(t *testing.T) {
	tests := []struct {
		name        string
		tls         TLSConfig
		expectError bool
	}{
		{
			name: "empty version (default)",
			tls: TLSConfig{
				MinVersion: "",
			},
			expectError: false,
		},
		{
			name: "TLS 1.2",
			tls: TLSConfig{
				MinVersion: "1.2",
			},
			expectError: false,
		},
		{
			name: "TLS 1.3",
			tls: TLSConfig{
				MinVersion: "1.3",
			},
			expectError: false,
		},
		{
			name: "invalid version",
			tls: TLSConfig{
				MinVersion: "1.1",
			},
			expectError: true,
		},
		{
			name: "invalid version string",
			tls: TLSConfig{
				MinVersion: "invalid",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTLSVersion(tt.tls)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid TLS minVersion")
				assert.Contains(t, err.Error(), "must be '1.2' or '1.3'")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateTLSConfigIntegration tests the main ValidateTLSConfig function with realistic scenarios
func TestValidateTLSConfigIntegration(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "complete valid server config",
			config: Config{
				Server: ServerConfig{
					TLS: TLSConfig{
						Mode:       "server",
						CertFile:   "/path/to/cert.pem",
						KeyFile:    "/path/to/key.pem",
						MinVersion: "1.2",
					},
				},
			},
			expectError: false,
		},
		{
			name: "complete valid mutual config",
			config: Config{
				Server: ServerConfig{
					TLS: TLSConfig{
						Mode:             "mutual",
						CertContent:      "cert-content",
						KeyContent:       "key-content",
						CAContent:        "ca-content",
						ClientAuthPolicy: "require",
						MinVersion:       "1.3",
					},
				},
			},
			expectError: false,
		},
		{
			name: "disabled TLS",
			config: Config{
				Server: ServerConfig{
					TLS: TLSConfig{
						Mode: "disabled",
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid mode with valid certs",
			config: Config{
				Server: ServerConfig{
					TLS: TLSConfig{
						Mode:     "invalid",
						CertFile: "/path/to/cert.pem",
						KeyFile:  "/path/to/key.pem",
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid TLS mode: invalid",
		},
		{
			name: "valid mode with invalid version",
			config: Config{
				Server: ServerConfig{
					TLS: TLSConfig{
						Mode:       "server",
						CertFile:   "/path/to/cert.pem",
						KeyFile:    "/path/to/key.pem",
						MinVersion: "1.0",
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid TLS minVersion: 1.0",
		},
		{
			name: "server mode missing certificates",
			config: Config{
				Server: ServerConfig{
					TLS: TLSConfig{
						Mode:       "server",
						MinVersion: "1.2",
					},
				},
			},
			expectError: true,
			errorMsg:    "TLS certificate and key are required for server mode",
		},
		{
			name: "mutual mode missing CA",
			config: Config{
				Server: ServerConfig{
					TLS: TLSConfig{
						Mode:     "mutual",
						CertFile: "/path/to/cert.pem",
						KeyFile:  "/path/to/key.pem",
					},
				},
			},
			expectError: true,
			errorMsg:    "CA certificate is required for mutual TLS mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateTLSConfig()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
