package config

import "fmt"

// ValidateTLSConfig validates the TLS configuration
func (c *Config) ValidateTLSConfig() error {
	tls := c.Server.TLS

	if err := validateTLSMode(tls); err != nil {
		return err
	}

	if err := validateTLSVersion(tls); err != nil {
		return err
	}

	return nil
}

// validateTLSMode validates the TLS mode and associated requirements
func validateTLSMode(tls TLSConfig) error {
	switch tls.Mode {
	case "disabled":
		return nil // No validation needed for disabled mode
	case "server":
		return validateServerModeTLS(tls)
	case "mutual":
		return validateMutualModeTLS(tls)
	default:
		return fmt.Errorf("invalid TLS mode: %s (must be 'disabled', 'server', or 'mutual')", tls.Mode)
	}
}

// validateServerModeTLS validates TLS configuration for server mode
func validateServerModeTLS(tls TLSConfig) error {
	if err := validateCertAndKeyRequired(tls, "server mode"); err != nil {
		return err
	}

	return validateNoDuplicateCertSources(tls)
}

// validateMutualModeTLS validates TLS configuration for mutual mode
func validateMutualModeTLS(tls TLSConfig) error {
	if err := validateCertAndKeyRequired(tls, "mutual mode"); err != nil {
		return err
	}

	if err := validateCARequired(tls); err != nil {
		return err
	}

	if err := validateNoDuplicateCertSources(tls); err != nil {
		return err
	}

	if err := validateCANoDuplicateSource(tls); err != nil {
		return err
	}

	return validateClientAuthPolicy(tls)
}

// validateCertAndKeyRequired checks that both certificate and key are provided
func validateCertAndKeyRequired(tls TLSConfig, mode string) error {
	if (tls.CertFile == "" && tls.CertContent == "") || (tls.KeyFile == "" && tls.KeyContent == "") {
		return fmt.Errorf("TLS certificate and key are required for %s (provide either files or content)", mode)
	}
	return nil
}

// validateCARequired checks that CA certificate is provided for mutual TLS
func validateCARequired(tls TLSConfig) error {
	if tls.CAFile == "" && tls.CAContent == "" {
		return fmt.Errorf("CA certificate is required for mutual TLS mode (provide either caFile or caContent)")
	}
	return nil
}

// validateNoDuplicateCertSources ensures no duplicate sources for cert and key
func validateNoDuplicateCertSources(tls TLSConfig) error {
	if tls.CertFile != "" && tls.CertContent != "" {
		return fmt.Errorf("cannot specify both certFile and certContent - choose one")
	}
	if tls.KeyFile != "" && tls.KeyContent != "" {
		return fmt.Errorf("cannot specify both keyFile and keyContent - choose one")
	}
	return nil
}

// validateCANoDuplicateSource ensures no duplicate sources for CA
func validateCANoDuplicateSource(tls TLSConfig) error {
	if tls.CAFile != "" && tls.CAContent != "" {
		return fmt.Errorf("cannot specify both caFile and caContent - choose one")
	}
	return nil
}

// validateClientAuthPolicy validates the client authentication policy
func validateClientAuthPolicy(tls TLSConfig) error {
	switch tls.ClientAuthPolicy {
	case "require", "request", "verify", "":
		return nil // Valid policies (empty defaults to require)
	default:
		return fmt.Errorf("invalid clientAuthPolicy: %s (must be 'require', 'request', or 'verify')", tls.ClientAuthPolicy)
	}
}

// validateTLSVersion validates the TLS version configuration
func validateTLSVersion(tls TLSConfig) error {
	switch tls.MinVersion {
	case "", "1.2", "1.3":
		return nil // Valid versions (empty defaults to 1.2)
	default:
		return fmt.Errorf("invalid TLS minVersion: %s (must be '1.2' or '1.3')", tls.MinVersion)
	}
}