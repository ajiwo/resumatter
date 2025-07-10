package common

import (
	"fmt"
	"slices"
)

// ValidateOutputFormat validates format against configured supported formats
func ValidateOutputFormat(format string, supportedFormats []string) error {
	if len(supportedFormats) == 0 {
		return nil // No restrictions configured
	}

	if slices.Contains(supportedFormats, format) {
		return nil
	}

	return fmt.Errorf("unsupported output format '%s'. Supported formats: %v",
		format, supportedFormats)
}

// GetSupportedFormats returns the list of supported formats
func GetSupportedFormats(supportedFormats []string) []string {
	return supportedFormats
}
