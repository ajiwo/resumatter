package common

import (
	"testing"
)

func TestValidateOutputFormat(t *testing.T) {
	tests := []struct {
		name             string
		format           string
		supportedFormats []string
		expectError      bool
		expectedError    string
	}{
		{
			name:             "valid format - json",
			format:           "json",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      false,
		},
		{
			name:             "valid format - text",
			format:           "text",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      false,
		},
		{
			name:             "valid format - markdown",
			format:           "markdown",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      false,
		},
		{
			name:             "invalid format - xml",
			format:           "xml",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      true,
			expectedError:    "unsupported output format 'xml'. Supported formats: [json text markdown]",
		},
		{
			name:             "invalid format - yaml",
			format:           "yaml",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      true,
			expectedError:    "unsupported output format 'yaml'. Supported formats: [json text markdown]",
		},
		{
			name:             "invalid format - csv",
			format:           "csv",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      true,
			expectedError:    "unsupported output format 'csv'. Supported formats: [json text markdown]",
		},
		{
			name:             "case sensitive - JSON uppercase",
			format:           "JSON",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      true,
			expectedError:    "unsupported output format 'JSON'. Supported formats: [json text markdown]",
		},
		{
			name:             "empty format string",
			format:           "",
			supportedFormats: []string{"json", "text", "markdown"},
			expectError:      true,
			expectedError:    "unsupported output format ''. Supported formats: [json text markdown]",
		},
		{
			name:             "empty supported formats - should allow all",
			format:           "xml",
			supportedFormats: []string{},
			expectError:      false,
		},
		{
			name:             "single supported format - valid",
			format:           "json",
			supportedFormats: []string{"json"},
			expectError:      false,
		},
		{
			name:             "single supported format - invalid",
			format:           "text",
			supportedFormats: []string{"json"},
			expectError:      true,
			expectedError:    "unsupported output format 'text'. Supported formats: [json]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run validation
			err := ValidateOutputFormat(tt.format, tt.supportedFormats)

			// Check results
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.expectedError != "" && err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestGetSupportedFormats(t *testing.T) {
	tests := []struct {
		name             string
		supportedFormats []string
		expected         []string
	}{
		{
			name:             "normal config with formats",
			supportedFormats: []string{"json", "text", "markdown"},
			expected:         []string{"json", "text", "markdown"},
		},
		{
			name:             "config with single format",
			supportedFormats: []string{"json"},
			expected:         []string{"json"},
		},
		{
			name:             "config with empty formats",
			supportedFormats: []string{},
			expected:         []string{},
		},
		{
			name:             "custom formats",
			supportedFormats: []string{"xml", "yaml", "csv"},
			expected:         []string{"xml", "yaml", "csv"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get supported formats
			result := GetSupportedFormats(tt.supportedFormats)

			// Check results
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d formats, got %d", len(tt.expected), len(result))
				return
			}

			for i, expected := range tt.expected {
				if i >= len(result) || result[i] != expected {
					t.Errorf("Expected format[%d] = '%s', got '%s'", i, expected, result[i])
				}
			}
		})
	}
}

// Benchmark tests to ensure validation is fast
func BenchmarkValidateOutputFormat(b *testing.B) {
	supportedFormats := []string{"json", "text", "markdown"}

	b.Run("valid format", func(b *testing.B) {
		for b.Loop() {
			_ = ValidateOutputFormat("json", supportedFormats)
		}
	})

	b.Run("invalid format", func(b *testing.B) {
		for b.Loop() {
			_ = ValidateOutputFormat("xml", supportedFormats)
		}
	})
}

func BenchmarkGetSupportedFormats(b *testing.B) {
	supportedFormats := []string{"json", "text", "markdown"}

	for b.Loop() {
		GetSupportedFormats(supportedFormats)
	}
}
