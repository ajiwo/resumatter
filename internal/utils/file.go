package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ValidateInputFile checks if a file exists and is readable
func ValidateInputFile(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", filename)
		}
		return fmt.Errorf("cannot access file %s: %w", filename, err)
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", filename)
	}

	// Check if file is readable
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("cannot read file %s: %w", filename, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s: %w", filename, err)
	}

	return nil
}

// ValidateOutputFile checks if the output file path is valid
func ValidateOutputFile(filename string) error {
	if filename == "" {
		return nil // stdout is valid
	}

	dir := filepath.Dir(filename)
	if dir != "." {
		// Check if directory exists or can be created
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return fmt.Errorf("cannot create directory %s: %w", dir, err)
			}
		}
	}

	return nil
}

// GetFileExtension returns the file extension in lowercase
func GetFileExtension(filename string) string {
	ext := filepath.Ext(filename)
	return strings.ToLower(ext)
}

// IsTextFile checks if the file has a text-based extension
func IsTextFile(filename string) bool {
	ext := GetFileExtension(filename)
	textExtensions := []string{".txt", ".md", ".markdown", ".text"}

	return slices.Contains(textExtensions, ext)
}

// FormatFileSize returns a human-readable file size
func FormatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
