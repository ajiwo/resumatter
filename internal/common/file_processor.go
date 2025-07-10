package common

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"resumatter/internal/errors"
	"resumatter/internal/utils"
)

// FileProcessor handles common file operations
type FileProcessor struct {
	logger *errors.Logger
}

// NewFileProcessor creates a new file processor instance
func NewFileProcessor(logger *errors.Logger) *FileProcessor {
	return &FileProcessor{logger: logger}
}

// ReadFile reads content from a file with proper error handling
func (fp *FileProcessor) ReadFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return "", errors.NewIOError(errors.ErrCodeFileNotFound,
				fmt.Sprintf("File not found: %s", filename), err)
		}
		return "", errors.NewIOError(errors.ErrCodeFileNotReadable,
			fmt.Sprintf("Cannot read file: %s", filename), err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log the error but don't override the main operation result
			if fp.logger != nil {
				fp.logger.Warn("Failed to close file", "filename", filename, "error", err)
			}
		}
	}()

	content, err := io.ReadAll(file)
	if err != nil {
		return "", errors.NewIOError(errors.ErrCodeFileNotReadable,
			fmt.Sprintf("Failed to read file content: %s", filename), err)
	}

	return string(content), nil
}

// WriteFile writes content to a file with directory creation
func (fp *FileProcessor) WriteFile(filename, content string) error {
	dir := filepath.Dir(filename)
	if dir != "." {
		err := os.MkdirAll(dir, 0750)
		if err != nil {
			return errors.NewIOError("DIRECTORY_CREATE_FAILED",
				fmt.Sprintf("Cannot create directory: %s", dir), err)
		}
	}

	err := os.WriteFile(filename, []byte(content), 0600)
	if err != nil {
		return errors.NewIOError("FILE_WRITE_FAILED",
			fmt.Sprintf("Cannot write file: %s", filename), err)
	}

	return nil
}

// ValidateAndReadFiles validates and reads multiple input files
func (fp *FileProcessor) ValidateAndReadFiles(filenames ...string) ([]string, error) {
	contents := make([]string, len(filenames))

	for i, filename := range filenames {
		// Validate input file
		if err := utils.ValidateInputFile(filename); err != nil {
			return nil, errors.NewValidationError("INVALID_INPUT_FILE",
				fmt.Sprintf("Invalid file %s", filename), err)
		}

		// Warn about non-text files
		if !utils.IsTextFile(filename) {
			if fp.logger != nil {
				fp.logger.Warn("File may not be a text file",
					"filename", filename)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: %s may not be a text file\n", filename)
			}
		}

		// Read file content
		content, err := fp.ReadFile(filename)
		if err != nil {
			return nil, err // Error already wrapped by ReadFile
		}

		contents[i] = content
	}

	return contents, nil
}

// ValidateOutputFile validates output file path
func (fp *FileProcessor) ValidateOutputFile(filename string) error {
	if filename == "" {
		return nil // stdout is valid
	}

	if err := utils.ValidateOutputFile(filename); err != nil {
		return errors.NewValidationError("INVALID_OUTPUT_FILE",
			fmt.Sprintf("Invalid output file: %s", filename), err)
	}

	return nil
}
