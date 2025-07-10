package errors

import (
	"fmt"
	"log/slog"
	"os"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeValidation ErrorType = "validation"
	ErrorTypeIO         ErrorType = "io"
	ErrorTypeAI         ErrorType = "ai"
	ErrorTypeNetwork    ErrorType = "network"
	ErrorTypeConfig     ErrorType = "config"
	ErrorTypeInternal   ErrorType = "internal"
)

// AppError represents a structured application error
type AppError struct {
	Type    ErrorType      `json:"type"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Cause   error          `json:"cause,omitempty"`
	Context map[string]any `json:"context,omitempty"`
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

// newAppError is an unexported helper to create AppError instances
func newAppError(typ ErrorType, code, message string, cause error) *AppError {
	return &AppError{
		Type:    typ,
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Error constructors for different types
func NewValidationError(code, message string, cause error) *AppError {
	return newAppError(ErrorTypeValidation, code, message, cause)
}

func NewIOError(code, message string, cause error) *AppError {
	return newAppError(ErrorTypeIO, code, message, cause)
}

func NewAIError(code, message string, cause error) *AppError {
	return newAppError(ErrorTypeAI, code, message, cause)
}

func NewNetworkError(code, message string, cause error) *AppError {
	return newAppError(ErrorTypeNetwork, code, message, cause)
}

func NewConfigError(code, message string, cause error) *AppError {
	return newAppError(ErrorTypeConfig, code, message, cause)
}

func NewInternalError(code, message string, cause error) *AppError {
	return newAppError(ErrorTypeInternal, code, message, cause)
}

// WithContext adds context to an error
func (e *AppError) WithContext(key string, value any) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// Logger wraps slog with application-specific methods
type Logger struct {
	logger *slog.Logger
}

// NewLogger creates a new structured logger
func NewLogger(level slog.Level) *Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &Logger{logger: logger}
}

// LogError logs an application error with appropriate level and context
func (l *Logger) LogError(err error, message string, args ...any) {
	if appErr, ok := err.(*AppError); ok {
		logArgs := []any{
			"error_type", appErr.Type,
			"error_code", appErr.Code,
			"error_message", appErr.Message,
		}

		// Add context if available
		for key, value := range appErr.Context {
			logArgs = append(logArgs, key, value)
		}

		// Add additional args
		logArgs = append(logArgs, args...)

		l.logger.Error(message, logArgs...)
	} else {
		// Regular error
		logArgs := append([]any{"error", err.Error()}, args...)
		l.logger.Error(message, logArgs...)
	}
}

func (l *Logger) Info(message string, args ...any) {
	l.logger.Info(message, args...)
}

func (l *Logger) Debug(message string, args ...any) {
	l.logger.Debug(message, args...)
}

func (l *Logger) Warn(message string, args ...any) {
	l.logger.Warn(message, args...)
}

// New creates a new logger instance
func New(level string) (*Logger, error) {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level: %s", level)
	}

	return NewLogger(slogLevel), nil
}

// Common error codes
const (
	ErrCodeFileNotFound    = "FILE_NOT_FOUND"
	ErrCodeFileNotReadable = "FILE_NOT_READABLE"
	ErrCodeInvalidFormat   = "INVALID_FORMAT"
	ErrCodeAIServiceFailed = "AI_SERVICE_FAILED"
	ErrCodeAITimeout       = "AI_TIMEOUT"
	ErrCodeInvalidRequest  = "INVALID_REQUEST"
	ErrCodeMissingAPIKey   = "MISSING_API_KEY"
	ErrCodeNetworkTimeout  = "NETWORK_TIMEOUT"
	ErrCodeInvalidConfig   = "INVALID_CONFIG"
)
