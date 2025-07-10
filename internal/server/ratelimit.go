package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"resumatter/internal/errors"

	"golang.org/x/time/rate"
)

// LimiterManager manages a collection of rate limiters for different keys (IPs, API keys).
type LimiterManager struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	lastSeen map[string]time.Time
	rate     rate.Limit // e.g., rate.Limit(1) for 1 request per second
	burst    int
	done     chan struct{} // Channel to signal cleanup goroutine to stop
	logger   *errors.Logger
}

// RateLimiter is an alias for LimiterManager to maintain backward compatibility
type RateLimiter = LimiterManager

// NewRateLimiter creates a new manager.
// requestsPerMin is the number of requests allowed per minute.
// window parameter is ignored (kept for backward compatibility).
// burstCapacity is the token bucket size.
func NewRateLimiter(requestsPerMin int, window time.Duration, burstCapacity int, logger *errors.Logger) *LimiterManager {
	// The rate.Limit is specified in requests per second.
	r := rate.Limit(float64(requestsPerMin) / 60.0)

	m := &LimiterManager{
		limiters: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		rate:     r,
		burst:    burstCapacity,
		done:     make(chan struct{}),
		logger:   logger,
	}

	// Start the cleanup goroutine
	go m.cleanupRoutine(10 * time.Minute) // Cleanup every 10 minutes
	return m
}

// GetLimiter retrieves or creates a limiter for a given key.
func (m *LimiterManager) GetLimiter(key string) *rate.Limiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	limiter, exists := m.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(m.rate, m.burst)
		m.limiters[key] = limiter
	}
	m.lastSeen[key] = time.Now() // Update last seen time

	return limiter
}

// Allow checks if a request should be allowed for the given key
func (m *LimiterManager) Allow(key string) bool {
	// Get the specific limiter for this key
	limiter := m.GetLimiter(key)

	// Check if the request is allowed. Allow() is non-blocking.
	return limiter.Allow()
}

// GetStats returns current rate limiter statistics
func (m *LimiterManager) GetStats() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()

	return map[string]any{
		"active_limiters": len(m.limiters),
		"rate_per_second": float64(m.rate),
		"rate_per_minute": float64(m.rate) * 60.0,
		"burst_capacity":  m.burst,
	}
}

// cleanupRoutine periodically removes inactive limiters
func (m *LimiterManager) cleanupRoutine(cleanupInterval time.Duration) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup(cleanupInterval)
		case <-m.done:
			return
		}
	}
}

// cleanup removes limiters that haven't been used for the specified duration
func (m *LimiterManager) cleanup(evictionAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, lastSeen := range m.lastSeen {
		if now.Sub(lastSeen) > evictionAge {
			delete(m.limiters, key)
			delete(m.lastSeen, key)
		}
	}

	// Log cleanup stats if logger is available
	if m.logger != nil {
		m.logger.Debug("Rate limiter cleanup completed",
			"remaining_limiters", len(m.limiters))
	}
}

// Close stops the cleanup goroutine. Should be called when shutting down the server.
func (m *LimiterManager) Close() {
	close(m.done)
}

// rateLimitMiddleware creates rate limiting middleware using golang.org/x/time/rate.
func (s *Server) rateLimitMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	if s.RateLimit == nil || !s.RateLimit.Enabled {
		return func(next http.HandlerFunc) http.HandlerFunc { return next }
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// The logic to get the rateLimitKey remains the same
			rateLimitKey := getRateLimitKey(r, s.RateLimit.ByAPIKey, s.RateLimit.ByIP)
			if rateLimitKey == "" {
				next(w, r)
				return
			}

			// Check if the request is allowed. Allow() is non-blocking.
			if !s.RateLimiter.Allow(rateLimitKey) {
				s.Logger.Info("Rate limit exceeded",
					"key", rateLimitKey,
					"endpoint", r.URL.Path,
					"client_ip", getClientIP(r))
				writeErrorResponse(w, "Rate limit exceeded", "Too many requests", http.StatusTooManyRequests)
				return
			}

			next(w, r)
		}
	}
}

// Helper to consolidate key extraction logic
func getRateLimitKey(r *http.Request, byAPIKey, byIP bool) string {
	if byAPIKey {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			authHeader := r.Header.Get("Authorization")
			if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
				apiKey = after
			}
		}
		if apiKey != "" {
			return "api:" + apiKey
		}
	}

	if byIP {
		return "ip:" + getClientIP(r)
	}

	return ""
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if ip := parseFirstIP(xff); ip != "" {
			return ip
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// parseFirstIP parses the first valid IP from a comma-separated list
func parseFirstIP(ips string) string {
	// Split by comma and check each IP
	for ip := range strings.SplitSeq(ips, ",") {
		ip = strings.TrimSpace(ip)
		if parsed := net.ParseIP(ip); parsed != nil {
			return ip
		}
	}
	return ""
}
