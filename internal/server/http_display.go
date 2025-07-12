package server

import "fmt"

// displayServerInfo shows server configuration information
func (s *Server) displayServerInfo() {
	s.displayEndpoints()
	s.displayAuthInfo()
	s.displayRequestLimitInfo()
	s.displayRateLimitInfo()
}

// displayEndpoints shows available API endpoints
func (s *Server) displayEndpoints() {
	fmt.Println("Available endpoints:")
	fmt.Println("  GET  /health    - Health check")
	fmt.Println("  GET  /stats     - Server statistics")
	fmt.Println("  POST /tailor    - Tailor resume (requires API key)")
	fmt.Println("  POST /evaluate  - Evaluate resume (requires API key)")
	fmt.Println("  POST /analyze   - Analyze job description (requires API key)")
}

// displayAuthInfo shows authentication configuration
func (s *Server) displayAuthInfo() {
	if len(s.APIKeys) > 0 {
		fmt.Printf("API authentication: ENABLED (%d keys configured)\n", len(s.APIKeys))
		fmt.Println("Include 'X-API-Key: <your-key>' header in requests to /tailor and /evaluate")
	} else {
		fmt.Println("API authentication: DISABLED (no API keys configured)")
		fmt.Println("WARNING: API endpoints are publicly accessible!")
	}
}

// displayRequestLimitInfo shows request size limit configuration
func (s *Server) displayRequestLimitInfo() {
	if s.MaxRequestSize > 0 {
		fmt.Printf("Request size limit: %d bytes (%.1f MB)\n", s.MaxRequestSize, float64(s.MaxRequestSize)/(1024*1024))
	} else {
		fmt.Println("Request size limit: DISABLED")
		fmt.Println("WARNING: No request size limits configured!")
	}
}

// displayRateLimitInfo shows rate limiting configuration
func (s *Server) displayRateLimitInfo() {
	if s.RateLimit != nil && s.RateLimit.Enabled {
		fmt.Printf("Rate limiting: ENABLED (%d requests/min, burst: %d)\n",
			s.RateLimit.RequestsPerMin, s.RateLimit.BurstCapacity)
		if s.RateLimit.ByAPIKey {
			fmt.Println("  - Per API key rate limiting enabled")
		}
		if s.RateLimit.ByIP {
			fmt.Println("  - Per IP address rate limiting enabled")
		}
	} else {
		fmt.Println("Rate limiting: DISABLED")
		fmt.Println("WARNING: No rate limiting configured!")
	}
}
