package crawler

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	whoisPort       = 43
	maxResponseSize = 1 << 20 // 1MB
	maxReferralHops = 3
)

// WhoisClient handles raw TCP WHOIS queries on port 43.
type WhoisClient struct {
	Timeout time.Duration
}

func NewWhoisClient() *WhoisClient {
	return &WhoisClient{
		Timeout: 15 * time.Second,
	}
}

// Query sends a WHOIS query to the given server and returns the raw response.
func (wc *WhoisClient) Query(ctx context.Context, server, query string) (string, error) {
	addr := net.JoinHostPort(server, fmt.Sprintf("%d", whoisPort))

	dialer := &net.Dialer{Timeout: wc.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", server, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(wc.Timeout))
	}

	// Send query with CRLF
	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		return "", fmt.Errorf("writing query to %s: %w", server, err)
	}

	// Read response
	response, err := io.ReadAll(io.LimitReader(conn, maxResponseSize))
	if err != nil {
		return "", fmt.Errorf("reading response from %s: %w", server, err)
	}

	return string(response), nil
}

// QueryWithReferral performs a WHOIS query and follows referrals to registrar WHOIS servers.
// Returns the final (most detailed) response and the server it came from.
func (wc *WhoisClient) QueryWithReferral(ctx context.Context, server, domain string) (response string, finalServer string, err error) {
	currentServer := server
	var lastResponse string

	for hop := 0; hop < maxReferralHops; hop++ {
		resp, err := wc.Query(ctx, currentServer, domain)
		if err != nil {
			if lastResponse != "" {
				// Return what we have from the previous hop
				return lastResponse, currentServer, nil
			}
			return "", currentServer, err
		}

		lastResponse = resp

		// Check for referral to a more specific WHOIS server
		referral := extractReferral(resp)
		if referral == "" || referral == currentServer {
			break
		}

		currentServer = referral
	}

	return lastResponse, currentServer, nil
}

// extractReferral looks for referral patterns in a WHOIS response.
// Common patterns:
//   - "Registrar WHOIS Server: whois.example.com"
//   - "ReferralServer: whois://whois.example.com"
//   - "whois: whois.example.com"
func extractReferral(response string) string {
	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		// Verisign-style: "Registrar WHOIS Server: whois.registrar.com"
		if strings.HasPrefix(lower, "registrar whois server:") {
			server := strings.TrimSpace(line[len("Registrar WHOIS Server:"):])
			if server != "" {
				return server
			}
		}

		// ARIN-style: "ReferralServer: whois://whois.example.com"
		if strings.HasPrefix(lower, "referralserver:") {
			server := strings.TrimSpace(line[len("ReferralServer:"):])
			server = strings.TrimPrefix(server, "whois://")
			server = strings.TrimPrefix(server, "rwhois://")
			// Remove port if present
			if host, _, err := net.SplitHostPort(server); err == nil {
				server = host
			}
			if server != "" {
				return server
			}
		}
	}

	return ""
}

// IsRateLimited checks if a WHOIS response indicates rate limiting.
func IsRateLimited(response string) bool {
	lower := strings.ToLower(response)

	// A real rate limit response is short — just an error message, no domain data.
	// Many registries include "rate limited" in their footer/disclaimer on valid responses.
	// Only treat as rate-limited if response is under 500 chars (no real WHOIS data).
	isShort := len(response) < 500

	patterns := []string{
		"quota exceeded",
		"rate limit",
		"too many requests",
		"try again later",
		"connection limit",
		"query limit",
		"exceeded the maximum",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) && isShort {
			return true
		}
	}
	return false
}
