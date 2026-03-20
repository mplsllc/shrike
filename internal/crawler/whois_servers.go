package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	ianaRDAPBootstrapURL = "https://data.iana.org/rdap/dns.json"
	ianaWhoisServer      = "whois.iana.org"
	bootstrapRefreshInterval = 24 * time.Hour
)

// ServerDiscovery resolves domains to their RDAP and WHOIS server URLs.
type ServerDiscovery struct {
	mu sync.RWMutex

	// RDAP: TLD → RDAP base URL (from IANA bootstrap)
	rdapServers map[string]string

	// Raw WHOIS: TLD → whois server hostname (cached from IANA lookups)
	whoisServers map[string]string

	httpClient *http.Client
	lastRefresh time.Time
}

// rdapBootstrap represents the IANA RDAP bootstrap file format (RFC 9224).
type rdapBootstrap struct {
	Version     string     `json:"version"`
	Publication string     `json:"publication"`
	Services    [][]interface{} `json:"services"`
}

func NewServerDiscovery(httpClient *http.Client) *ServerDiscovery {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ServerDiscovery{
		rdapServers:  make(map[string]string),
		whoisServers: make(map[string]string),
		httpClient:   httpClient,
	}
}

// LoadRDAPBootstrap fetches and parses the IANA RDAP bootstrap file.
// This maps TLDs to their RDAP service URLs.
func (sd *ServerDiscovery) LoadRDAPBootstrap(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ianaRDAPBootstrapURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := sd.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching RDAP bootstrap: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RDAP bootstrap returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var bootstrap rdapBootstrap
	if err := json.Unmarshal(body, &bootstrap); err != nil {
		return fmt.Errorf("parsing bootstrap JSON: %w", err)
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	for _, service := range bootstrap.Services {
		if len(service) != 2 {
			continue
		}

		// service[0] is an array of TLD strings
		// service[1] is an array of RDAP base URLs
		tlds, ok := service[0].([]interface{})
		if !ok {
			continue
		}
		urls, ok := service[1].([]interface{})
		if !ok || len(urls) == 0 {
			continue
		}

		// Use the first URL as the RDAP base
		baseURL, ok := urls[0].(string)
		if !ok {
			continue
		}
		// Ensure trailing slash
		if !strings.HasSuffix(baseURL, "/") {
			baseURL += "/"
		}

		for _, t := range tlds {
			tld, ok := t.(string)
			if !ok {
				continue
			}
			sd.rdapServers[strings.ToLower(tld)] = baseURL
		}
	}

	sd.lastRefresh = time.Now()
	return nil
}

// RDAPServer returns the RDAP base URL for a given TLD, or empty string if not found.
func (sd *ServerDiscovery) RDAPServer(tld string) string {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.rdapServers[strings.ToLower(tld)]
}

// HasRDAP returns whether a TLD has a known RDAP server.
func (sd *ServerDiscovery) HasRDAP(tld string) bool {
	return sd.RDAPServer(tld) != ""
}

// WhoisServer returns the WHOIS server hostname for a given TLD.
// Returns a cached value if available, otherwise queries IANA.
func (sd *ServerDiscovery) WhoisServer(ctx context.Context, tld string) (string, error) {
	tld = strings.ToLower(tld)

	sd.mu.RLock()
	server, ok := sd.whoisServers[tld]
	sd.mu.RUnlock()

	if ok {
		return server, nil
	}

	// Query IANA root WHOIS for this TLD
	server, err := sd.queryIANA(ctx, tld)
	if err != nil {
		return "", err
	}

	sd.mu.Lock()
	sd.whoisServers[tld] = server
	sd.mu.Unlock()

	return server, nil
}

// queryIANA queries whois.iana.org for a TLD's WHOIS server.
func (sd *ServerDiscovery) queryIANA(ctx context.Context, tld string) (string, error) {
	client := &WhoisClient{
		Timeout: 10 * time.Second,
	}
	raw, err := client.Query(ctx, ianaWhoisServer, tld)
	if err != nil {
		return "", fmt.Errorf("querying IANA for %s: %w", tld, err)
	}

	// Parse the IANA response for "whois:" field
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "whois:") {
			server := strings.TrimSpace(strings.TrimPrefix(line, "whois:"))
			server = strings.TrimSpace(strings.TrimPrefix(server, "WHOIS:"))
			if server != "" {
				// Validate the hostname to prevent SSRF — must look like a valid WHOIS server
				if !isValidWhoisHostname(server) {
					return "", fmt.Errorf("invalid WHOIS server hostname from IANA: %s", server)
				}
				return server, nil
			}
		}
	}

	return "", fmt.Errorf("no WHOIS server found for TLD %s", tld)
}

// isValidWhoisHostname checks that a WHOIS server hostname is plausible.
// Prevents SSRF by rejecting IPs, localhost, internal hostnames, and invalid characters.
func isValidWhoisHostname(host string) bool {
	// Must contain at least one dot (not an IP or single-label hostname)
	if !strings.Contains(host, ".") {
		return false
	}
	// No colons (IPv6 or port), no slashes (URLs), no spaces
	if strings.ContainsAny(host, ":/ \t") {
		return false
	}
	// Block internal/private hostnames
	lower := strings.ToLower(host)
	if strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") ||
		lower == "localhost" || strings.HasPrefix(lower, "127.") || strings.HasPrefix(lower, "10.") ||
		strings.HasPrefix(lower, "192.168.") {
		return false
	}
	// Must end with a valid-looking TLD (at least 2 chars)
	parts := strings.Split(host, ".")
	lastPart := parts[len(parts)-1]
	if len(lastPart) < 2 {
		return false
	}
	return true
}

// NeedsRefresh returns true if the bootstrap data should be refreshed.
func (sd *ServerDiscovery) NeedsRefresh() bool {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return time.Since(sd.lastRefresh) > bootstrapRefreshInterval
}

// TLDFromDomain extracts the TLD from a domain name.
func TLDFromDomain(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-1]
}

// RDAPURLForDomain builds the full RDAP query URL for a domain.
func (sd *ServerDiscovery) RDAPURLForDomain(domain string) string {
	tld := TLDFromDomain(domain)
	base := sd.RDAPServer(tld)
	if base == "" {
		return ""
	}
	return base + "domain/" + strings.ToLower(domain)
}

// Stats returns the number of known RDAP and WHOIS servers.
func (sd *ServerDiscovery) Stats() (rdapCount, whoisCount int) {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return len(sd.rdapServers), len(sd.whoisServers)
}
