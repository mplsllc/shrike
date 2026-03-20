package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RDAPClient handles RDAP (RFC 9083) queries over HTTP/JSON.
type RDAPClient struct {
	httpClient *http.Client
	discovery  *ServerDiscovery
}

func NewRDAPClient(discovery *ServerDiscovery) *RDAPClient {
	return &RDAPClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		discovery: discovery,
	}
}

// RDAPResponse represents an RDAP domain response per RFC 9083.
type RDAPResponse struct {
	ObjectClassName string          `json:"objectClassName"`
	Handle          string          `json:"handle,omitempty"`
	LDHName         string          `json:"ldhName"`
	UnicodeName     string          `json:"unicodeName,omitempty"`
	Status          []string        `json:"status,omitempty"`
	Entities        []RDAPEntity    `json:"entities,omitempty"`
	Events          []RDAPEvent     `json:"events,omitempty"`
	Nameservers     []RDAPNameserver `json:"nameservers,omitempty"`
	SecureDNS       *RDAPSecureDNS  `json:"secureDNS,omitempty"`
	Links           []RDAPLink      `json:"links,omitempty"`
	Notices         []RDAPNotice    `json:"notices,omitempty"`
	Port43          string          `json:"port43,omitempty"`

	// Store the raw JSON for full fidelity
	RawJSON json.RawMessage `json:"-"`
}

type RDAPEntity struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle,omitempty"`
	Roles           []string     `json:"roles,omitempty"`
	VCardArray      interface{}  `json:"vcardArray,omitempty"`
	Entities        []RDAPEntity `json:"entities,omitempty"`
	Events          []RDAPEvent  `json:"events,omitempty"`
	PublicIDs       []RDAPPublicID `json:"publicIds,omitempty"`
}

type RDAPEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type RDAPNameserver struct {
	ObjectClassName string `json:"objectClassName"`
	LDHName         string `json:"ldhName"`
}

type RDAPSecureDNS struct {
	DelegationSigned bool `json:"delegationSigned"`
}

type RDAPLink struct {
	Rel   string `json:"rel,omitempty"`
	Href  string `json:"href,omitempty"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type RDAPNotice struct {
	Title       string   `json:"title,omitempty"`
	Description []string `json:"description,omitempty"`
	Links       []RDAPLink `json:"links,omitempty"`
}

type RDAPPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// QueryDomain performs an RDAP lookup for a domain.
func (rc *RDAPClient) QueryDomain(ctx context.Context, domain string) (*RDAPResponse, error) {
	url := rc.discovery.RDAPURLForDomain(domain)
	if url == "" {
		return nil, fmt.Errorf("no RDAP server for domain %s", domain)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RDAP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("domain %s not found in RDAP", domain)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("RDAP rate limited for %s", domain)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP returned status %d for %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil, fmt.Errorf("reading RDAP response: %w", err)
	}

	var rdapResp RDAPResponse
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return nil, fmt.Errorf("parsing RDAP response: %w", err)
	}
	rdapResp.RawJSON = body

	return &rdapResp, nil
}

// IsRDAPRateLimited checks if an RDAP error indicates rate limiting.
func IsRDAPRateLimited(err error) bool {
	if err == nil {
		return false
	}
	return fmt.Sprintf("%v", err) == fmt.Sprintf("RDAP rate limited for %s", "")[:len("RDAP rate limited")] ||
		len(err.Error()) > 18 && err.Error()[:18] == "RDAP rate limited "
}
