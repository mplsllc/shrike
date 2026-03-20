package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// GraphRepository handles cross-pillar queries — the relationship layer
// that connects domains to IPs to ASNs to organizations.
type GraphRepository struct {
	pool *pgxpool.Pool
}

func NewGraphRepository(pool *pgxpool.Pool) *GraphRepository {
	return &GraphRepository{pool: pool}
}

// GraphNode represents a node in the relationship graph.
type GraphNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // domain, ip, asn, nameserver, registrar
	Label string `json:"label"`
}

// GraphEdge represents a relationship between two nodes.
type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"` // resolves_to, announced_by, registered_by, serves
}

// GraphData holds the full graph for visualization.
type GraphData struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// DomainGraph builds a relationship graph centered on a domain.
// Domain → IPs (from DNS A/AAAA) → ASNs (from BGP) + nameservers + registrar.
func (r *GraphRepository) DomainGraph(ctx context.Context, domainName string) (*GraphData, error) {
	graph := &GraphData{}

	// Get domain info
	var domainID int64
	var registrar, tld *string
	err := r.pool.QueryRow(ctx,
		`SELECT d.id, ds.registrar, d.tld
		 FROM domains d
		 LEFT JOIN LATERAL (
			SELECT registrar FROM domain_snapshots WHERE domain_id = d.id ORDER BY observed_at DESC LIMIT 1
		 ) ds ON true
		 WHERE d.name = $1`, domainName).Scan(&domainID, &registrar, &tld)
	if err != nil {
		return nil, fmt.Errorf("domain not found: %w", err)
	}

	domainNode := GraphNode{ID: "domain:" + domainName, Type: "domain", Label: domainName}
	graph.Nodes = append(graph.Nodes, domainNode)

	// Registrar
	if registrar != nil && *registrar != "" {
		regNode := GraphNode{ID: "registrar:" + *registrar, Type: "registrar", Label: *registrar}
		graph.Nodes = append(graph.Nodes, regNode)
		graph.Edges = append(graph.Edges, GraphEdge{
			Source: domainNode.ID, Target: regNode.ID, Type: "registered_by",
		})
	}

	// Nameservers (from latest snapshot)
	nsRows, err := r.pool.Query(ctx,
		`SELECT unnest(name_servers) as ns FROM domain_snapshots
		 WHERE domain_id = $1 ORDER BY observed_at DESC LIMIT 1`, domainID)
	if err == nil {
		defer nsRows.Close()
		for nsRows.Next() {
			var ns string
			if nsRows.Scan(&ns) == nil && ns != "" {
				nsNode := GraphNode{ID: "ns:" + ns, Type: "nameserver", Label: ns}
				graph.Nodes = append(graph.Nodes, nsNode)
				graph.Edges = append(graph.Edges, GraphEdge{
					Source: domainNode.ID, Target: nsNode.ID, Type: "serves",
				})
			}
		}
	}

	// IPs (from DNS A/AAAA records)
	ipRows, err := r.pool.Query(ctx,
		`SELECT DISTINCT value FROM dns_records
		 WHERE domain_id = $1 AND record_type IN ('A', 'AAAA')
		 ORDER BY value`, domainID)
	if err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var ip string
			if ipRows.Scan(&ip) == nil {
				ipNode := GraphNode{ID: "ip:" + ip, Type: "ip", Label: ip}
				graph.Nodes = append(graph.Nodes, ipNode)
				graph.Edges = append(graph.Edges, GraphEdge{
					Source: domainNode.ID, Target: ipNode.ID, Type: "resolves_to",
				})

				// Find ASN for this IP
				var asnNumber *int
				var asnName *string
				r.pool.QueryRow(ctx,
					`SELECT a.number, s.name FROM ip_blocks b
					 JOIN ip_asn_history iah ON iah.ip_block_id = b.id
					 JOIN asns a ON a.id = iah.asn_id
					 LEFT JOIN LATERAL (
						SELECT name FROM asn_snapshots WHERE asn_id = a.id ORDER BY observed_at DESC LIMIT 1
					 ) s ON true
					 WHERE b.cidr >>= $1::inet
					 ORDER BY iah.last_seen DESC LIMIT 1`, ip).Scan(&asnNumber, &asnName)

				if asnNumber != nil {
					label := fmt.Sprintf("AS%d", *asnNumber)
					if asnName != nil && *asnName != "" {
						label += " (" + *asnName + ")"
					}
					asnNodeID := fmt.Sprintf("asn:%d", *asnNumber)
					// Avoid duplicate ASN nodes
					found := false
					for _, n := range graph.Nodes {
						if n.ID == asnNodeID {
							found = true
							break
						}
					}
					if !found {
						graph.Nodes = append(graph.Nodes, GraphNode{ID: asnNodeID, Type: "asn", Label: label})
					}
					graph.Edges = append(graph.Edges, GraphEdge{
						Source: ipNode.ID, Target: asnNodeID, Type: "announced_by",
					})
				}
			}
		}
	}

	return graph, nil
}

// SharedHosting returns domains that share an IP with the given domain.
func (r *GraphRepository) SharedHosting(ctx context.Context, domainName string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT d2.name FROM dns_records r1
		 JOIN domains d1 ON d1.id = r1.domain_id
		 JOIN dns_records r2 ON r2.value = r1.value AND r2.record_type = r1.record_type AND r2.domain_id != r1.domain_id
		 JOIN domains d2 ON d2.id = r2.domain_id
		 WHERE d1.name = $1 AND r1.record_type IN ('A', 'AAAA')
		 LIMIT $2`, domainName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			domains = append(domains, name)
		}
	}
	return domains, nil
}
