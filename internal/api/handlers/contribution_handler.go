package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"git.mp.ls/mpls/shrike/internal/models"
)

type ContributionHandler struct {
	pool *pgxpool.Pool
}

func NewContributionHandler(pool *pgxpool.Pool) *ContributionHandler {
	return &ContributionHandler{pool: pool}
}

type contributeRequest struct {
	DataType string            `json:"data_type" binding:"required"` // domain_whois, dns, ip_whois
	Records  []json.RawMessage `json:"records" binding:"required"`
}

// Submit receives community data contributions.
// Requires an API key. Records go through validation before merging.
func (h *ContributionHandler) Submit(c *gin.Context) {
	// Require API key
	_, exists := c.Get("api_tier")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required to contribute data"})
		return
	}

	var req contributeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "data_type and records are required"})
		return
	}

	// Validate data_type
	validTypes := map[string]bool{"domain_whois": true, "dns": true, "ip_whois": true, "asn": true}
	if !validTypes[req.DataType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "data_type must be one of: domain_whois, dns, ip_whois, asn"})
		return
	}

	if len(req.Records) == 0 || len(req.Records) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "records must contain 1-1000 items"})
		return
	}

	keyID, _ := c.Get("api_key_id")

	// Create contribution record
	var contribID int64
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO contributions (contributor, api_key_id, data_type, record_count, status)
		 VALUES ($1, $2, $3, $4, 'pending')
		 RETURNING id`,
		keyID, keyID, req.DataType, len(req.Records)).Scan(&contribID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create contribution"})
		return
	}

	// Store individual records for validation
	stored := 0
	for _, rec := range req.Records {
		// Extract target from record (domain name, IP, etc.)
		var parsed map[string]interface{}
		if err := json.Unmarshal(rec, &parsed); err != nil {
			continue
		}
		target := ""
		if t, ok := parsed["domain"].(string); ok {
			target = t
		} else if t, ok := parsed["ip"].(string); ok {
			target = t
		} else if t, ok := parsed["target"].(string); ok {
			target = t
		}

		_, err := h.pool.Exec(c.Request.Context(),
			`INSERT INTO contribution_records (contribution_id, data_type, target, record_data, validation_status)
			 VALUES ($1, $2, $3, $4, 'pending')`,
			contribID, req.DataType, target, rec)
		if err == nil {
			stored++
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":             contribID,
		"status":         models.ContribStatusPending,
		"records_stored": stored,
		"message":        "Contribution received. Records will be validated before merging into the database.",
	})
}
