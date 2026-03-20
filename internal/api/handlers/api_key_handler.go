package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type APIKeyHandler struct {
	pool *pgxpool.Pool
}

func NewAPIKeyHandler(pool *pgxpool.Pool) *APIKeyHandler {
	return &APIKeyHandler{pool: pool}
}

type signupRequest struct {
	Owner string `json:"owner" binding:"required"`
	Email string `json:"email" binding:"required"`
}

// Signup creates a new free API key.
func (h *APIKeyHandler) Signup(c *gin.Context) {
	var req signupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "owner and email are required"})
		return
	}

	// Validate email format
	req.Email = strings.TrimSpace(req.Email)
	if !emailRegex.MatchString(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email format"})
		return
	}

	// Limit owner length
	req.Owner = strings.TrimSpace(req.Owner)
	if len(req.Owner) > 200 {
		req.Owner = req.Owner[:200]
	}

	// Check if email already has a key (prevent spam signups)
	var existingCount int
	h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM api_keys WHERE email = $1 AND revoked_at IS NULL`, req.Email).Scan(&existingCount)
	if existingCount >= 3 {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "maximum API keys reached for this email"})
		return
	}

	// Generate a random API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	rawKey := "shrike_" + hex.EncodeToString(keyBytes)

	// Hash for storage
	hash := sha256.Sum256([]byte(rawKey))

	var id int64
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO api_keys (key_hash, owner, email, tier)
		 VALUES ($1, $2, $3, 'free')
		 RETURNING id`,
		hash[:], req.Owner, req.Email).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"api_key": rawKey,
		"tier":    "free",
		"message": "Store this key securely — it cannot be retrieved again.",
	})
}
