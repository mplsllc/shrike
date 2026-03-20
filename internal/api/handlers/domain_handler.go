package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"git.mp.ls/mpls/shrike/internal/cache"
	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
	"git.mp.ls/mpls/shrike/internal/services"
)

type DomainHandler struct {
	repo    *repository.DomainRepository
	lookup  *services.LookupService
	cache   *cache.Cache
}

func NewDomainHandler(repo *repository.DomainRepository, lookup *services.LookupService, cache *cache.Cache) *DomainHandler {
	return &DomainHandler{repo: repo, lookup: lookup, cache: cache}
}

// GetDomain returns the current snapshot for a domain.
// If the domain is unknown, triggers a real-time lookup.
// ?wait=true blocks until the lookup completes (up to 15s).
// Otherwise returns 202 with a poll URL.
func (h *DomainHandler) GetDomain(c *gin.Context) {
	name := strings.ToLower(c.Param("name"))
	wait := c.Query("wait") == "true"

	// Check cache first
	domain, snap := h.cache.GetDomain(name)
	if domain != nil && snap != nil {
		c.JSON(http.StatusOK, models.DomainDetail{
			Domain:          *domain,
			CurrentSnapshot: snap,
		})
		return
	}

	// Real-time lookup (checks DB, then live crawl if needed)
	result, isAsync, err := h.lookup.Lookup(c.Request.Context(), name, wait)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	if isAsync {
		// Lookup started asynchronously — return 202 with poll URL
		c.Header("Location", "/api/v1/domains/"+name+"/status")
		c.JSON(http.StatusAccepted, gin.H{
			"status":            "fetching",
			"message":           "Live lookup in progress",
			"poll_url":          "/api/v1/domains/" + name + "/status",
			"estimated_seconds": 5,
		})
		return
	}

	if result == nil || result.Err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "WHOIS lookup failed for this domain"})
		return
	}

	detail := models.DomainDetail{
		CurrentSnapshot: result.Snapshot,
	}
	if result.Domain != nil {
		detail.Domain = *result.Domain
	}
	if result.DNS != nil {
		detail.DNSSummary = result.DNS
	}

	c.JSON(http.StatusOK, detail)
}

// GetDomainStatus returns the status of an in-flight lookup.
// Used for polling after a 202 response.
func (h *DomainHandler) GetDomainStatus(c *gin.Context) {
	name := strings.ToLower(c.Param("name"))

	status := h.lookup.GetInflightStatus(name)

	switch status {
	case services.StatusFetching:
		c.JSON(http.StatusOK, gin.H{
			"status":  "fetching",
			"message": "Querying WHOIS server...",
		})
	case services.StatusReady:
		// Redirect to the full result
		c.Header("Location", "/api/v1/domains/"+name)
		c.JSON(http.StatusOK, gin.H{
			"status":   "ready",
			"location": "/api/v1/domains/" + name,
		})
	case services.StatusError:
		c.JSON(http.StatusOK, gin.H{
			"status":  "error",
			"message": "Lookup failed",
		})
	default:
		// No in-flight lookup — check if domain exists in DB
		domain, _ := h.cache.GetDomain(name)
		if domain != nil {
			c.JSON(http.StatusOK, gin.H{
				"status":   "ready",
				"location": "/api/v1/domains/" + name,
			})
		} else {
			c.JSON(http.StatusNotFound, gin.H{
				"status":  "unknown",
				"message": "No lookup in progress for this domain",
			})
		}
	}
}

// GetDomainHistory returns historical snapshots for a domain.
func (h *DomainHandler) GetDomainHistory(c *gin.Context) {
	name := strings.ToLower(c.Param("name"))

	domain, err := h.repo.GetByName(c.Request.Context(), name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if domain == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}

	timeRange := parseTimeRange(c)
	page := parsePagination(c)

	result, err := h.repo.GetHistory(c.Request.Context(), domain.ID, timeRange, page)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func parseTimeRange(c *gin.Context) models.TimeRange {
	var tr models.TimeRange
	if from := c.Query("from"); from != "" {
		if t, err := time.Parse("2006-01-02", from); err == nil {
			tr.From = &t
		}
	}
	if to := c.Query("to"); to != "" {
		if t, err := time.Parse("2006-01-02", to); err == nil {
			tr.To = &t
		}
	}
	return tr
}

func parsePagination(c *gin.Context) models.Pagination {
	page := models.Pagination{Limit: 50, Offset: 0}
	if limit := c.Query("limit"); limit != "" {
		if l := parseInt(limit); l > 0 && l <= 100 {
			page.Limit = l
		}
	}
	if offset := c.Query("offset"); offset != "" {
		if o := parseInt(offset); o >= 0 {
			page.Offset = o
		}
	}
	return page
}

func parseInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 10000 {
		return 0
	}
	return n
}
