package handlers

import (
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"

	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
)

type RedactionHandler struct {
	repo *repository.RedactionRepository
}

func NewRedactionHandler(repo *repository.RedactionRepository) *RedactionHandler {
	return &RedactionHandler{repo: repo}
}

// SubmitRequest handles the privacy page form submission.
func (h *RedactionHandler) SubmitRequest(c *gin.Context) {
	email := c.PostForm("email")
	domain := c.PostForm("domain")
	description := c.PostForm("description")

	if email == "" || description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and description are required"})
		return
	}

	// Validate email format
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email format"})
		return
	}

	// Limit description length
	if len(description) > 5000 {
		description = description[:5000]
	}

	req := &models.RedactionRequest{
		RequesterEmail: email,
		Description:    description,
	}
	if domain != "" {
		req.DomainName = &domain
	}

	id, err := h.repo.Submit(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to submit request"})
		return
	}

	// If submitted from HTML form, redirect back to privacy page
	if c.GetHeader("Accept") == "" || c.ContentType() == "application/x-www-form-urlencoded" {
		c.Redirect(http.StatusSeeOther, "/privacy?submitted=true")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"status":  "pending",
		"message": "Redaction request received. We will process it within 30 days.",
	})
}
