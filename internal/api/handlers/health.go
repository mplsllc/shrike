package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"git.mp.ls/mpls/shrike/internal/version"
)

func Health(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := pool.Ping(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":  "unhealthy",
				"version": version.Version,
				"db":      "unreachable",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": version.Version,
			"db":      "connected",
		})
	}
}

func NotImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "not implemented yet",
	})
}
