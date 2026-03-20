package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders sets security headers on all responses.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://d3js.org; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://cdn.tailwindcss.com; font-src 'self' data:")
		c.Next()
	}
}

// CORS allows cross-origin API requests from known origins only.
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Allow requests from our own domain and localhost for dev
		allowed := origin == "https://shrike.mp.ls" ||
			origin == "http://localhost:8043" ||
			origin == ""

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
