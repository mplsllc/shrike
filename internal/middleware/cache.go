package middleware

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

// CacheControl sets Cache-Control headers based on the request path.
// Current WHOIS: 15 min. History: 1 hour. Search: 5 min. DNS: 5 min.
func CacheControl() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Only cache successful GET responses
		if c.Request.Method != "GET" || c.Writer.Status() >= 400 {
			return
		}

		path := c.Request.URL.Path
		var maxAge int

		switch {
		case strings.Contains(path, "/history"):
			maxAge = 3600 // 1 hour — history is immutable
		case strings.Contains(path, "/dns"):
			maxAge = 300 // 5 min — DNS changes faster
		case strings.Contains(path, "/search"):
			maxAge = 300 // 5 min
		case strings.HasPrefix(path, "/api/v1/domains/") ||
			strings.HasPrefix(path, "/api/v1/ips/") ||
			strings.HasPrefix(path, "/api/v1/asns/"):
			maxAge = 900 // 15 min — current WHOIS data
		case strings.HasPrefix(path, "/api/v1/stats"):
			maxAge = 300 // 5 min
		default:
			maxAge = 60 // 1 min default
		}

		c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	}
}
