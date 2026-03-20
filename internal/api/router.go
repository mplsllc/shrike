package api

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"git.mp.ls/mpls/shrike/internal/api/handlers"
	"git.mp.ls/mpls/shrike/internal/cache"
	"git.mp.ls/mpls/shrike/internal/middleware"
	"git.mp.ls/mpls/shrike/internal/repository"
	"git.mp.ls/mpls/shrike/internal/services"
)

// RouterDeps holds all dependencies needed by the router.
type RouterDeps struct {
	Pool          *pgxpool.Pool
	DomainRepo    *repository.DomainRepository
	IPRepo        *repository.IPRepository
	ASNRepo       *repository.ASNRepository
	LookupService *services.LookupService
	Cache         *cache.Cache
	RateLimitCfg  middleware.RateLimitConfig
	TemplateDir   string
}

func NewRouter(deps RouterDeps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	// Trust only the local nginx reverse proxy — prevents X-Forwarded-For spoofing
	r.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	r.ForwardedByClientIP = true
	r.RemoteIPHeaders = []string{"X-Real-IP", "X-Forwarded-For"}

	// Global middleware
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORS())
	r.Use(middleware.RequestSizeLimit(10 << 20)) // 10MB max request body

	// API key auth (sets tier on context, anonymous passes through)
	apiKeyAuth := middleware.NewApiKeyAuth(deps.Pool)
	r.Use(apiKeyAuth.Middleware())

	// Bot protection (blocks scrapers without API keys)
	r.Use(middleware.BotProtection())

	// Rate limiting with progressive bans
	rateLimiter := middleware.NewAPIRateLimiter(deps.RateLimitCfg)
	r.Use(rateLimiter.Middleware())

	// HTTP cache headers
	r.Use(middleware.CacheControl())

	// Health and metrics
	r.GET("/health", handlers.Health(deps.Pool))
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Static files
	r.Static("/static", "web/static")

	// Handlers
	domainHandler := handlers.NewDomainHandler(deps.DomainRepo, deps.LookupService, deps.Cache)
	apiKeyHandler := handlers.NewAPIKeyHandler(deps.Pool)

	// Web handler for template-rendered pages
	webHandler := handlers.NewWebHandler(
		deps.TemplateDir,
		deps.Pool,
		deps.DomainRepo,
		deps.IPRepo,
		deps.ASNRepo,
		deps.LookupService,
		deps.Cache,
	)

	// Redaction handler
	redactionRepo := repository.NewRedactionRepository(deps.Pool)
	redactionHandler := handlers.NewRedactionHandler(redactionRepo)

	// Web UI routes
	r.GET("/", webHandler.Home)
	r.GET("/domain/:name", webHandler.DomainPage)
	r.GET("/domain/:name/poll", webHandler.DomainPoll)
	r.GET("/ip/:address", webHandler.IPPage)
	r.GET("/asn/:number", webHandler.ASNPage)
	r.GET("/status", webHandler.StatusPage)
	r.GET("/privacy", webHandler.PrivacyPage)
	r.GET("/license", webHandler.LicensePage)
	r.GET("/docs", webHandler.DocsPage)
	r.GET("/graph/:name", webHandler.GraphPage)
	r.POST("/api/v1/redaction-request", redactionHandler.SubmitRequest)

	// Contribution handler
	contributionHandler := handlers.NewContributionHandler(deps.Pool)

	// API v1
	v1 := r.Group("/api/v1")
	{
		// Domain WHOIS
		v1.GET("/domains/:name", domainHandler.GetDomain)
		v1.GET("/domains/:name/status", domainHandler.GetDomainStatus)
		v1.GET("/domains/:name/history", domainHandler.GetDomainHistory)
		v1.GET("/domains/:name/dns", handlers.NotImplemented)
		v1.GET("/domains/:name/dns/history", handlers.NotImplemented)
		v1.GET("/domains/:name/graph", handlers.NotImplemented)

		// IP WHOIS
		v1.GET("/ips/:address", handlers.NotImplemented)
		v1.GET("/ips/:address/history", handlers.NotImplemented)
		v1.GET("/ips/:address/domains", handlers.NotImplemented)
		v1.GET("/ips/:address/asn", handlers.NotImplemented)

		// ASN
		v1.GET("/asns/:number", handlers.NotImplemented)
		v1.GET("/asns/:number/history", handlers.NotImplemented)
		v1.GET("/asns/:number/prefixes", handlers.NotImplemented)
		v1.GET("/asns/:number/prefixes/history", handlers.NotImplemented)
		v1.GET("/asns/:number/domains", handlers.NotImplemented)

		// Search & cross-reference
		v1.GET("/search", handlers.NotImplemented)
		v1.GET("/graph/domain/:name", handlers.NotImplemented)
		v1.GET("/graph/org/:name", handlers.NotImplemented)
		v1.GET("/pivot/nameserver/:ns", handlers.NotImplemented)
		v1.GET("/pivot/registrar/:name", handlers.NotImplemented)

		// Community
		v1.POST("/contribute", contributionHandler.Submit)

		// API key signup
		v1.POST("/keys/signup", apiKeyHandler.Signup)

		// Operational
		v1.GET("/stats", handlers.NotImplemented)
	}

	return r
}
