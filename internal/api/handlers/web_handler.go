package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"git.mp.ls/mpls/shrike/internal/cache"
	"git.mp.ls/mpls/shrike/internal/models"
	"git.mp.ls/mpls/shrike/internal/repository"
	"git.mp.ls/mpls/shrike/internal/services"
)

type WebHandler struct {
	tmplMap    map[string]*template.Template
	pool       *pgxpool.Pool
	domainRepo *repository.DomainRepository
	ipRepo     *repository.IPRepository
	asnRepo    *repository.ASNRepository
	lookup     *services.LookupService
	cache      *cache.Cache
}

type StatsData struct {
	Domains    int `json:"domains"`
	Snapshots  int `json:"snapshots"`
	IPBlocks   int `json:"ip_blocks"`
	ASNs       int `json:"asns"`
	DNSRecords int `json:"dns_records"`
}

func NewWebHandler(
	templateDir string,
	pool *pgxpool.Pool,
	domainRepo *repository.DomainRepository,
	ipRepo *repository.IPRepository,
	asnRepo *repository.ASNRepository,
	lookup *services.LookupService,
	appCache *cache.Cache,
) *WebHandler {
	funcMap := template.FuncMap{
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"derefBool": func(b *bool) bool {
			if b == nil {
				return false
			}
			return *b
		},
		"derefInt": func(i *int) int {
			if i == nil {
				return 0
			}
			return *i
		},
	}

	// Parse layout + partials as the base template set
	baseFiles := []string{
		filepath.Join(templateDir, "layouts", "base.html"),
		filepath.Join(templateDir, "partials", "header.html"),
		filepath.Join(templateDir, "partials", "footer.html"),
	}

	// For each page, clone the base templates and parse the page into the clone.
	// This gives each page its own template set with the layout + partials available.
	pages := map[string]string{
		"home":           filepath.Join(templateDir, "pages", "home.html"),
		"domain":         filepath.Join(templateDir, "pages", "domain.html"),
		"domain_loading": filepath.Join(templateDir, "pages", "domain_loading.html"),
		"ip":             filepath.Join(templateDir, "pages", "ip.html"),
		"asn":            filepath.Join(templateDir, "pages", "asn.html"),
		"status":         filepath.Join(templateDir, "pages", "status.html"),
		"privacy":        filepath.Join(templateDir, "pages", "privacy.html"),
		"docs":           filepath.Join(templateDir, "pages", "docs.html"),
		"graph":          filepath.Join(templateDir, "pages", "graph.html"),
		"license":        filepath.Join(templateDir, "pages", "license.html"),
	}

	base := template.Must(template.New("base").Funcs(funcMap).ParseFiles(baseFiles...))

	tmplMap := make(map[string]*template.Template, len(pages))
	for name, pagePath := range pages {
		clone := template.Must(base.Clone())
		tmplMap[name] = template.Must(clone.ParseFiles(pagePath))
	}

	return &WebHandler{
		tmplMap:    tmplMap,
		pool:       pool,
		domainRepo: domainRepo,
		ipRepo:     ipRepo,
		asnRepo:    asnRepo,
		lookup:     lookup,
		cache:      appCache,
	}
}

func (h *WebHandler) Home(c *gin.Context) {
	stats := h.getStats(c)
	h.render(c, "home", gin.H{"Stats": stats})
}

func (h *WebHandler) DomainPage(c *gin.Context) {
	name := strings.ToLower(c.Param("name"))

	// If redirected from poll after lookup completed/failed, just show what we have
	// without triggering another async lookup
	skipLookup := c.Query("done") == "1"

	if !skipLookup {
		result, isAsync, err := h.lookup.Lookup(c.Request.Context(), name, false)
		if err != nil {
			h.render(c, "domain", gin.H{
				"Domain": models.Domain{Name: name, TLD: domainTLD(name)},
				"Error":  "Something went wrong",
			})
			return
		}

		if isAsync {
			h.render(c, "domain_loading", gin.H{
				"DomainName": name,
			})
			return
		}

		if result != nil && result.Domain != nil {
			h.render(c, "domain", gin.H{
				"Domain":   result.Domain,
				"Snapshot": result.Snapshot,
				"DNS":      result.DNS,
			})
			return
		}
	}

	// No data — either skipped lookup or lookup returned nothing.
	// Check DB directly for whatever we have.
	domain, _ := h.domainRepo.GetByName(c.Request.Context(), name)
	if domain != nil {
		snap, _ := h.domainRepo.GetLatestSnapshot(c.Request.Context(), domain.ID)
		h.render(c, "domain", gin.H{
			"Domain":   domain,
			"Snapshot": snap,
		})
		return
	}

	h.render(c, "domain", gin.H{
		"Domain": models.Domain{Name: name, TLD: domainTLD(name)},
	})
}

// DomainPoll is called by htmx every 2 seconds during a live lookup.
// When the lookup is done, it redirects to the full domain page.
func (h *WebHandler) DomainPoll(c *gin.Context) {
	name := strings.ToLower(c.Param("name"))

	status := h.lookup.GetInflightStatus(name)
	switch status {
	case services.StatusReady:
		c.Redirect(http.StatusFound, "/domain/"+name+"?done=1")
	case services.StatusError:
		c.Redirect(http.StatusFound, "/domain/"+name+"?done=1")
	case services.StatusUnknown:
		// Lookup finished and was cleaned up — redirect to result
		c.Redirect(http.StatusFound, "/domain/"+name+"?done=1")
	default:
		// Still fetching — return the same loading HTML for htmx to re-poll
		h.render(c, "domain_loading", gin.H{
			"DomainName": name,
		})
	}
}

func (h *WebHandler) IPPage(c *gin.Context) {
	address := c.Param("address")

	block, err := h.ipRepo.FindContaining(c.Request.Context(), address)
	if err != nil {
		h.render(c, "ip", gin.H{"Address": address, "Error": "Something went wrong"})
		return
	}

	var snap *models.IPSnapshot
	if block != nil {
		snap, _ = h.ipRepo.GetLatestSnapshot(c.Request.Context(), block.ID)
	}

	h.render(c, "ip", gin.H{
		"Address":  address,
		"IPBlock":  block,
		"Snapshot": snap,
	})
}

func (h *WebHandler) ASNPage(c *gin.Context) {
	numStr := c.Param("number")
	num, _ := strconv.Atoi(numStr)

	asn, err := h.asnRepo.GetByNumber(c.Request.Context(), num)
	if err != nil || asn == nil {
		h.render(c, "asn", gin.H{
			"ASN": models.ASN{Number: num},
		})
		return
	}

	snap, _ := h.asnRepo.GetLatestSnapshot(c.Request.Context(), asn.ID)
	prefixes, _ := h.asnRepo.GetPrefixes(c.Request.Context(), asn.ID, models.Pagination{Limit: 50})

	var prefixList []models.ASNPrefix
	if prefixes != nil {
		prefixList = prefixes.Data
	}

	h.render(c, "asn", gin.H{
		"ASN":      asn,
		"Snapshot": snap,
		"Prefixes": prefixList,
	})
}

func (h *WebHandler) StatusPage(c *gin.Context) {
	stats := h.getStats(c)
	dbStatus := "Connected"
	if err := h.pool.Ping(c.Request.Context()); err != nil {
		dbStatus = "Unreachable"
	}

	h.render(c, "status", gin.H{
		"Stats":         stats,
		"DBStatus":      dbStatus,
		"CrawlerStatus": "Running",
		"QueueDepth":    0,
	})
}

func (h *WebHandler) PrivacyPage(c *gin.Context) {
	h.render(c, "privacy", nil)
}

func (h *WebHandler) LicensePage(c *gin.Context) {
	h.render(c, "license", nil)
}

func (h *WebHandler) DocsPage(c *gin.Context) {
	h.render(c, "docs", nil)
}

func (h *WebHandler) GraphPage(c *gin.Context) {
	name := strings.ToLower(c.Param("name"))
	graphRepo := repository.NewGraphRepository(h.pool)
	graph, err := graphRepo.DomainGraph(c.Request.Context(), name)
	if err != nil {
		h.render(c, "status", gin.H{"Error": "Domain not found"})
		return
	}
	graphJSON, _ := json.Marshal(graph)
	h.render(c, "graph", gin.H{
		"Label":     name,
		"GraphJSON": template.JS(graphJSON),
	})
}

func (h *WebHandler) render(c *gin.Context, name string, data interface{}) {
	tmpl, ok := h.tmplMap[name]
	if !ok {
		c.String(http.StatusInternalServerError, "Template %q not found", name)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(c.Writer, "base.html", data); err != nil {
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

func (h *WebHandler) getStats(c *gin.Context) *StatsData {
	stats := &StatsData{}
	h.pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM domains").Scan(&stats.Domains)
	h.pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM domain_snapshots").Scan(&stats.Snapshots)
	h.pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM ip_blocks").Scan(&stats.IPBlocks)
	h.pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM asns").Scan(&stats.ASNs)
	h.pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM dns_records").Scan(&stats.DNSRecords)
	return stats
}

func domainTLD(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	return parts[len(parts)-1]
}
