package geo_access_control

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Config holds the plugin configuration
type Config struct {
	// API endpoint for geolocation lookup
	// Supports placeholders: {ip}
	// Default: http://geoip-api:8080/country/{ip}
	API string `json:"api,omitempty"`

	// API timeout in milliseconds
	APITimeoutMs int `json:"apiTimeoutMs,omitempty"`

	// Use JSON format for API requests (adds ?format=json to API calls)
	// Default: true (uses JSON format)
	UseJSONFormat bool `json:"useJSONFormat,omitempty"`

	// List of allowed countries (ISO 3166-1 alpha-2 codes, e.g., US, CA, GB)
	// If a request's country matches any in this list, it will be allowed
	AllowedCountries []string `json:"allowedCountries,omitempty"`

	// List of allowed regions (format: COUNTRY-REGION, e.g., US-CA, CN-44)
	// If a request's region matches any in this list, it will be allowed
	// Note: Requires GeoLite2-City database
	AllowedRegions []string `json:"allowedRegions,omitempty"`

	// List of allowed cities (format: COUNTRY|City, e.g., US|New York)
	// If a request's city matches any in this list, it will be allowed
	// Note: Requires GeoLite2-City database
	AllowedCities []string `json:"allowedCities,omitempty"`

	// Blacklist mode: if true, block listed countries/regions/cities instead of allowing them
	BlackListMode bool `json:"blackListMode,omitempty"`

	// Allow requests from private IP addresses (192.168.x.x, 10.x.x.x, etc.)
	AllowLocalRequests bool `json:"allowLocalRequests,omitempty"`

	// Allow requests when country cannot be determined
	AllowUnknownCountries bool `json:"allowUnknownCountries,omitempty"`

	// List of IP addresses to always allow (supports CIDR notation)
	AllowedIPs []string `json:"allowedIPs,omitempty"`

	// LRU cache size for IP lookups
	CacheSize int `json:"cacheSize,omitempty"`

	// HTTP status code to return when blocking (default: 403)
	DeniedHTTPStatusCode int `json:"deniedHTTPStatusCode,omitempty"`

	// Custom error message for blocked requests
	DeniedMessage string `json:"deniedMessage,omitempty"`

	// Redirect URL for blocked requests (overrides status code and message)
	RedirectURL string `json:"redirectURL,omitempty"`

	// Add country/region/city information to request headers
	AddCountryHeader bool `json:"addCountryHeader,omitempty"`
	AddRegionHeader  bool `json:"addRegionHeader,omitempty"`
	AddCityHeader    bool `json:"addCityHeader,omitempty"`

	// Path patterns to exclude from filtering (regex)
	ExcludedPathPatterns []string `json:"excludedPathPatterns,omitempty"`

	// Enable verbose logging
	LogAllowedRequests bool `json:"logAllowedRequests,omitempty"`
	LogBlockedRequests bool `json:"logBlockedRequests,omitempty"`
	LogAPIRequests     bool `json:"logAPIRequests,omitempty"`
	LogLocalRequests   bool `json:"logLocalRequests,omitempty"`

	// Silent startup (disable startup messages)
	SilentStartUp bool `json:"silentStartUp,omitempty"`
}

// CreateConfig creates and initializes the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		API:                   "http://geoip-api:8080/country/{ip}",
		APITimeoutMs:          750,
		UseJSONFormat:         true,
		AllowedCountries:      []string{},
		AllowedRegions:        []string{},
		AllowedCities:         []string{},
		BlackListMode:         false,
		AllowLocalRequests:    true,
		AllowUnknownCountries: false,
		AllowedIPs:            []string{},
		CacheSize:             100,
		DeniedHTTPStatusCode:  http.StatusForbidden,
		DeniedMessage:         "Access Denied",
		RedirectURL:           "",
		AddCountryHeader:      false,
		AddRegionHeader:       false,
		AddCityHeader:         false,
		ExcludedPathPatterns:  []string{},
		LogAllowedRequests:    false,
		LogBlockedRequests:    true,
		LogAPIRequests:        false,
		LogLocalRequests:      false,
		SilentStartUp:         false,
	}
}

// GeoAccessControl holds the plugin instance
type GeoAccessControl struct {
	next                 http.Handler
	name                 string
	config               *Config
	cache                *LRUCache
	excludedPathRegexps  []*regexp.Regexp
	privateIPRanges      []*net.IPNet
	allowedIPRanges      []*net.IPNet
	httpClient           *http.Client
}

// GeoData holds geolocation information from API
type GeoData struct {
	Country string
	Region  string
	City    string
}

// APIResponse is the JSON response structure from geoip-api
type APIResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	Region  string `json:"region,omitempty"`
}

// New creates a new plugin instance
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validate configuration
	if config.API == "" {
		return nil, fmt.Errorf("API endpoint is required")
	}

	// Validate that at least one filter list is provided (unless in blacklist mode)
	if !config.BlackListMode {
		if len(config.AllowedCountries) == 0 && len(config.AllowedRegions) == 0 && len(config.AllowedCities) == 0 {
			return nil, fmt.Errorf("at least one of allowedCountries, allowedRegions, or allowedCities must be specified")
		}
	}

	// Set defaults
	if config.DeniedHTTPStatusCode == 0 {
		config.DeniedHTTPStatusCode = http.StatusForbidden
	}

	if config.APITimeoutMs == 0 {
		config.APITimeoutMs = 750
	}

	if config.CacheSize == 0 {
		config.CacheSize = 100
	}

	plugin := &GeoAccessControl{
		next:   next,
		name:   name,
		config: config,
		cache:  NewLRUCache(config.CacheSize),
		httpClient: &http.Client{
			Timeout: time.Duration(config.APITimeoutMs) * time.Millisecond,
		},
	}

	// Initialize private IP ranges
	plugin.privateIPRanges = parsePrivateIPRanges()

	// Parse allowed IPs
	if len(config.AllowedIPs) > 0 {
		var err error
		plugin.allowedIPRanges, err = parseIPRanges(config.AllowedIPs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowedIPs: %w", err)
		}
	}

	// Compile excluded path patterns
	for _, pattern := range config.ExcludedPathPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile excludedPathPattern '%s': %w", pattern, err)
		}
		plugin.excludedPathRegexps = append(plugin.excludedPathRegexps, re)
	}

	if !config.SilentStartUp {
		filters := []string{}
		if len(config.AllowedCountries) > 0 {
			filters = append(filters, fmt.Sprintf("countries=%d", len(config.AllowedCountries)))
		}
		if len(config.AllowedRegions) > 0 {
			filters = append(filters, fmt.Sprintf("regions=%d", len(config.AllowedRegions)))
		}
		if len(config.AllowedCities) > 0 {
			filters = append(filters, fmt.Sprintf("cities=%d", len(config.AllowedCities)))
		}
		log.Printf("[Geo Access Control] Plugin initialized: filters=[%s], cacheSize=%d, api=%s",
			strings.Join(filters, ", "), config.CacheSize, config.API)
	}

	return plugin, nil
}

// ServeHTTP implements the http.Handler interface
func (g *GeoAccessControl) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check if path is excluded
	for _, re := range g.excludedPathRegexps {
		if re.MatchString(req.URL.Path) {
			g.next.ServeHTTP(rw, req)
			return
		}
	}

	// Extract client IP
	clientIP := g.extractClientIP(req)
	if clientIP == "" {
		if g.config.LogBlockedRequests {
			log.Printf("[Geo Access Control] No client IP found in request")
		}
		g.denyRequest(rw, req, "No client IP found")
		return
	}

	// Check if IP is in allowed list
	if g.isIPAllowed(clientIP) {
		if g.config.LogLocalRequests {
			log.Printf("[Geo Access Control] IP %s is in allowed list", clientIP)
		}
		g.next.ServeHTTP(rw, req)
		return
	}

	// Check if it's a private IP and local requests are allowed
	if g.config.AllowLocalRequests && g.isPrivateIP(clientIP) {
		if g.config.LogLocalRequests {
			log.Printf("[Geo Access Control] Private IP %s allowed", clientIP)
		}
		g.next.ServeHTTP(rw, req)
		return
	}

	// Get geolocation data
	geoData, err := g.getGeoData(clientIP)
	if err != nil {
		if g.config.AllowUnknownCountries {
			if g.config.LogAllowedRequests {
				log.Printf("[Geo Access Control] Unknown country for IP %s, allowing (allowUnknownCountries=true)", clientIP)
			}
			g.next.ServeHTTP(rw, req)
		} else {
			if g.config.LogBlockedRequests {
				log.Printf("[Geo Access Control] Failed to get geolocation for IP %s: %v", clientIP, err)
			}
			g.denyRequest(rw, req, fmt.Sprintf("Failed to determine location: %v", err))
		}
		return
	}

	// Add headers if configured
	if g.config.AddCountryHeader && geoData.Country != "" {
		req.Header.Set("X-Country-Code", geoData.Country)
	}
	if g.config.AddRegionHeader && geoData.Region != "" {
		req.Header.Set("X-Region-Code", geoData.Region)
	}
	if g.config.AddCityHeader && geoData.City != "" {
		req.Header.Set("X-City-Name", geoData.City)
	}

	// Check access based on filter mode
	allowed := g.checkAccess(geoData)

	if allowed {
		if g.config.LogAllowedRequests {
			log.Printf("[Geo Access Control] Allowed: IP=%s, Country=%s, Region=%s, City=%s",
				clientIP, geoData.Country, geoData.Region, geoData.City)
		}
		g.next.ServeHTTP(rw, req)
	} else {
		if g.config.LogBlockedRequests {
			log.Printf("[Geo Access Control] Blocked: IP=%s, Country=%s, Region=%s, City=%s",
				clientIP, geoData.Country, geoData.Region, geoData.City)
		}
		g.denyRequest(rw, req, fmt.Sprintf("Access denied from %s", geoData.Country))
	}
}

// extractClientIP extracts the client IP from the request
func (g *GeoAccessControl) extractClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// isPrivateIP checks if an IP is in a private range
func (g *GeoAccessControl) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, ipRange := range g.privateIPRanges {
		if ipRange.Contains(ip) {
			return true
		}
	}

	return false
}

// isIPAllowed checks if an IP is in the allowed list
func (g *GeoAccessControl) isIPAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, ipRange := range g.allowedIPRanges {
		if ipRange.Contains(ip) {
			return true
		}
	}

	return false
}

// getGeoData retrieves geolocation data for an IP
func (g *GeoAccessControl) getGeoData(ip string) (*GeoData, error) {
	// Check cache first
	if cached, found := g.cache.Get(ip); found {
		if g.config.LogAPIRequests {
			log.Printf("[Geo Access Control] Cache hit for IP %s", ip)
		}
		return cached.(*GeoData), nil
	}

	// Determine API endpoint based on configured filters
	// Priority: City > Region > Country (use highest level needed)
	var apiURL string
	if len(g.config.AllowedCities) > 0 || len(g.config.AllowedRegions) > 0 {
		// Need city/region data, use city endpoint (includes region info)
		apiURL = strings.ReplaceAll(g.config.API, "/country/", "/city/")
		apiURL = strings.ReplaceAll(apiURL, "{ip}", ip)
	} else {
		// Only need country data
		apiURL = strings.ReplaceAll(g.config.API, "{ip}", ip)
	}

	// Add JSON format parameter if enabled
	if g.config.UseJSONFormat {
		if strings.Contains(apiURL, "?") {
			apiURL += "&format=json"
		} else {
			apiURL += "?format=json"
		}
	}

	if g.config.LogAPIRequests {
		log.Printf("[Geo Access Control] Querying API: %s", apiURL)
	}

	// Make API request
	resp, err := g.httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response: %w", err)
	}

	// Parse response based on format
	geoData := &GeoData{}
	bodyStr := strings.TrimSpace(string(body))

	// Check if response is JSON
	if strings.HasPrefix(bodyStr, "{") {
		// Parse JSON response
		var apiResp APIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			return nil, fmt.Errorf("failed to parse JSON response: %w", err)
		}

		geoData.Country = apiResp.Country
		geoData.City = apiResp.City
		geoData.Region = apiResp.Region

		if g.config.LogAPIRequests {
			log.Printf("[Geo Access Control] Parsed JSON response: Country=%s, City=%s, Region=%s",
				geoData.Country, geoData.City, geoData.Region)
		}
	} else {
		// Parse text format from our geoip-api:
		// /country/ endpoint: "Country"
		// /city/ endpoint: "Country|City|Region"
		// /region/ endpoint: "Country|Region"
		parts := strings.Split(bodyStr, "|")
		if len(parts) > 0 {
			geoData.Country = strings.TrimSpace(parts[0])
		}
		// City endpoint returns: Country|City|Region
		if len(parts) > 1 {
			geoData.City = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			geoData.Region = strings.TrimSpace(parts[2])
		}

		if g.config.LogAPIRequests {
			log.Printf("[Geo Access Control] Parsed text response: Country=%s, City=%s, Region=%s",
				geoData.Country, geoData.City, geoData.Region)
		}
	}

	// Cache the result
	g.cache.Set(ip, geoData)

	return geoData, nil
}

// checkAccess determines if access should be allowed based on geo data
// Uses priority-based matching: City > Region > Country
// If a country has city rules defined, only city rules are checked for that country
// If a country has region rules defined (no city), only region rules are checked
// Otherwise, country rules are checked
func (g *GeoAccessControl) checkAccess(geoData *GeoData) bool {
	if geoData.Country == "" {
		return false // No country data, cannot make decision
	}

	// Check if this country has city-level rules defined
	hasCityRules := g.hasCountryCityRules(geoData.Country)

	// Check if this country has region-level rules defined
	hasRegionRules := g.hasCountryRegionRules(geoData.Country)

	var matched bool

	// Priority 1: City rules (if defined for this country)
	if hasCityRules {
		if geoData.City != "" {
			cityKey := fmt.Sprintf("%s|%s", geoData.Country, geoData.City)
			matched = contains(g.config.AllowedCities, cityKey)
		} else {
			// Country has city rules but we don't have city data
			matched = false
		}
	} else if hasRegionRules {
		// Priority 2: Region rules (if defined for this country, and no city rules)
		if geoData.Region != "" {
			// Combine country and region (e.g., US + CA = US-CA)
			fullRegion := geoData.Country + "-" + geoData.Region
			matched = contains(g.config.AllowedRegions, fullRegion)
		} else {
			// Country has region rules but we don't have region data
			matched = false
		}
	} else {
		// Priority 3: Country rules (no city or region rules for this country)
		matched = contains(g.config.AllowedCountries, geoData.Country)
	}

	// Apply blacklist/whitelist logic
	if g.config.BlackListMode {
		return !matched // Block if matched in blacklist
	}
	return matched // Allow if matched in whitelist
}

// hasCountryCityRules checks if there are any city rules defined for a specific country
func (g *GeoAccessControl) hasCountryCityRules(country string) bool {
	prefix := country + "|"
	for _, city := range g.config.AllowedCities {
		if strings.HasPrefix(city, prefix) {
			return true
		}
	}
	return false
}

// hasCountryRegionRules checks if there are any region rules defined for a specific country
func (g *GeoAccessControl) hasCountryRegionRules(country string) bool {
	prefix := country + "-"
	for _, region := range g.config.AllowedRegions {
		if strings.HasPrefix(region, prefix) {
			return true
		}
	}
	return false
}

// denyRequest sends a denial response
func (g *GeoAccessControl) denyRequest(rw http.ResponseWriter, req *http.Request, reason string) {
	if g.config.RedirectURL != "" {
		http.Redirect(rw, req, g.config.RedirectURL, http.StatusTemporaryRedirect)
		return
	}

	rw.WriteHeader(g.config.DeniedHTTPStatusCode)
	if g.config.DeniedMessage != "" {
		rw.Write([]byte(g.config.DeniedMessage))
	}
}

// Helper functions

func parsePrivateIPRanges() []*net.IPNet {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	ranges, _ := parseIPRanges(privateRanges)
	return ranges
}

func parseIPRanges(ipStrings []string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet

	for _, ipStr := range ipStrings {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// Check if it's a CIDR notation
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %w", ipStr, err)
			}
			ranges = append(ranges, ipNet)
		} else {
			// Single IP address
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", ipStr)
			}
			// Create a /32 or /128 network
			var ipNet *net.IPNet
			if ip.To4() != nil {
				_, ipNet, _ = net.ParseCIDR(ipStr + "/32")
			} else {
				_, ipNet, _ = net.ParseCIDR(ipStr + "/128")
			}
			ranges = append(ranges, ipNet)
		}
	}

	return ranges, nil
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if strings.EqualFold(v, item) {
			return true
		}
	}
	return false
}
