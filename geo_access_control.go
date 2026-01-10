package geo_access_control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// RegionRules defines rules for a specific region within a country.
type RegionRules struct {
	Allowed bool     `json:"allowed,omitempty"`
	Cities  []string `json:"cities,omitempty"`
}

// CountryRules defines rules for a specific country.
type CountryRules struct {
	Allowed bool                   `json:"allowed,omitempty"`
	Regions map[string]RegionRules `json:"regions,omitempty"`
	Cities  []string               `json:"cities,omitempty"`
}

// Config holds the plugin configuration.
type Config struct {
	GeoAPIEndpoint        string                 `json:"geoAPIEndpoint,omitempty"`
	GeoAPITimeout         int                    `json:"geoAPITimeoutMilliseconds,omitempty"`
	GeoAPIResponseIsJSON  bool                   `json:"geoAPIResponseIsJSON,omitempty"`
	AccessRules           map[string]interface{} `json:"accessRules,omitempty"`
	AllowPrivateIPAccess  bool                   `json:"allowPrivateIPAccess,omitempty"`
	AllowRequestsWithoutGeoData bool                   `json:"allowRequestsWithoutGeoData,omitempty"`
	CacheSize             int                    `json:"cacheSize,omitempty"`
	DeniedStatusCode      int                    `json:"deniedStatusCode,omitempty"`
	DeniedResponseMessage string                 `json:"deniedResponseMessage,omitempty"`
	RedirectURL           string                 `json:"redirectURL,omitempty"`
	ExcludedPaths         []string               `json:"excludedPaths,omitempty"`
	LogAllowedAccess      bool                   `json:"logAllowedAccess,omitempty"`
	LogDeniedAccess       bool                   `json:"logDeniedAccess,omitempty"`
	LogGeoAPICalls        bool                   `json:"logGeoAPICalls,omitempty"`
	LogPrivateIPAccess    bool                   `json:"logPrivateIPAccess,omitempty"`
	LogLevel              string                 `json:"logLevel,omitempty"`
	LogFilePath           string                 `json:"logFilePath,omitempty"`
}

// CreateConfig creates and initializes the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		GeoAPIEndpoint:          "http://geoip-api:8080/country/{ip}",
		GeoAPITimeout:           750, // GeoAPI timeout in milliseconds
		GeoAPIResponseIsJSON:         true,
		AccessRules:           make(map[string]interface{}),
		AllowPrivateIPAccess:    true,
		AllowRequestsWithoutGeoData: false,
		CacheSize:             100,
		DeniedStatusCode:      http.StatusNotFound,
		DeniedResponseMessage:         "Not Found",
		LogLevel:              "info", // Default log level
		LogFilePath:           "",     // Default empty log file path
	}
}

// GeoAccessControl holds the plugin instance.
type GeoAccessControl struct {
	next                http.Handler
	name                string
	allowedRules        map[string]CountryRules
	config              *Config
	cache               *LRUCache
	excludedPathRegexps []*regexp.Regexp
	privateIPRanges     []*net.IPNet
	allowedIPs          []*net.IPNet
	deniedIPs           []*net.IPNet
	httpClient          *http.Client
	logger              *PluginLogger
}

// GeoData holds geolocation information from API.
type GeoData struct {
	Country string
	Region  string
	City    string
}

// APIResponse is the JSON response structure from geoip-api.
type APIResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	Region  string `json:"region,omitempty"`
}

// New creates a new plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Setup logging
	var logWriter io.Writer = os.Stderr
	if config.LogFilePath != "" {
		logFile, err := os.OpenFile(config.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		// TODO: Add a way to close the log file when the plugin is stopped.
		// For Traefik plugins, there isn't a direct "shutdown" hook, so this might be tricky.
		// For now, it will remain open for the lifetime of the plugin.
		logWriter = io.MultiWriter(os.Stderr, logFile)
	}

	pluginLogger := &PluginLogger{
		logger: log.New(logWriter, fmt.Sprintf("[%s] ", name), log.Ldate|log.Ltime|log.Lshortfile),
		level:  parseLogLevel(config.LogLevel),
	}

	if config.GeoAPIEndpoint == "" {
		pluginLogger.Errorf("API endpoint is required")
		return nil, fmt.Errorf("API endpoint is required")
	}

	plugin := &GeoAccessControl{
		next:   next,
		name:   name,
		config: config,
		cache:  NewLRUCache(config.CacheSize),
		httpClient: &http.Client{
			Timeout: time.Duration(config.GeoAPITimeout) * time.Millisecond,
		},
		logger: pluginLogger,
	}

	plugin.allowedRules = make(map[string]CountryRules)
	var allowedIPStrings, deniedIPStrings []string

	for key, configValue := range config.AccessRules {
		isCountryCode := len(key) == 2 && key == strings.ToUpper(key)
		isIP := net.ParseIP(key) != nil || strings.Contains(key, "/")

		if isCountryCode {
			countryRule := CountryRules{}
			if v, ok := configValue.(bool); ok {
				countryRule.Allowed = v
			} else if v, ok := configValue.(map[string]interface{}); ok {
				if regionsConfig, ok := v["regions"]; ok {
					countryRule.Regions = make(map[string]RegionRules)
					if rCfg, ok := regionsConfig.(map[string]interface{}); ok {
						for regionCode, regionRulesConfig := range rCfg {
							regionRule := RegionRules{}
							if rrCfg, ok := regionRulesConfig.(bool); ok {
								regionRule.Allowed = rrCfg
							} else if rrCfg, ok := regionRulesConfig.(map[string]interface{}); ok {
								if citiesConfig, ok := rrCfg["cities"].([]interface{}); ok {
									for _, cityItem := range citiesConfig {
										if cityStr, ok := cityItem.(string); ok {
											regionRule.Cities = append(regionRule.Cities, cityStr)
										}
									}
								}
							}
							countryRule.Regions[regionCode] = regionRule
						}
					}
				}
				if citiesConfig, ok := v["cities"].([]interface{}); ok {
					for _, cityItem := range citiesConfig {
						if cityStr, ok := cityItem.(string); ok {
							countryRule.Cities = append(countryRule.Cities, cityStr)
						}
					}
				}
			}
			plugin.allowedRules[key] = countryRule
		} else if isIP {
			if allowed, ok := configValue.(bool); ok {
				if allowed {
					allowedIPStrings = append(allowedIPStrings, key)
				} else {
					deniedIPStrings = append(deniedIPStrings, key)
				}
			}
		}
	}

	if len(plugin.allowedRules) == 0 && len(allowedIPStrings) == 0 && len(deniedIPStrings) == 0 {
		plugin.logger.Errorf("at least one rule must be specified in 'accessRules'")
		return nil, fmt.Errorf("at least one rule must be specified in 'accessRules'")
	}

	var err error
	plugin.privateIPRanges = parsePrivateIPRanges()

	if len(allowedIPStrings) > 0 {
		plugin.allowedIPs, err = parseIPRanges(allowedIPStrings)
		if err != nil {
			plugin.logger.Errorf("failed to parse allowed IPs: %w", err)
			return nil, fmt.Errorf("failed to parse allowed IPs: %w", err)
		}
	}
	if len(deniedIPStrings) > 0 {
		plugin.deniedIPs, err = parseIPRanges(deniedIPStrings)
		if err != nil {
			plugin.logger.Errorf("failed to parse denied IPs: %w", err)
			return nil, fmt.Errorf("failed to parse denied IPs: %w", err)
		}
	}

	return plugin, nil
}

// ServeHTTP implements the http.Handler interface.
func (g *GeoAccessControl) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := g.extractClientIP(req)
	if clientIP == "" {
		g.logger.Warnf("Unable to extract client IP for request to %s", req.Host)
		g.denyRequest(rw, req, "No client IP found")
		return
	}

	g.logger.Debugf("Processing request from IP: %s to %s", clientIP, g.formatURL(req))

	if decision, determined := g.checkIPRules(clientIP); determined {
		if decision {
			if g.config.LogAllowedAccess {
				g.logger.Infof("Allowed request from IP: %s to %s by explicit IP rule", clientIP, g.formatURLForLevel(req, g.logger.level))
			}
			g.next.ServeHTTP(rw, req)
		} else {
			if g.config.LogDeniedAccess {
				g.logger.Warnf("Denied request from IP: %s to %s by explicit IP rule", clientIP, g.formatURLForLevel(req, g.logger.level))
			}
			g.denyRequest(rw, req, "IP address is denied")
		}
		return
	}

	if g.config.AllowPrivateIPAccess && g.isPrivateIP(clientIP) {
		if g.config.LogPrivateIPAccess {
			g.logger.Infof("Allowed private IP access for: %s to %s", clientIP, g.formatURLForLevel(req, g.logger.level))
		}
		g.next.ServeHTTP(rw, req)
		return
	}

	geoData, err := g.getGeoData(clientIP)
	if err != nil {
		if g.config.LogDeniedAccess {
			g.logger.Errorf("Error getting geo data for IP %s to %s: %v", clientIP, g.formatURLForLevel(req, g.logger.level), err)
		}
		if g.config.AllowRequestsWithoutGeoData {
			if g.config.LogAllowedAccess {
				g.logger.Infof("Allowed request from IP: %s to %s due to missing geo data (allowUnknownCountries enabled)", clientIP, g.formatURLForLevel(req, g.logger.level))
			}
			g.next.ServeHTTP(rw, req)
		} else {
			g.denyRequest(rw, req, "Could not determine location")
		}
		return
	}

	if g.checkGeoAccess(geoData) {
		if g.config.LogAllowedAccess {
			g.logger.Infof("Allowed request from IP: %s (%s, %s, %s) to %s by geo rule", clientIP, geoData.Country, geoData.Region, geoData.City, g.formatURLForLevel(req, g.logger.level))
		}
		g.next.ServeHTTP(rw, req)
	} else {
		if g.config.LogDeniedAccess {
			g.logger.Warnf("Denied request from IP: %s (%s, %s, %s) to %s by geo rule", clientIP, geoData.Country, geoData.Region, geoData.City, g.formatURLForLevel(req, g.logger.level))
		}
		g.denyRequest(rw, req, "Location is not allowed")
	}
}

// extractClientIP extracts the client IP from the request.
func (g *GeoAccessControl) extractClientIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// isPrivateIP checks if an IP is in a private range.
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

// checkIPRules checks if an IP is explicitly allowed or denied.
func (g *GeoAccessControl) checkIPRules(ipStr string) (decision bool, determined bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, false
	}
	for _, deniedRange := range g.deniedIPs {
		if deniedRange.Contains(ip) {
			return false, true // Explicitly denied
		}
	}
	for _, allowedRange := range g.allowedIPs {
		if allowedRange.Contains(ip) {
			return true, true // Explicitly allowed
		}
	}
	return false, false // No IP rule matched
}

// checkGeoAccess determines if access should be allowed based on geo data and hierarchical rules.
func (g *GeoAccessControl) checkGeoAccess(geoData *GeoData) bool {
	if geoData.Country == "" {
		return false
	}
	countryRule, countryExists := g.allowedRules[geoData.Country]
	if !countryExists {
		return false
	}
	if geoData.Region != "" {
		if regionRule, regionExists := countryRule.Regions[geoData.Region]; regionExists {
			if geoData.City != "" && len(regionRule.Cities) > 0 {
				return contains(regionRule.Cities, geoData.City)
			}
			return regionRule.Allowed
		}
	}
	if geoData.City != "" && len(countryRule.Cities) > 0 {
		return contains(countryRule.Cities, geoData.City)
	}
	return countryRule.Allowed
}

// getGeoData retrieves geolocation data for an IP.
func (g *GeoAccessControl) getGeoData(ip string) (*GeoData, error) {
	if cached, found := g.cache.Get(ip); found {
		g.logger.Debugf("Geo data for IP %s found in cache", ip)
		return cached.(*GeoData), nil
	}
	
	apiURL := strings.ReplaceAll(g.config.GeoAPIEndpoint, "{ip}", ip)
	if g.needsCityLevelData() {
		apiURL = strings.ReplaceAll(apiURL, "/country/", "/city/")
	}

	if g.config.GeoAPIResponseIsJSON {
		if strings.Contains(apiURL, "?") {
			apiURL += "&format=json"
		} else {
			apiURL += "?format=json"
		}
	}

	if g.config.LogGeoAPICalls {
		g.logger.Debugf("Making GeoAPI call to: %s for IP: %s", apiURL, ip)
	}

	resp, err := g.httpClient.Get(apiURL)
	if err != nil {
		g.logger.Errorf("Failed to make GeoAPI request to %s for IP %s: %v", apiURL, ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		g.logger.Errorf("Failed to read GeoAPI response body from %s for IP %s: %v", apiURL, ip, err)
		return nil, err
	}
	
	geoData := &GeoData{}
	if strings.HasPrefix(string(body), "{") {
		var apiResp APIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			g.logger.Errorf("Failed to unmarshal GeoAPI JSON response from %s for IP %s: %v", apiURL, ip, err)
			return nil, err
		}
		geoData.Country = apiResp.Country
		geoData.City = apiResp.City
		geoData.Region = apiResp.Region
	} else {
		// Handle plain text response
		parts := strings.Split(string(body), "|")
		if len(parts) > 0 {
			geoData.Country = parts[0]
		}
		if len(parts) > 1 {
			geoData.City = parts[1]
		}
		if len(parts) > 2 {
			geoData.Region = parts[2]
		}
	}

	g.cache.Set(ip, geoData)
	return geoData, nil
}

// denyRequest sends a denial response.
func (g *GeoAccessControl) denyRequest(rw http.ResponseWriter, req *http.Request, reason string) {
	if g.config.RedirectURL != "" {
		http.Redirect(rw, req, g.config.RedirectURL, http.StatusTemporaryRedirect)
		return
	}
	rw.WriteHeader(g.config.DeniedStatusCode)
	rw.Write([]byte(g.config.DeniedResponseMessage))
}

// needsCityLevelData checks if city-level data is required.
func (g *GeoAccessControl) needsCityLevelData() bool {
	for _, countryRule := range g.allowedRules {
		if len(countryRule.Cities) > 0 || len(countryRule.Regions) > 0 {
			return true
		}
	}
	return false
}

// parsePrivateIPRanges parses the private IP ranges.
func parsePrivateIPRanges() []*net.IPNet {
	privateCIDRs := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10",
	}
	cidrs, _ := parseIPRanges(privateCIDRs)
	return cidrs
}

// parseIPRanges parses a list of IP strings into IPNet ranges.
func parseIPRanges(ipStrings []string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet
	for _, ipStr := range ipStrings {
		ipStr = strings.TrimSpace(ipStr)
		if _, ipNet, err := net.ParseCIDR(ipStr); err == nil {
			ranges = append(ranges, ipNet)
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip != nil {
			if ip.To4() != nil {
				ranges = append(ranges, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			} else {
				ranges = append(ranges, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			continue
		}
		// Since parseIPRanges is a utility function, it doesn't have access to g.logger directly.
		// The error will be propagated and logged by the caller (New function).
		return nil, fmt.Errorf("invalid IP/CIDR address: %s", ipStr)
	}
	return ranges, nil
}

// LogLevel type for defining log levels.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

func parseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo // Default to info
	}
}

// PluginLogger is a custom logger for the plugin.
type PluginLogger struct {
	logger *log.Logger
	level  LogLevel
}

func (l *PluginLogger) Debugf(format string, v ...interface{}) {
	if l.level <= LevelDebug {
		l.logger.Printf("[DEBUG] "+format, v...)
	}
}

func (l *PluginLogger) Infof(format string, v ...interface{}) {
	if l.level <= LevelInfo {
		l.logger.Printf("[INFO] "+format, v...)
	}
}

func (l *PluginLogger) Warnf(format string, v ...interface{}) {
	if l.level <= LevelWarn {
		l.logger.Printf("[WARN] "+format, v...)
	}
}

func (l *PluginLogger) Errorf(format string, v ...interface{}) {
	if l.level <= LevelError {
		l.logger.Printf("[ERROR] "+format, v...)
	}
}

func (l *PluginLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Fatalf("[FATAL] "+format, v...)
}

func (l *PluginLogger) Printf(format string, v ...interface{}) {
	l.logger.Printf(format, v...)
}

// getScheme returns the scheme (http or https) for the request.
func getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if req.URL.Scheme != "" {
		return req.URL.Scheme
	}
	return "http"
}

// formatURL returns the full URL for debug logging.
func (g *GeoAccessControl) formatURL(req *http.Request) string {
	scheme := getScheme(req)
	return fmt.Sprintf("%s://%s%s", scheme, req.Host, req.URL.Path)
}

// formatURLForLevel returns URL format based on log level.
// Debug: full URL with path (e.g., https://example.com/api/users)
// Info and above: just the host (e.g., example.com)
func (g *GeoAccessControl) formatURLForLevel(req *http.Request, level LogLevel) string {
	if level <= LevelDebug {
		return g.formatURL(req)
	}
	return req.Host
}

// contains checks if a string is in a slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
