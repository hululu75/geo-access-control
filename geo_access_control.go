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
	Unknown bool                   `json:"unknown,omitempty"` // Allow requests without region info
	Regions map[string]RegionRules `json:"regions,omitempty"`
	Cities  []string               `json:"cities,omitempty"`
}

// Config holds the plugin configuration.
type Config struct {
	GeoAPIEndpoint        string                 `json:"geoAPIEndpoint,omitempty"`
	GeoAPITimeout         int                    `json:"geoAPITimeout,omitempty"`
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
	LogWhiteListAccess    bool                   `json:"logWhiteListAccess,omitempty"`
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
	ipRules             []ipRule
	allowedIPs          []*net.IPNet
	deniedIPs           []*net.IPNet
	httpClient          *http.Client
	logger              *PluginLogger
	logFile             *os.File
}

// ipRule associates an IP range with an allow/deny decision.
type ipRule struct {
	ipNet   *net.IPNet
	allowed bool
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
	var logFile *os.File
	if config.LogFilePath != "" {
		var err error
		logFile, err = os.OpenFile(config.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		logWriter = io.MultiWriter(os.Stderr, logFile)
	}

	pluginLogger := &PluginLogger{
		logger: log.New(logWriter, "", log.Ldate|log.Ltime),
		level:  parseLogLevel(config.LogLevel),
		name:   name,
	}

	if config.GeoAPIEndpoint == "" {
		pluginLogger.Errorf("API endpoint is required")
		if logFile != nil {
			logFile.Close()
		}
		return nil, fmt.Errorf("API endpoint is required")
	}

	// Validate and apply safe defaults for critical config values
	if config.CacheSize <= 0 {
		pluginLogger.Warnf("cacheSize %d is invalid, defaulting to 100", config.CacheSize)
		config.CacheSize = 100
	}
	if config.GeoAPITimeout <= 0 {
		pluginLogger.Warnf("geoAPITimeout %d is invalid, defaulting to 750ms", config.GeoAPITimeout)
		config.GeoAPITimeout = 750
	}
	if config.DeniedStatusCode < 100 || config.DeniedStatusCode > 599 {
		pluginLogger.Warnf("deniedStatusCode %d is invalid, defaulting to 404", config.DeniedStatusCode)
		config.DeniedStatusCode = http.StatusNotFound
	}

	plugin := &GeoAccessControl{
		next:   next,
		name:   name,
		config: config,
		cache:  NewLRUCache(config.CacheSize),
		httpClient: &http.Client{
			Timeout: time.Duration(config.GeoAPITimeout) * time.Millisecond,
		},
		logger:  pluginLogger,
		logFile: logFile,
	}

	// closeOnError cleans up resources if New() fails after this point
	closeOnError := func() {
		if logFile != nil {
			logFile.Close()
		}
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
			} else if strVal, ok := configValue.(string); ok {
				// Handle string "true" or "false" from TOML
				countryRule.Allowed = (strVal == "true" || strVal == "True" || strVal == "TRUE")
			} else if v, ok := configValue.(map[string]interface{}); ok {
				// Handle allowed field at country level
				if allowedVal, ok := v["allowed"].(bool); ok {
					countryRule.Allowed = allowedVal
				} else if allowedStr, ok := v["allowed"].(string); ok {
					countryRule.Allowed = (allowedStr == "true" || allowedStr == "True" || allowedStr == "TRUE")
				}
				// Handle unknown field (for requests without region info)
				if unknownVal, ok := v["unknown"].(bool); ok {
					countryRule.Unknown = unknownVal
				} else if unknownStr, ok := v["unknown"].(string); ok {
					countryRule.Unknown = (unknownStr == "true" || unknownStr == "True" || unknownStr == "TRUE")
				}
				// Handle regions
				if regionsConfig, ok := v["regions"]; ok {
					countryRule.Regions = make(map[string]RegionRules)
					if rCfg, ok := regionsConfig.(map[string]interface{}); ok {
						for regionCode, regionRulesConfig := range rCfg {
							regionRule := RegionRules{}
							if rrCfg, ok := regionRulesConfig.(bool); ok {
								regionRule.Allowed = rrCfg
							} else if strVal, ok := regionRulesConfig.(string); ok {
								// Handle string "true" or "false" from TOML
								regionRule.Allowed = (strVal == "true" || strVal == "True" || strVal == "TRUE")
							} else if rrCfg, ok := regionRulesConfig.(map[string]interface{}); ok {
								// Handle allowed field
								if allowedVal, ok := rrCfg["allowed"].(bool); ok {
									regionRule.Allowed = allowedVal
								} else if allowedStr, ok := rrCfg["allowed"].(string); ok {
									regionRule.Allowed = (allowedStr == "true" || allowedStr == "True" || allowedStr == "TRUE")
								}
								// Handle cities field
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
			var allowed bool
			var parsed bool

			// Try bool type first
			if boolVal, ok := configValue.(bool); ok {
				allowed = boolVal
				parsed = true
			} else if strVal, ok := configValue.(string); ok {
				// Handle string "true" or "false" from TOML (workaround for TOML parser issue)
				allowed = (strVal == "true" || strVal == "True" || strVal == "TRUE")
				parsed = true
			}

			if parsed {
				if allowed {
					allowedIPStrings = append(allowedIPStrings, key)
				} else {
					deniedIPStrings = append(deniedIPStrings, key)
				}
			}
		}
	}

	// Compile excluded path regexps
	for _, pattern := range config.ExcludedPaths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			plugin.logger.Errorf("failed to compile excluded path pattern %q: %v", pattern, err)
			closeOnError()
			return nil, fmt.Errorf("failed to compile excluded path pattern %q: %w", pattern, err)
		}
		plugin.excludedPathRegexps = append(plugin.excludedPathRegexps, re)
	}

	if len(plugin.allowedRules) == 0 && len(allowedIPStrings) == 0 && len(deniedIPStrings) == 0 {
		plugin.logger.Errorf("at least one rule must be specified in 'accessRules'")
		closeOnError()
		return nil, fmt.Errorf("at least one rule must be specified in 'accessRules'")
	}

	var err error
	plugin.privateIPRanges = parsePrivateIPRanges()

	if len(allowedIPStrings) > 0 {
		plugin.allowedIPs, err = parseIPRanges(allowedIPStrings)
		if err != nil {
			plugin.logger.Errorf("failed to parse allowed IPs: %v", err)
			closeOnError()
			return nil, fmt.Errorf("failed to parse allowed IPs: %w", err)
		}
	}
	if len(deniedIPStrings) > 0 {
		plugin.deniedIPs, err = parseIPRanges(deniedIPStrings)
		if err != nil {
			plugin.logger.Errorf("failed to parse denied IPs: %v", err)
			closeOnError()
			return nil, fmt.Errorf("failed to parse denied IPs: %w", err)
		}
	}

	// Build combined IP rules list for most-specific-wins matching
	for _, ipNet := range plugin.allowedIPs {
		plugin.ipRules = append(plugin.ipRules, ipRule{ipNet: ipNet, allowed: true})
	}
	for _, ipNet := range plugin.deniedIPs {
		plugin.ipRules = append(plugin.ipRules, ipRule{ipNet: ipNet, allowed: false})
	}

	return plugin, nil
}

// Close releases resources held by the plugin (log file, HTTP connections).
// Should be called when the plugin is being stopped or replaced.
func (g *GeoAccessControl) Close() error {
	if g.httpClient != nil {
		g.httpClient.CloseIdleConnections()
	}
	if g.logFile != nil {
		return g.logFile.Close()
	}
	return nil
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

	// Check excluded paths
	for _, re := range g.excludedPathRegexps {
		if re.MatchString(req.URL.Path) {
			g.logger.Debugf("Path %s matched excluded pattern %s, bypassing geo access control", req.URL.Path, re.String())
			g.next.ServeHTTP(rw, req)
			return
		}
	}

	if decision, determined := g.checkIPRules(clientIP); determined {
		if decision {
			if g.config.LogWhiteListAccess {
				g.logger.Infof("Allowed request from IP: %s to %s (IP whitelist)", clientIP, g.formatURLForLevel(req, g.logger.level))
			}
			g.next.ServeHTTP(rw, req)
		} else {
			if g.config.LogDeniedAccess {
				g.logger.Warnf("Denied request from IP: %s to %s (IP blacklist)", clientIP, g.formatURLForLevel(req, g.logger.level))
			}
			g.denyRequest(rw, req, "IP address is denied")
		}
		return
	}

	if g.config.AllowPrivateIPAccess && g.isPrivateIP(clientIP) {
		if g.config.LogPrivateIPAccess {
			g.logger.Infof("Allowed request from IP: %s to %s (private IP)", clientIP, g.formatURLForLevel(req, g.logger.level))
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

	allowed, matchedRule := g.checkGeoAccess(geoData)
	if allowed {
		if g.config.LogAllowedAccess {
			g.logger.Infof("Allowed request from IP: %s (%s, %s, %s) to %s (matched: %s)", clientIP, geoData.Country, geoData.Region, geoData.City, g.formatURLForLevel(req, g.logger.level), matchedRule)
		}
		g.next.ServeHTTP(rw, req)
	} else {
		if g.config.LogDeniedAccess {
			g.logger.Warnf("Denied request from IP: %s (%s, %s, %s) to %s (blocked: %s)", clientIP, geoData.Country, geoData.Region, geoData.City, g.formatURLForLevel(req, g.logger.level), matchedRule)
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
// Uses most-specific-wins logic: the rule with the longest prefix match takes precedence.
func (g *GeoAccessControl) checkIPRules(ipStr string) (decision bool, determined bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, false
	}

	bestPrefixLen := -1
	bestDecision := false
	matched := false

	for _, rule := range g.ipRules {
		if rule.ipNet.Contains(ip) {
			prefixLen, _ := rule.ipNet.Mask.Size()
			if prefixLen > bestPrefixLen {
				bestPrefixLen = prefixLen
				bestDecision = rule.allowed
				matched = true
			}
		}
	}

	return bestDecision, matched
}

// checkGeoAccess determines if access should be allowed based on geo data and hierarchical rules.
// Returns (allowed bool, matchedRule string)
func (g *GeoAccessControl) checkGeoAccess(geoData *GeoData) (bool, string) {
	if geoData == nil {
		return false, "no geo data"
	}
	if geoData.Country == "" {
		return false, "no country data"
	}
	countryRule, countryExists := g.allowedRules[geoData.Country]
	if !countryExists {
		return false, "country not in rules"
	}

	// Check if regions are defined
	hasRegionRules := len(countryRule.Regions) > 0

	// If region info exists, check region rules
	if geoData.Region != "" {
		if regionRule, regionExists := countryRule.Regions[geoData.Region]; regionExists {
			// Region matches - check city rules if any
			if geoData.City != "" && len(regionRule.Cities) > 0 {
				if contains(regionRule.Cities, geoData.City) {
					return true, fmt.Sprintf("city %s in region %s, %s", geoData.City, geoData.Region, geoData.Country)
				}
				return false, fmt.Sprintf("city %s not in allowed list (region %s, %s)", geoData.City, geoData.Region, geoData.Country)
			}
			return regionRule.Allowed, fmt.Sprintf("region %s, %s", geoData.Region, geoData.Country)
		}
		// Has region info but doesn't match any defined regions
		if hasRegionRules {
			return false, fmt.Sprintf("region %s not in allowed regions (%s)", geoData.Region, geoData.Country)
		}
	} else if hasRegionRules {
		// No region info - check if "unknown" region rule exists
		if unknownRule, exists := countryRule.Regions["unknown"]; exists {
			return unknownRule.Allowed, fmt.Sprintf("region unknown (%s)", geoData.Country)
		}
		// If no "unknown" rule in regions, use country-level 'unknown' field
		return countryRule.Unknown, fmt.Sprintf("region unknown (country-level, %s)", geoData.Country)
	}

	// Fallback to country-level rules
	if geoData.City != "" && len(countryRule.Cities) > 0 {
		if contains(countryRule.Cities, geoData.City) {
			// Include region info only if region rules are defined in config
			if hasRegionRules && geoData.Region != "" {
				return true, fmt.Sprintf("city %s in region %s, %s", geoData.City, geoData.Region, geoData.Country)
			}
			return true, fmt.Sprintf("city %s, %s", geoData.City, geoData.Country)
		}
		if hasRegionRules && geoData.Region != "" {
			return false, fmt.Sprintf("city not in allowed list (region %s, %s)", geoData.Region, geoData.Country)
		}
		return false, fmt.Sprintf("city not in allowed list (%s)", geoData.Country)
	}
	return countryRule.Allowed, fmt.Sprintf("country %s", geoData.Country)
}

// getGeoData retrieves geolocation data for an IP.
func (g *GeoAccessControl) getGeoData(ip string) (*GeoData, error) {
	if cached, found := g.cache.Get(ip); found {
		if geoData, ok := cached.(*GeoData); ok {
			g.logger.Debugf("Geo data for IP %s found in cache", ip)
			return geoData, nil
		}
		g.logger.Warnf("Cache contained invalid type for IP %s, refetching", ip)
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

	// Limit response body to 1MB to prevent memory abuse
	const maxBodySize = 1 << 20

	if resp.StatusCode != http.StatusOK {
		// Drain body so the underlying TCP connection can be reused
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize))
		g.logger.Errorf("GeoAPI returned non-200 status %d from %s for IP %s", resp.StatusCode, apiURL, ip)
		return nil, fmt.Errorf("GeoAPI returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
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
	name   string
}

func (l *PluginLogger) Debugf(format string, v ...interface{}) {
	if l.level <= LevelDebug {
		l.logger.Printf("[%s] [DEBUG] "+format, append([]interface{}{l.name}, v...)...)
	}
}

func (l *PluginLogger) Infof(format string, v ...interface{}) {
	if l.level <= LevelInfo {
		l.logger.Printf("[%s] [INFO] "+format, append([]interface{}{l.name}, v...)...)
	}
}

func (l *PluginLogger) Warnf(format string, v ...interface{}) {
	if l.level <= LevelWarn {
		l.logger.Printf("[%s] [WARN] "+format, append([]interface{}{l.name}, v...)...)
	}
}

func (l *PluginLogger) Errorf(format string, v ...interface{}) {
	if l.level <= LevelError {
		l.logger.Printf("[%s] [ERROR] "+format, append([]interface{}{l.name}, v...)...)
	}
}

func (l *PluginLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Fatalf("[%s] [FATAL] "+format, append([]interface{}{l.name}, v...)...)
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
