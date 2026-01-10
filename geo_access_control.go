package geo_access_control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	API                   string                 `json:"api,omitempty"`
	APITimeoutMs          int                    `json:"apiTimeoutMs,omitempty"`
	UseJSONFormat         bool                   `json:"useJSONFormat,omitempty"`
	AllowedLists          map[string]interface{} `json:"allowedLists,omitempty"`
	AllowLocalRequests    bool                   `json:"allowLocalRequests,omitempty"`
	AllowUnknownCountries bool                   `json:"allowUnknownCountries,omitempty"`
	CacheSize             int                    `json:"cacheSize,omitempty"`
	DeniedHTTPStatusCode  int                    `json:"deniedHTTPStatusCode,omitempty"`
	DeniedMessage         string                 `json:"deniedMessage,omitempty"`
	RedirectURL           string                 `json:"redirectURL,omitempty"`
	AddCountryHeader      bool                   `json:"addCountryHeader,omitempty"`
	AddRegionHeader       bool                   `json:"addRegionHeader,omitempty"`
	AddCityHeader         bool                   `json:"addCityHeader,omitempty"`
	ExcludedPathPatterns  []string               `json:"excludedPathPatterns,omitempty"`
	LogAllowedRequests    bool                   `json:"logAllowedRequests,omitempty"`
	LogBlockedRequests    bool                   `json:"logBlockedRequests,omitempty"`
	LogAPIRequests        bool                   `json:"logAPIRequests,omitempty"`
	LogLocalRequests      bool                   `json:"logLocalRequests,omitempty"`
	SilentStartUp         bool                   `json:"silentStartUp,omitempty"`
}

// CreateConfig creates and initializes the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		API:                   "http://geoip-api:8080/country/{ip}",
		APITimeoutMs:          750,
		UseJSONFormat:         true,
		AllowedLists:          make(map[string]interface{}),
		AllowLocalRequests:    true,
		AllowUnknownCountries: false,
		CacheSize:             100,
		DeniedHTTPStatusCode:  http.StatusForbidden,
		DeniedMessage:         "Access Denied",
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
	if config.API == "" {
		return nil, fmt.Errorf("API endpoint is required")
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

	plugin.allowedRules = make(map[string]CountryRules)
	var allowedIPStrings, deniedIPStrings []string

	for key, configValue := range config.AllowedLists {
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
		return nil, fmt.Errorf("at least one rule must be specified in 'allowedLists'")
	}

	var err error
	plugin.privateIPRanges = parsePrivateIPRanges()

	if len(allowedIPStrings) > 0 {
		plugin.allowedIPs, err = parseIPRanges(allowedIPStrings)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowed IPs: %w", err)
		}
	}
	if len(deniedIPStrings) > 0 {
		plugin.deniedIPs, err = parseIPRanges(deniedIPStrings)
		if err != nil {
			return nil, fmt.Errorf("failed to parse denied IPs: %w", err)
		}
	}

	return plugin, nil
}

// ServeHTTP implements the http.Handler interface.
func (g *GeoAccessControl) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := g.extractClientIP(req)
	if clientIP == "" {
		g.denyRequest(rw, req, "No client IP found")
		return
	}

	if decision, determined := g.checkIPRules(clientIP); determined {
		if decision {
			g.next.ServeHTTP(rw, req)
		} else {
			g.denyRequest(rw, req, "IP address is denied")
		}
		return
	}

	if g.config.AllowLocalRequests && g.isPrivateIP(clientIP) {
		g.next.ServeHTTP(rw, req)
		return
	}

	geoData, err := g.getGeoData(clientIP)
	if err != nil {
		if g.config.AllowUnknownCountries {
			g.next.ServeHTTP(rw, req)
		} else {
			g.denyRequest(rw, req, "Could not determine location")
		}
		return
	}
	
	if g.config.AddCountryHeader && geoData.Country != "" {
		req.Header.Set("X-Country-Code", geoData.Country)
	}
	if g.config.AddRegionHeader && geoData.Region != "" {
		req.Header.Set("X-Region-Code", geoData.Region)
	}
	if g.config.AddCityHeader && geoData.City != "" {
		req.Header.Set("X-City-Name", geoData.City)
	}

	if g.checkGeoAccess(geoData) {
		g.next.ServeHTTP(rw, req)
	} else {
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
		return cached.(*GeoData), nil
	}
	
	apiURL := strings.ReplaceAll(g.config.API, "{ip}", ip)
	if g.needsCityLevelData() {
		apiURL = strings.ReplaceAll(apiURL, "/country/", "/city/")
	}

	if g.config.UseJSONFormat {
		if strings.Contains(apiURL, "?") {
			apiURL += "&format=json"
		} else {
			apiURL += "?format=json"
		}
	}

	resp, err := g.httpClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	geoData := &GeoData{}
	if strings.HasPrefix(string(body), "{") {
		var apiResp APIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			return nil, err
		}
		geoData.Country = apiResp.Country
		geoData.City = apiResp.City
		geoData.Region = apiResp.Region
	} else {
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
	rw.WriteHeader(g.config.DeniedHTTPStatusCode)
	rw.Write([]byte(g.config.DeniedMessage))
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
		return nil, fmt.Errorf("invalid IP/CIDR address: %s", ipStr)
	}
	return ranges, nil
}

// contains checks if a string is in a slice of strings.
func contains(list []string, item string) bool {
	for _, v := range list {
		if strings.EqualFold(v, item) {
			return true
		}
	}
	return false
}