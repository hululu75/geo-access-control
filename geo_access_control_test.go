package geo_access_control

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()
	if config.GeoAPIEndpoint != "http://geoip-api:8080/country/{ip}" {
		t.Errorf("Expected default API, got %s", config.GeoAPIEndpoint)
	}
	if config.CacheSize != 100 {
		t.Errorf("Expected default cacheSize to be 100, got %d", config.CacheSize)
	}
	if config.DeniedStatusCode != http.StatusNotFound {
		t.Errorf("Expected default status code to be 404, got %d", config.DeniedStatusCode)
	}
	if config.DeniedResponseMessage != "Not Found" {
		t.Errorf("Expected default denied message to be 'Not Found', got %s", config.DeniedResponseMessage)
	}
}

func TestNew(t *testing.T) {
	// Simplified test cases for New function
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				GeoAPIEndpoint: "http://test/country/{ip}",
				AccessRules: map[string]interface{}{
					"US": true,
				},
			},
			wantErr: false,
		},
		{
			name: "missing API",
			config: &Config{
				AccessRules: map[string]interface{}{
					"US": true,
				},
			},
			wantErr: true,
		},
		{
			name: "no rules",
			config: &Config{
				GeoAPIEndpoint: "http://test/country/{ip}",
				AccessRules:    make(map[string]interface{}),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(), nil, tt.config, "test-plugin")
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccess(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint: "http://test-api",
		AccessRules: map[string]interface{}{
			// IP Rules
			"1.1.1.1":    false,
			"8.8.0.0/16": true,

			// Geo Rules
			"US": true,
			"KP": false,
			"GB": map[string]interface{}{
				"regions": map[string]interface{}{
					"SCO": false,
					"ENG": map[string]interface{}{
						"cities": []interface{}{"London"},
					},
				},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	geoPlugin := plugin.(*GeoAccessControl)

	tests := []struct {
		name          string
		clientIP      string
		geoData       *GeoData
		expectedAllow bool
	}{
		// IP Rule Precedence
		{"IP Deny Rule", "1.1.1.1", &GeoData{Country: "US"}, false},
		{"IP Allow Rule", "8.8.8.8", &GeoData{Country: "KP"}, true},
		// Geo Rule Logic
		{"Geo Country Allow", "1.2.3.4", &GeoData{Country: "US", Region: "CA"}, true},
		{"Geo Country Deny", "1.2.3.4", &GeoData{Country: "KP"}, false},
		{"Geo Region Deny Overrides Country", "1.2.3.4", &GeoData{Country: "GB", Region: "SCO"}, false},
		{"Geo City Allow (Most Specific)", "1.2.3.4", &GeoData{Country: "GB", Region: "ENG", City: "London"}, true},
		{"Geo City Not in List", "1.2.3.4", &GeoData{Country: "GB", Region: "ENG", City: "Manchester"}, false},
		{"Geo Country Not in List", "1.2.3.4", &GeoData{Country: "FR"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simplified check logic for test purposes
			decision := false
			if dec, det := geoPlugin.checkIPRules(tt.clientIP); det {
				decision = dec
			} else {
				decision, _ = geoPlugin.checkGeoAccess(tt.geoData)
			}

			if decision != tt.expectedAllow {
				t.Errorf("Expected access %v, got %v", tt.expectedAllow, decision)
			}
		})
	}
}

func TestCacheTTL(t *testing.T) {
	// TTL of 50ms for fast testing
	cache := NewLRUCache(10, 50*time.Millisecond)

	cache.Set("key1", "value1")

	// Should be found immediately
	val, found := cache.Get("key1")
	if !found {
		t.Fatal("Expected key1 to be found in cache")
	}
	if val.(string) != "value1" {
		t.Errorf("Expected value1, got %v", val)
	}

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Should be expired now
	_, found = cache.Get("key1")
	if found {
		t.Error("Expected key1 to be expired")
	}

	// Expired entry should be removed from cache
	if cache.Len() != 0 {
		t.Errorf("Expected cache length 0 after expiry, got %d", cache.Len())
	}
}

func TestCacheNoTTL(t *testing.T) {
	// TTL of 0 means no expiration
	cache := NewLRUCache(10, 0)

	cache.Set("key1", "value1")

	// Should still be found (no TTL)
	val, found := cache.Get("key1")
	if !found {
		t.Fatal("Expected key1 to be found in cache with no TTL")
	}
	if val.(string) != "value1" {
		t.Errorf("Expected value1, got %v", val)
	}
}

func TestCacheTTLRefreshOnUpdate(t *testing.T) {
	cache := NewLRUCache(10, 80*time.Millisecond)

	cache.Set("key1", "value1")

	// Wait 50ms then update the value
	time.Sleep(50 * time.Millisecond)
	cache.Set("key1", "value2")

	// Wait another 50ms (100ms total since first set, 50ms since update)
	time.Sleep(50 * time.Millisecond)

	// Should still be found because the update reset the TTL
	val, found := cache.Get("key1")
	if !found {
		t.Fatal("Expected key1 to be found after TTL refresh")
	}
	if val.(string) != "value2" {
		t.Errorf("Expected value2, got %v", val)
	}
}

func TestCreateConfigCacheTTL(t *testing.T) {
	config := CreateConfig()
	if config.CacheTTL != 3600 {
		t.Errorf("Expected default cacheTTL to be 3600, got %d", config.CacheTTL)
	}
}

func TestHostRulesParsing(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint: "http://test-api",
		AccessRules: map[string]interface{}{
			"1.2.3.4": true,
		},
		PerHostRules: map[string]HostRules{
			"example.com": {
				AllowedUserAgents:        []string{"Mozilla", "Chrome"},
				BlockedUserAgents:        []string{"curl", "wget"},
				AllowedUserAgentPatterns: []string{"^MyApp/.*"},
				BlockedUserAgentPatterns: []string{".*bot.*"},
			},
			"*.test.com": {
				BlockedUserAgentPatterns: []string{".*crawler.*"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	geoPlugin := plugin.(*GeoAccessControl)

	// Check exact match host rules
	if rules, found := geoPlugin.getHostRules("example.com"); !found {
		t.Error("Expected to find rules for example.com")
	} else {
		if len(rules.allowedUserAgents) != 2 {
			t.Errorf("Expected 2 allowed user agents, got %d", len(rules.allowedUserAgents))
		}
		if len(rules.blockedUserAgentRegexps) != 1 {
			t.Errorf("Expected 1 blocked user agent regex, got %d", len(rules.blockedUserAgentRegexps))
		}
	}

	// Check wildcard host rules
	if rules, found := geoPlugin.getHostRules("sub.test.com"); !found {
		t.Error("Expected to find rules for sub.test.com via wildcard")
	} else {
		if len(rules.blockedUserAgentRegexps) != 1 {
			t.Errorf("Expected 1 blocked user agent regex, got %d", len(rules.blockedUserAgentRegexps))
		}
	}

	// Check host with port
	if rules, found := geoPlugin.getHostRules("example.com:8080"); !found {
		t.Error("Expected to find rules for example.com:8080")
	} else {
		if len(rules.allowedUserAgents) != 2 {
			t.Errorf("Expected 2 allowed user agents, got %d", len(rules.allowedUserAgents))
		}
	}
}

func TestHostRulesMatching(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint: "http://test-api",
		AccessRules: map[string]interface{}{
			"1.2.3.4": true,
		},
		PerHostRules: map[string]HostRules{
			"example.com": {
				AllowedUserAgents: []string{"MyApp"},
				BlockedUserAgents: []string{"BadBot"},
			},
			"*.test.com": {
				BlockedUserAgentPatterns: []string{".*[Bb]ot.*"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	geoPlugin := plugin.(*GeoAccessControl)

	tests := []struct {
		name          string
		host          string
		userAgent     string
		expectedAllow bool
	}{
		{"Allowed string match", "example.com", "MyApp/1.0", true},
		{"Blocked string match", "example.com", "BadBot/1.0", false},
		{"Not in whitelist", "example.com", "OtherApp", false},
		{"Wildcard blocked by regex", "sub.test.com", "EvilBot", false},
		{"Wildcard allowed", "sub.test.com", "GoodBrowser", true},
		{"No host rules", "unknown.com", "AnyAgent", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, found := geoPlugin.getHostRules(tt.host)
			if !found {
				// No host rules means allow by default; verify the test expectation agrees.
				if !tt.expectedAllow {
					t.Errorf("Host %s has no rules (default allow), but test expects deny", tt.host)
				}
				return
			}
			allowed := geoPlugin.checkUserAgentByRules(tt.userAgent, rules, &http.Request{Host: tt.host})
			if allowed != tt.expectedAllow {
				t.Errorf("Expected %v for User-Agent %q on host %s, got %v", tt.expectedAllow, tt.userAgent, tt.host, allowed)
			}
		})
	}
}

func TestPrivateIPBypassesHostRules(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint:       "http://test-api",
		AllowPrivateIPAccess: true,
		BlockEmptyUserAgent:  true,
		AccessRules: map[string]interface{}{
			"US": true,
		},
		PerHostRules: map[string]HostRules{
			"example.com": {
				BlockedUserAgents: []string{"Everything"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	plugin.(*GeoAccessControl).next = nextHandler

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.RemoteAddr = "192.168.1.100:1234"
	req.Header.Set("User-Agent", "Everything")

	plugin.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Expected next handler to be called for private IP, even if User-Agent is blocked by host rules")
	}
}

func TestBlockEmptyUserAgentPerHost(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint:              "http://test-api",
		BlockEmptyUserAgent:         false,
		AllowPrivateIPAccess:        false,
		AllowRequestsWithoutGeoData: true,
		AccessRules: map[string]interface{}{
			"US": true,
		},
		PerHostRules: map[string]HostRules{
			"strict.example.com": {
				BlockEmptyUserAgent: func() *bool { b := true; return &b }(),
			},
			"lenient.example.com": {
				BlockEmptyUserAgent: func() *bool { b := false; return &b }(),
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	tests := []struct {
		name          string
		host          string
		userAgent     string
		expectedAllow bool
	}{
		{"Strict host blocks empty UA", "strict.example.com", "", false},
		{"Strict host allows with UA", "strict.example.com", "Mozilla", true},
		{"Lenient host allows empty UA", "lenient.example.com", "", true},
		{"Lenient host allows with UA", "lenient.example.com", "Mozilla", true},
		{"No host rule uses global", "unknown.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			plugin.(*GeoAccessControl).next = nextHandler

			rec := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "http://"+tt.host+"/test", nil)
			req.RemoteAddr = "8.8.8.8:1234"
			req.Header.Set("User-Agent", tt.userAgent)

			plugin.ServeHTTP(rec, req)

			if nextCalled != tt.expectedAllow {
				t.Errorf("Expected next called=%v for host %s with UA %q, got %v", tt.expectedAllow, tt.host, tt.userAgent, nextCalled)
			}
		})
	}
}

// TestEmptyUserAgentFallback covers the cases where a host has rules but no
// per-host blockEmptyUserAgent config, verifying that:
//   - the global BlockEmptyUserAgent flag is honoured as a fallback,
//   - an empty UA is denied with a clear reason when an allowlist is configured,
//   - an empty UA is allowed when neither the global flag nor an allowlist restricts it.
func TestEmptyUserAgentFallback(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name                string
		globalBlockEmpty    bool
		hostRules           HostRules
		userAgent           string
		expectedAllow bool
	}{
		{
			name:             "Global flag blocks empty UA when host has no per-host config",
			globalBlockEmpty: true,
			hostRules:        HostRules{BlockedUserAgents: []string{"BadBot"}}, // no BlockEmptyUserAgent
			userAgent:        "",
			expectedAllow:    false,
		},
		{
			name:             "Global flag allows empty UA when host has no per-host config",
			globalBlockEmpty: false,
			hostRules:        HostRules{BlockedUserAgents: []string{"BadBot"}}, // no BlockEmptyUserAgent
			userAgent:        "",
			expectedAllow:    true,
		},
		{
			name:             "Allowlist denies empty UA with clear reason (no per-host config, global=false)",
			globalBlockEmpty: false,
			hostRules:        HostRules{AllowedUserAgents: []string{"ValidClient"}},
			userAgent:        "",
			expectedAllow:    false,
		},
		{
			name:             "Allowlist still denies empty UA when global=true",
			globalBlockEmpty: true,
			hostRules:        HostRules{AllowedUserAgents: []string{"ValidClient"}},
			userAgent:        "",
			expectedAllow:    false,
		},
		{
			name:             "Per-host allow overrides global block",
			globalBlockEmpty: true,
			hostRules:        HostRules{BlockEmptyUserAgent: boolPtr(false)},
			userAgent:        "",
			expectedAllow:    true,
		},
		{
			name:             "Per-host block overrides global allow",
			globalBlockEmpty: false,
			hostRules:        HostRules{BlockEmptyUserAgent: boolPtr(true)},
			userAgent:        "",
			expectedAllow:    false,
		},
		{
			name:             "Non-empty UA passes allowlist normally",
			globalBlockEmpty: false,
			hostRules:        HostRules{AllowedUserAgents: []string{"ValidClient"}},
			userAgent:        "ValidClient/1.0",
			expectedAllow:    true,
		},
		{
			name:             "Non-empty UA rejected by allowlist normally",
			globalBlockEmpty: false,
			hostRules:        HostRules{AllowedUserAgents: []string{"ValidClient"}},
			userAgent:        "OtherApp/1.0",
			expectedAllow:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				GeoAPIEndpoint:              "http://test-api",
				BlockEmptyUserAgent:         tt.globalBlockEmpty,
				AllowPrivateIPAccess:        false,
				AllowRequestsWithoutGeoData: true,
				AccessRules: map[string]interface{}{
					"US": true,
				},
				PerHostRules: map[string]HostRules{
					"api.example.com": tt.hostRules,
				},
			}

			plugin, err := New(context.Background(), nil, config, "test-plugin")
			if err != nil {
				t.Fatalf("Failed to create plugin: %v", err)
			}

			nextCalled := false
			plugin.(*GeoAccessControl).next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "http://api.example.com/test", nil)
			req.RemoteAddr = "8.8.8.8:1234"
			req.Header.Set("User-Agent", tt.userAgent)

			plugin.ServeHTTP(rec, req)

			if nextCalled != tt.expectedAllow {
				t.Errorf("Expected allow=%v for UA %q (global blockEmpty=%v), got allow=%v",
					tt.expectedAllow, tt.userAgent, tt.globalBlockEmpty, nextCalled)
			}
		})
	}
}

func TestWildcardRulesSortedBySpecificity(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint: "http://test-api",
		AccessRules: map[string]interface{}{
			"US": true,
		},
		PerHostRules: map[string]HostRules{
			// Order in map is random; plugin must sort by specificity.
			"*.com": {
				BlockedUserAgents: []string{"BroadBlock"},
			},
			"*.example.com": {
				AllowedUserAgents: []string{"SpecificAllow"},
			},
			"*.sub.example.com": {
				AllowedUserAgents: []string{"MostSpecific"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	geoPlugin := plugin.(*GeoAccessControl)

	// "app.sub.example.com" should match "*.sub.example.com" (most specific), not "*.example.com"
	rules, found := geoPlugin.getHostRules("app.sub.example.com")
	if !found {
		t.Fatal("Expected to find wildcard rules for app.sub.example.com")
	}
	if len(rules.allowedUserAgents) != 1 || rules.allowedUserAgents[0] != "MostSpecific" {
		t.Errorf("Expected MostSpecific rule, got %v", rules.allowedUserAgents)
	}

	// "foo.example.com" should match "*.example.com", not "*.com"
	rules, found = geoPlugin.getHostRules("foo.example.com")
	if !found {
		t.Fatal("Expected to find wildcard rules for foo.example.com")
	}
	if len(rules.allowedUserAgents) != 1 || rules.allowedUserAgents[0] != "SpecificAllow" {
		t.Errorf("Expected SpecificAllow rule, got %v", rules.allowedUserAgents)
	}

	// "random.com" should match "*.com"
	rules, found = geoPlugin.getHostRules("random.com")
	if !found {
		t.Fatal("Expected to find wildcard rules for random.com")
	}
	if len(rules.blockedUserAgents) != 1 || rules.blockedUserAgents[0] != "BroadBlock" {
		t.Errorf("Expected BroadBlock rule, got blocked=%v allowed=%v", rules.blockedUserAgents, rules.allowedUserAgents)
	}
}

func TestExtractClientIPPrefersXRealIP(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint: "http://test-api",
		AccessRules: map[string]interface{}{
			"US": true,
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	geoPlugin := plugin.(*GeoAccessControl)

	tests := []struct {
		name       string
		xRealIP    string
		xff        string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "X-Real-IP takes precedence over XFF",
			xRealIP:    "10.0.0.1",
			xff:        "192.168.1.1, 172.16.0.1",
			remoteAddr: "127.0.0.1:1234",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "Falls back to XFF when X-Real-IP absent",
			xRealIP:    "",
			xff:        "203.0.113.5, 172.16.0.1",
			remoteAddr: "127.0.0.1:1234",
			expectedIP: "203.0.113.5",
		},
		{
			name:       "Falls back to RemoteAddr when no headers",
			xRealIP:    "",
			xff:        "",
			remoteAddr: "198.51.100.1:1234",
			expectedIP: "198.51.100.1",
		},
		{
			name:       "Ignores invalid X-Real-IP, uses XFF",
			xRealIP:    "not-an-ip",
			xff:        "203.0.113.5",
			remoteAddr: "127.0.0.1:1234",
			expectedIP: "203.0.113.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			ip := geoPlugin.extractClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestExecutionOrder(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint:              "http://test-api",
		AllowPrivateIPAccess:        true,
		BlockEmptyUserAgent:         true,
		AllowRequestsWithoutGeoData: true,
		AccessRules: map[string]interface{}{
			"US":         true,
			"10.0.0.0/8": true,
		},
		PerHostRules: map[string]HostRules{
			"*.example.com": {
				BlockedUserAgents: []string{"Blocked"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	tests := []struct {
		name          string
		ip            string
		userAgent     string
		host          string
		expectedAllow bool
		reason        string
	}{
		{"Private IP bypasses all", "192.168.1.1", "Blocked", "api.example.com", true, "private IP"},
		{"IP whitelist bypasses host rules", "10.0.0.1", "Blocked", "api.example.com", true, "IP whitelist"},
		{"Host rules block", "8.8.8.8", "Blocked", "api.example.com", false, "host rule"},
		{"Host rules allow", "8.8.8.8", "Allowed", "api.example.com", true, "host rule + geo allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			plugin.(*GeoAccessControl).next = nextHandler

			rec := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "http://"+tt.host+"/test", nil)
			req.RemoteAddr = tt.ip + ":1234"
			req.Header.Set("User-Agent", tt.userAgent)

			plugin.ServeHTTP(rec, req)

			if nextCalled != tt.expectedAllow {
				t.Errorf("%s: Expected allow=%v, got %v", tt.name, tt.expectedAllow, nextCalled)
			}
		})
	}
}

func TestHostRulesContinueToGeoCheck(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint:              "http://test-api",
		AllowPrivateIPAccess:        false,
		BlockEmptyUserAgent:         true,
		AllowRequestsWithoutGeoData: false,
		AccessRules: map[string]interface{}{
			"US": true,
		},
		PerHostRules: map[string]HostRules{
			"api.example.com": {
				AllowedUserAgents: []string{"ValidClient"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	plugin.(*GeoAccessControl).next = nextHandler

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://api.example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("User-Agent", "ValidClient")

	plugin.ServeHTTP(rec, req)

	// Even though Host rules pass, request should be denied because Geo API fails
	// and AllowRequestsWithoutGeoData is false
	if nextCalled {
		t.Error("Expected request to be denied when Geo API fails and AllowRequestsWithoutGeoData is false")
	}

	// Verify that response is denied (404 by default)
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestHostRulesDeniedSendsResponse(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint:        "http://test-api",
		DeniedStatusCode:      http.StatusForbidden, // 403
		DeniedResponseMessage: "Access Denied",
		AccessRules: map[string]interface{}{
			"US": true,
		},
		PerHostRules: map[string]HostRules{
			"api.example.com": {
				AllowedUserAgents: []string{"ValidClient"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	plugin.(*GeoAccessControl).next = nextHandler

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://api.example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("User-Agent", "InvalidClient")

	plugin.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Expected request to be denied when User-Agent is not in whitelist")
	}

	// Verify that response is sent with configured status code and message
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rec.Code)
	}
	if rec.Body.String() != "Access Denied" {
		t.Errorf("Expected body 'Access Denied', got '%s'", rec.Body.String())
	}
}

func TestHostRulesDeniedClosesConnection(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint:              "http://test-api",
		CloseConnectionOnHostReject: true,
		AccessRules: map[string]interface{}{
			"US": true,
		},
		PerHostRules: map[string]HostRules{
			"api.example.com": {
				AllowedUserAgents: []string{"ValidClient"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	plugin.(*GeoAccessControl).next = nextHandler

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://api.example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("User-Agent", "InvalidClient")

	// httptest.ResponseRecorder does not implement http.Hijacker, so the plugin
	// falls through to panic(http.ErrAbortHandler) — the HTTP/2 abort path.
	// Capture the panic so the test can assert on it.
	var aborted bool
	func() {
		defer func() {
			if r := recover(); r == http.ErrAbortHandler {
				aborted = true
			} else if r != nil {
				t.Errorf("Unexpected panic: %v", r)
			}
		}()
		plugin.ServeHTTP(rec, req)
	}()

	if nextCalled {
		t.Error("Expected next handler not to be called when connection is dropped")
	}
	if !aborted {
		t.Error("Expected http.ErrAbortHandler panic when Hijack is not supported")
	}
}

// hijackableResponseWriter wraps httptest.ResponseRecorder and implements
// http.Hijacker so we can test the HTTP/1.x hijack path.
type hijackableResponseWriter struct {
	*httptest.ResponseRecorder
	conn     net.Conn
	hijacked bool
}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	rw := bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn))
	return h.conn, rw, nil
}

func TestHostRulesDeniedClosesConnectionHTTP1Hijack(t *testing.T) {
	config := &Config{
		GeoAPIEndpoint:              "http://test-api",
		CloseConnectionOnHostReject: true,
		AccessRules: map[string]interface{}{
			"US": true,
		},
		PerHostRules: map[string]HostRules{
			"api.example.com": {
				AllowedUserAgents: []string{"ValidClient"},
			},
		},
	}

	plugin, err := New(context.Background(), nil, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	nextCalled := false
	plugin.(*GeoAccessControl).next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	// Create a pipe to simulate a TCP connection; the plugin will close the
	// server side, and we verify by reading from the client side.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	hrw := &hijackableResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverConn,
	}

	req, _ := http.NewRequest("GET", "http://api.example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Header.Set("User-Agent", "InvalidClient")

	// Should NOT panic — hijack succeeds for HTTP/1.x, so connection is
	// closed directly instead of using panic(http.ErrAbortHandler).
	plugin.ServeHTTP(hrw, req)

	if nextCalled {
		t.Error("Expected next handler not to be called")
	}
	if !hrw.hijacked {
		t.Error("Expected Hijack() to be called for HTTP/1.x")
	}

	// Verify the server side of the connection was closed: a read on the
	// client side should return an error (EOF or closed pipe).
	buf := make([]byte, 1)
	_, readErr := clientConn.Read(buf)
	if readErr == nil {
		t.Error("Expected read error on client conn after server conn was closed")
	}
}
