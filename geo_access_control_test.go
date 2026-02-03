package geo_access_control

import (
	"context"
	"net/http"
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
