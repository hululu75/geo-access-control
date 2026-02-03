package geo_access_control

import (
	"context"
	"net/http"
	"testing"
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

// Other tests like TestParseIPRanges can remain as they are independent helpers.
