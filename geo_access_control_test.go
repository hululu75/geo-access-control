package geo_access_control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config.API != "http://geoip-api:8080/country/{ip}" {
		t.Errorf("Expected default API, got %s", config.API)
	}


	if config.CacheSize != 100 {
		t.Errorf("Expected default cacheSize to be 100, got %d", config.CacheSize)
	}

	if config.DeniedHTTPStatusCode != http.StatusForbidden {
		t.Errorf("Expected default status code to be 403, got %d", config.DeniedHTTPStatusCode)
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid country config",
			config: &Config{
				API:              "http://test/country/{ip}",
				AllowedCountries: []string{"US", "CA"},
			},
			wantErr: false,
		},
		{
			name: "missing API",
			config: &Config{
				AllowedCountries: []string{"US"},
			},
			wantErr: true,
			errMsg:  "API endpoint is required",
		},
		{
			name: "no filter lists",
			config: &Config{
				API: "http://test/country/{ip}",
			},
			wantErr: true,
			errMsg:  "at least one of",
		},
		{
			name: "region filter",
			config: &Config{
				API:            "http://test/region/{ip}",
				AllowedRegions: []string{"US-CA"},
			},
			wantErr: false,
		},
		{
			name: "city filter",
			config: &Config{
				API:           "http://test/city/{ip}",
				AllowedCities: []string{"US|New York"},
			},
			wantErr: false,
		},
		{
			name: "combined filters",
			config: &Config{
				API:              "http://test/country/{ip}",
				AllowedCountries: []string{"US"},
				AllowedRegions:   []string{"CN-44"},
				AllowedCities:    []string{"GB|London"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			_, err := New(ctx, next, tt.config, "test-plugin")

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	config := &Config{
		API:              "http://test/country/{ip}",
		FilterMode:       "country",
		AllowedCountries: []string{"US"},
	}

	plugin, _ := New(context.Background(), nil, config, "test")
	geoPlugin := plugin.(*GeoAccessControl)

	tests := []struct {
		name     string
		headers  map[string]string
		remoteAddr string
		expected string
	}{
		{
			name: "X-Forwarded-For single IP",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4",
			},
			expected: "1.2.3.4",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4, 5.6.7.8, 9.10.11.12",
			},
			expected: "1.2.3.4",
		},
		{
			name: "X-Real-IP",
			headers: map[string]string{
				"X-Real-IP": "1.2.3.4",
			},
			expected: "1.2.3.4",
		},
		{
			name:       "RemoteAddr",
			remoteAddr: "1.2.3.4:5678",
			expected:   "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

			ip := geoPlugin.extractClientIP(req)
			if ip != tt.expected {
				t.Errorf("Expected IP %s, got %s", tt.expected, ip)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	config := &Config{
		API:              "http://test/country/{ip}",
		FilterMode:       "country",
		AllowedCountries: []string{"US"},
	}

	plugin, _ := New(context.Background(), nil, config, "test")
	geoPlugin := plugin.(*GeoAccessControl)

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := geoPlugin.isPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("For IP %s, expected %v, got %v", tt.ip, tt.expected, result)
			}
		})
	}
}

func TestCheckAccess(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		geoData       *GeoData
		expectedAllow bool
	}{
		{
			name: "country whitelist - allow",
			config: &Config{
				AllowedCountries: []string{"US", "CA"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "US"},
			expectedAllow: true,
		},
		{
			name: "country whitelist - deny",
			config: &Config{
				AllowedCountries: []string{"US", "CA"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "CN"},
			expectedAllow: false,
		},
		{
			name: "country blacklist - allow",
			config: &Config{
				AllowedCountries: []string{"CN", "RU"},
				BlackListMode:    true,
			},
			geoData:       &GeoData{Country: "US"},
			expectedAllow: true,
		},
		{
			name: "country blacklist - deny",
			config: &Config{
				AllowedCountries: []string{"CN", "RU"},
				BlackListMode:    true,
			},
			geoData:       &GeoData{Country: "CN"},
			expectedAllow: false,
		},
		{
			name: "region whitelist - allow",
			config: &Config{
				AllowedRegions: []string{"US-CA", "US-NY"},
				BlackListMode:  false,
			},
			geoData:       &GeoData{Country: "US", Region: "CA"},
			expectedAllow: true,
		},
		{
			name: "region whitelist - deny",
			config: &Config{
				AllowedRegions: []string{"US-CA", "US-NY"},
				BlackListMode:  false,
			},
			geoData:       &GeoData{Country: "US", Region: "TX"},
			expectedAllow: false,
		},
		{
			name: "city whitelist - allow",
			config: &Config{
				AllowedCities: []string{"US|New York", "US|Los Angeles"},
				BlackListMode: false,
			},
			geoData:       &GeoData{Country: "US", City: "New York"},
			expectedAllow: true,
		},
		{
			name: "city whitelist - deny",
			config: &Config{
				AllowedCities: []string{"US|New York", "US|Los Angeles"},
				BlackListMode: false,
			},
			geoData:       &GeoData{Country: "US", City: "Chicago"},
			expectedAllow: false,
		},
		{
			name: "priority - country has no city/region rules, country match",
			config: &Config{
				AllowedCountries: []string{"US", "FR"},
				AllowedRegions:   []string{"CN-44"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "US", Region: "TX"},
			expectedAllow: true,
		},
		{
			name: "priority - country has region rules, region match",
			config: &Config{
				AllowedCountries: []string{"US"},
				AllowedRegions:   []string{"CN-44"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "CN", Region: "44"},
			expectedAllow: true,
		},
		{
			name: "priority - country has region rules, region no match",
			config: &Config{
				AllowedCountries: []string{"US"},
				AllowedRegions:   []string{"CN-44"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "CN", Region: "11"},
			expectedAllow: false,
		},
		{
			name: "priority - country has city rules, city match",
			config: &Config{
				AllowedCountries: []string{"FR"},
				AllowedCities:    []string{"US|New York", "US|Los Angeles"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "US", City: "New York"},
			expectedAllow: true,
		},
		{
			name: "priority - country has city rules, city no match (ignores country rule)",
			config: &Config{
				AllowedCountries: []string{"US"},
				AllowedCities:    []string{"US|New York"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "US", City: "Chicago", Region: "IL"},
			expectedAllow: false,
		},
		{
			name: "priority - different country with city rule",
			config: &Config{
				AllowedCountries: []string{"US"},
				AllowedCities:    []string{"GB|London"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "GB", City: "London"},
			expectedAllow: true,
		},
		{
			name: "priority - FR in countries, no city/region rules for FR",
			config: &Config{
				AllowedCountries: []string{"FR"},
				AllowedCities:    []string{"US|New York"},
				BlackListMode:    false,
			},
			geoData:       &GeoData{Country: "FR", City: "Paris"},
			expectedAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &GeoAccessControl{
				config: tt.config,
			}

			result := plugin.checkAccess(tt.geoData)
			if result != tt.expectedAllow {
				t.Errorf("Expected %v, got %v", tt.expectedAllow, result)
			}
		})
	}
}

func TestParseIPRanges(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{
			name:    "valid CIDR",
			input:   []string{"192.168.0.0/24"},
			wantErr: false,
		},
		{
			name:    "valid single IP",
			input:   []string{"192.168.1.1"},
			wantErr: false,
		},
		{
			name:    "mixed valid",
			input:   []string{"192.168.1.1", "10.0.0.0/8"},
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			input:   []string{"192.168.0.0/999"},
			wantErr: true,
		},
		{
			name:    "invalid IP",
			input:   []string{"999.999.999.999"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseIPRanges(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestJSONFormatParsing(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		expected GeoData
		wantErr  bool
	}{
		{
			name:     "country only response",
			jsonData: `{"ip":"8.8.8.8","country":"US"}`,
			expected: GeoData{Country: "US", City: "", Region: ""},
			wantErr:  false,
		},
		{
			name:     "full city response",
			jsonData: `{"ip":"8.8.8.8","country":"US","city":"Mountain View","region":"CA"}`,
			expected: GeoData{Country: "US", City: "Mountain View", Region: "CA"},
			wantErr:  false,
		},
		{
			name:     "region response",
			jsonData: `{"ip":"1.2.4.8","country":"CN","region":"44"}`,
			expected: GeoData{Country: "CN", City: "", Region: "44"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var apiResp APIResponse
			err := json.Unmarshal([]byte(tt.jsonData), &apiResp)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			geoData := GeoData{
				Country: apiResp.Country,
				City:    apiResp.City,
				Region:  apiResp.Region,
			}

			if geoData.Country != tt.expected.Country {
				t.Errorf("Country: expected %s, got %s", tt.expected.Country, geoData.Country)
			}
			if geoData.City != tt.expected.City {
				t.Errorf("City: expected %s, got %s", tt.expected.City, geoData.City)
			}
			if geoData.Region != tt.expected.Region {
				t.Errorf("Region: expected %s, got %s", tt.expected.Region, geoData.Region)
			}
		})
	}
}
