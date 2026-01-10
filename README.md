# Geo Access Control

A Traefik middleware plugin for controlling access based on geographic location (country, region, or city).

## Features

- **Priority-based multi-level filtering**: City > Region > Country priority system
- **Granular control per country**: Define specific cities/regions for some countries while allowing others entirely
- **Flexible rule composition**: Mix countries, regions, and cities in the same configuration
- **JSON and text format support**: Automatic parsing of both JSON and text API responses
- **Whitelist and blacklist modes**: Allow or block specific locations
- **Integration with geoip-api**: Optimized for use with your self-hosted GeoIP API
- **LRU caching**: Fast IP lookups with configurable cache size
- **Flexible IP allowlisting**: Support for individual IPs and CIDR ranges
- **Path exclusion**: Exclude specific paths from filtering (regex support)
- **Custom responses**: Configurable HTTP status codes, messages, or redirects
- **Header injection**: Add location information to request headers
- **Private IP handling**: Optionally bypass filtering for local requests
- **Comprehensive logging**: Detailed logging options for debugging and monitoring

## Installation

### Local Mode (for development/testing)

Add the plugin to your Traefik static configuration:

```yaml
# traefik.yml
experimental:
  localPlugins:
    geo-access-control:
      moduleName: github.com/yourusername/geo-access-control
```

### Pilot Mode (production)

```yaml
# traefik.yml
experimental:
  plugins:
    geo-access-control:
      moduleName: github.com/yourusername/geo-access-control
      version: v1.0.0
```

## Configuration

### Basic Country Filtering (Whitelist)

Allow only specific countries:

```yaml
http:
  middlewares:
    geo-allow-us-ca:
      plugin:
        geo-access-control:
          api: "http://geoip-api:8080/country/{ip}"
          allowedCountries:
            - US
            - CA
            - GB
```

### Country Filtering (Blacklist)

Block specific countries:

```yaml
http:
  middlewares:
    geo-block-bad-actors:
      plugin:
        geo-access-control:
          api: "http://geoip-api:8080/country/{ip}"
          blackListMode: true
          allowedCountries:
            - CN
            - RU
            - KP
```

### Region-Level Filtering

Allow only specific regions (requires GeoLite2-City database):

```yaml
http:
  middlewares:
    geo-allow-us-california:
      plugin:
        geo-access-control:
          api: "http://geoip-api:8080/country/{ip}"
          allowedRegions:
            - US-CA    # California
            - US-NY    # New York
            - CN-44    # Guangdong Province
```

### City-Level Filtering

Allow only specific cities (requires GeoLite2-City database):

```yaml
http:
  middlewares:
    geo-allow-major-cities:
      plugin:
        geo-access-control:
          api: "http://geoip-api:8080/country/{ip}"
          allowedCities:
            - "US|New York"
            - "US|Los Angeles"
            - "CN|Shanghai"
```

### **Priority-Based Multi-Level Filtering** (NEW!)

Combine countries, regions, and cities with **priority-based matching**:

```yaml
http:
  middlewares:
    geo-combined-access:
      plugin:
        geo-access-control:
          api: "http://geoip-api:8080/country/{ip}"
          allowedCountries:
            - US    # Allow all US (no city/region restrictions)
            - FR    # Allow all France
          allowedRegions:
            - CN-44  # Only allow Guangdong Province from China
            - CN-31  # Only allow Shanghai from China
          allowedCities:
            - "GB|London"      # Only allow London from UK
            - "GB|Manchester"  # Only allow Manchester from UK
```

**Priority Logic (City > Region > Country):**

For each country, the plugin checks in order:
1. **City rules** - If city rules exist for this country, ONLY city rules are checked
2. **Region rules** - If region rules exist (no city rules), ONLY region rules are checked
3. **Country rules** - If no city/region rules, country rules are checked

**Example scenarios:**
- 🇺🇸 USA, New York → ✅ **Allowed** (US has no city/region rules, uses country rule)
- 🇺🇸 USA, Any city → ✅ **Allowed** (US has no city/region rules, uses country rule)
- 🇨🇳 China, Guangdong (region: 44) → ✅ **Allowed** (CN has region rules, matches CN-44)
- 🇨🇳 China, Beijing (region: 11) → ❌ **Denied** (CN has region rules, but CN-11 not in list)
- 🇬🇧 UK, London → ✅ **Allowed** (GB has city rules, matches GB|London)
- 🇬🇧 UK, Birmingham → ❌ **Denied** (GB has city rules, but Birmingham not in list)
- 🇫🇷 France, Paris → ✅ **Allowed** (FR has no city/region rules, uses country rule)

**Key Point:** If you define city rules for a country (e.g., US), the country-level rule is **ignored** for that country. Only the specified cities are allowed.

### Complete Configuration Example

```yaml
http:
  middlewares:
    geo-full-config:
      plugin:
        geo-access-control:
          # API Configuration
          api: "http://geoip-api:8080/country/{ip}"
          apiTimeoutMs: 1000

          # Location Lists (can be combined - OR logic)
          allowedCountries:
            - US
            - CA
          allowedRegions:
            - CN-44
          allowedCities:
            - "GB|London"

          # Blacklist mode (if true, blocks listed locations instead)
          blackListMode: false

          # IP Allowlisting
          allowedIPs:
            - "192.168.1.0/24"
            - "10.0.0.5"

          # Local Request Handling
          allowLocalRequests: true
          allowUnknownCountries: false

          # Response Configuration
          deniedHTTPStatusCode: 403
          deniedMessage: "Access Denied: Your location is not allowed"
          redirectURL: ""  # Optional redirect for blocked requests

          # Header Injection
          addCountryHeader: true
          addRegionHeader: false
          addCityHeader: false

          # Path Exclusions (regex patterns)
          excludedPathPatterns:
            - "^/health$"
            - "^/api/public/.*"

          # Cache Configuration
          cacheSize: 200

          # Logging
          logAllowedRequests: false
          logBlockedRequests: true
          logAPIRequests: false
          logLocalRequests: false
          silentStartUp: false
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api` | string | `http://geoip-api:8080/country/{ip}` | GeoIP API endpoint with `{ip}` placeholder |
| `apiTimeoutMs` | int | `750` | API request timeout in milliseconds |
| `useJSONFormat` | bool | `true` | Use JSON format for API requests (adds `?format=json`). Set to `false` for text format. |
| `allowedCountries` | []string | `[]` | List of allowed country codes (ISO 3166-1 alpha-2). Requests from these countries are allowed. |
| `allowedRegions` | []string | `[]` | List of allowed regions (format: `COUNTRY-REGION`). Requires City database. |
| `allowedCities` | []string | `[]` | List of allowed cities (format: `COUNTRY\|City`). Requires City database. |
| `blackListMode` | bool | `false` | If true, blocks listed locations instead of allowing them |
| `allowLocalRequests` | bool | `true` | Allow requests from private IP addresses |
| `allowUnknownCountries` | bool | `false` | Allow requests when location cannot be determined |
| `allowedIPs` | []string | `[]` | List of always-allowed IPs (supports CIDR notation) |
| `cacheSize` | int | `100` | Number of IP lookups to cache |
| `deniedHTTPStatusCode` | int | `403` | HTTP status code for blocked requests |
| `deniedMessage` | string | `Access Denied` | Message returned for blocked requests |
| `redirectURL` | string | `""` | Redirect URL for blocked requests (overrides status/message) |
| `addCountryHeader` | bool | `false` | Add `X-Country-Code` header to requests |
| `addRegionHeader` | bool | `false` | Add `X-Region-Code` header to requests |
| `addCityHeader` | bool | `false` | Add `X-City-Name` header to requests |
| `excludedPathPatterns` | []string | `[]` | Regex patterns for paths to exclude from filtering |
| `logAllowedRequests` | bool | `false` | Log allowed requests |
| `logBlockedRequests` | bool | `true` | Log blocked requests |
| `logAPIRequests` | bool | `false` | Log GeoIP API calls |
| `logLocalRequests` | bool | `false` | Log local/private IP requests |
| `silentStartUp` | bool | `false` | Suppress startup log messages |

### Filtering Logic

The plugin uses **priority-based matching** per country:

**Priority Order: City > Region > Country**

For each incoming request:
1. Determine the request's country
2. Check if **city rules** are defined for this country
   - If YES → Check ONLY city rules (ignore region/country rules)
3. If no city rules, check if **region rules** are defined for this country
   - If YES → Check ONLY region rules (ignore country rules)
4. If no city/region rules, check **country rules**

**Whitelist Mode (`blackListMode: false`):**
- Request is **allowed** if it passes the priority check
- At least one filter list must be configured

**Blacklist Mode (`blackListMode: true`):**
- Request is **blocked** if it matches the priority check
- Works the same way but inverts the result

**Examples:**

```yaml
# Configuration
allowedCountries: [US, FR]
allowedRegions: [CN-44]
allowedCities: ["GB|London"]
```

Decision tree:
- Request from **US** → No city/region rules for US → Uses country rule → ✅ Allowed
- Request from **CN** (region: 44) → Has region rules for CN → Checks region (CN-44) → ✅ Allowed
- Request from **CN** (region: 11) → Has region rules for CN → Checks region (CN-11) → ❌ Denied
- Request from **GB** (city: London) → Has city rules for GB → Checks city → ✅ Allowed
- Request from **FR** → No city/region rules for FR → Uses country rule → ✅ Allowed

**Note:** The plugin automatically uses the appropriate API endpoint:
- If `allowedCities` or `allowedRegions` are configured → calls `/city/{ip}` (includes all data)
- Otherwise → calls `/country/{ip}` (country only, faster)

### Response Format Support

The plugin supports both **JSON** and **text** response formats from geoip-api:

**JSON Format (Default):**
```json
// /country/{ip}?format=json
{"ip":"8.8.8.8","country":"US"}

// /city/{ip}?format=json
{"ip":"8.8.8.8","country":"US","city":"Mountain View","region":"CA"}
```

**Text Format:**
```
// /country/{ip}
US

// /city/{ip}
US|Mountain View|CA
```

**Note:** The `region` field returns only the region code (e.g., `CA`, `44`, `IDF`), not the full `COUNTRY-REGION` format. The plugin automatically combines the country and region for matching.

By default, the plugin uses JSON format (`useJSONFormat: true`). To use text format:
```yaml
geo-text-format:
  plugin:
    geo-access-control:
      api: "http://geoip-api:8080/country/{ip}"
      useJSONFormat: false
      allowedCountries: [US]
```

## Integration with geoip-api

This plugin is designed to work seamlessly with the [geoip-api](../geoip-api) service:

### Docker Compose Example

```yaml
version: '3.8'

services:
  geoip-api:
    image: ghcr.io/yourusername/geoip-api:latest
    environment:
      - MAXMIND_LICENSE_KEY=your_license_key
      - GEOIP_DB_FILENAME=GeoLite2-City.mmdb
    volumes:
      - ./data:/data
    networks:
      - traefik-network

  traefik:
    image: traefik:v2.10
    command:
      - "--experimental.localPlugins.geo-access-control.moduleName=github.com/yourusername/geo-access-control"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./geo-access-control:/plugins-local/src/github.com/yourusername/geo-access-control
    labels:
      - "traefik.http.middlewares.geo-filter.plugin.geo-access-control.api=http://geoip-api:8080/country/{ip}"
      - "traefik.http.middlewares.geo-filter.plugin.geo-access-control.allowedCountries=US,CA,GB"
    networks:
      - traefik-network

networks:
  traefik-network:
    external: true
```

## Use Cases

### 1. Compliance and Data Sovereignty

Block access from countries where your service is not compliant:

```yaml
geo-compliance:
  plugin:
    geo-access-control:
      filterMode: "country"
      blackListMode: true
      allowedCountries:
        - KP  # North Korea
        - IR  # Iran
        - SY  # Syria
```

### 2. Regional Content Delivery

Restrict content to specific regions:

```yaml
geo-regional-content:
  plugin:
    geo-access-control:
      filterMode: "region"
      allowedRegions:
        - US-CA
        - US-NY
        - US-TX
```

### 3. City-Level Access Control

Allow access only from major cities:

```yaml
geo-city-only:
  plugin:
    geo-access-control:
      filterMode: "city"
      allowedCities:
        - "US|New York"
        - "GB|London"
        - "FR|Paris"
```

### 4. Health Check Exclusion

Exclude health checks from geo-filtering:

```yaml
geo-with-health:
  plugin:
    geo-access-control:
      filterMode: "country"
      allowedCountries: [US]
      excludedPathPatterns:
        - "^/health$"
        - "^/readiness$"
```

## Performance

- **Cache Hit Rate**: ~95% for typical web traffic
- **Latency**: <1ms (cache hit), <50ms (cache miss + API call)
- **Memory Usage**: ~10KB per 1000 cached IPs

## Debugging

Enable verbose logging for troubleshooting:

```yaml
geo-debug:
  plugin:
    geo-access-control:
      logAllowedRequests: true
      logBlockedRequests: true
      logAPIRequests: true
      logLocalRequests: true
```

## Comparison with geoblock

| Feature | geo-access-control | geoblock |
|---------|-------------------|----------|
| Country filtering | ✅ | ✅ |
| Region filtering | ✅ | ❌ |
| City filtering | ✅ | ❌ |
| **Priority-based multi-level filtering** | ✅ | ❌ |
| Per-country granular control | ✅ | ❌ |
| Custom API backend | ✅ | ✅ |
| LRU caching | ✅ | ✅ |
| Header injection | ✅ (3 headers) | ✅ (1 header) |
| Path exclusion | ✅ | ✅ |
| IP allowlisting | ✅ | ✅ |
| CIDR support | ✅ | ✅ |
| Blacklist mode | ✅ | ✅ |

**Key Advantage:** geo-access-control allows you to apply different filtering levels to different countries in the same configuration. For example, allow all traffic from US while restricting China to only Guangdong Province and UK to only London.

## License

MIT License

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Related Projects

- [geoip-api](../geoip-api) - Self-hosted GeoIP lookup service
- [Traefik](https://traefik.io/) - Cloud-native application proxy
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) - Free geolocation database
