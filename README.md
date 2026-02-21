# Geo Access Control

A Traefik middleware plugin for controlling access based on geographic location (country, region, or city) and IP address.

## Features

- **Unified & Hierarchical Configuration**: Define allow/deny rules for countries, regions, cities, and IPs in a single, intuitive structure.
- **"Most Specific Rule Wins" Logic**: Granular control with predictable behavior.
- **Expressive Rules**: Use `true` for "allow" and `false` for "deny" at any level of the hierarchy.
- **IP-Based Rules**: Explicitly allow or deny individual IPs or CIDR ranges, with IP rules taking precedence over geo-rules. Uses "most specific wins" logic (longest prefix match).
- **JSON and text format support**: Automatic parsing of both JSON and text API responses.
- **Integration with geoip-api**: Optimized for use with your self-hosted GeoIP API.
- **LRU caching with TTL**: Fast IP lookups with configurable cache size and time-based expiration.
- **Path exclusion**: Exclude specific paths from filtering (regex support).
- **Custom responses**: Configurable HTTP status codes, messages, or redirects.
- **Private IP handling**: Optionally bypass filtering for local requests.
- **Comprehensive logging**: Detailed logging options for debugging and monitoring.

## Recommended Setup with geoip-api

This plugin is designed to work seamlessly with [geoip-api](https://github.com/hululu75/geoip-api), a lightweight, self-hosted GeoIP lookup service.

### Complete Docker Compose Setup

Here's a complete example running Traefik, geoip-api, and your application together:

```yaml
version: '3.8'

services:
  # GeoIP API Service
  geoip-api:
    image: hululu75/geoip-api:latest
    container_name: geoip-api
    environment:
      - MAXMIND_LICENSE_KEY=your_maxmind_license_key_here  # Get free key from https://www.maxmind.com/en/geolite2/signup
      - PORT=8080
      - DB_UPDATE_INTERVAL_HOURS=720  # Update every 30 days
      - LOG_LEVEL=INFO
    volumes:
      - geoip-data:/app/data  # Persist database across restarts
    networks:
      - traefik-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Traefik Reverse Proxy
  traefik:
    image: traefik:v3.0
    container_name: traefik
    command:
      - --api.insecure=true
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --experimental.localPlugins.geo-access-control.moduleName=github.com/hululu75/geo-access-control
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"  # Traefik dashboard
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./plugins-local:/plugins-local  # Local plugins directory
      - ./traefik-config.yml:/etc/traefik/dynamic/config.yml:ro
    networks:
      - traefik-network
    depends_on:
      geoip-api:
        condition: service_healthy
    restart: unless-stopped

  # Your Application (Example)
  myapp:
    image: nginx:alpine
    container_name: myapp
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.myapp.rule=Host(`example.com`)"
      - "traefik.http.routers.myapp.entrypoints=websecure"
      - "traefik.http.routers.myapp.middlewares=geo-filter@file"
    networks:
      - traefik-network
    restart: unless-stopped

networks:
  traefik-network:
    driver: bridge

volumes:
  geoip-data:
```

### Step-by-Step Setup Guide

1. **Get a MaxMind License Key (Free)**

   - Sign up at https://www.maxmind.com/en/geolite2/signup
   - Generate a license key from your account dashboard
   - Copy the key for use in the docker-compose configuration

2. **Prepare the Plugin Directory Structure**

   ```bash
   mkdir -p plugins-local/src/github.com/hululu75
   cd plugins-local/src/github.com/hululu75
   git clone https://github.com/hululu75/geo-access-control.git
   cd ../../..
   ```

3. **Create Traefik Dynamic Configuration**

   Create `traefik-config.yml` with your geo-access rules:

   ```yaml
   http:
     middlewares:
       geo-filter:
         plugin:
           geo-access-control:
             # Point to the geoip-api service
             geoAPIEndpoint: "http://geoip-api:8080/city/{ip}"
             geoAPITimeout: 500
             geoAPIResponseIsJSON: false  # geoip-api returns text by default (US|City|Region)

             # Access rules
             accessRules:
               # Allow US and Canada
               US: true
               CA: true

               # Deny specific countries
               CN: false
               RU: false

               # UK with regional rules
               GB:
                 regions:
                   ENG: true    # Allow England
                   SCO: false   # Deny Scotland

             # Plugin settings
             allowPrivateIPAccess: true
             allowRequestsWithoutGeoData: false
             cacheSize: 1000
             cacheTTL: 3600
             deniedStatusCode: 403
             deniedResponseMessage: "Access denied from your location"

             # Logging
             logDeniedAccess: true
             logLevel: "info"
   ```

4. **Update docker-compose.yml**

   - Replace `your_maxmind_license_key_here` with your actual MaxMind license key
   - Update `Host(\`example.com\`)` with your actual domain

5. **Launch the Services**

   ```bash
   docker-compose up -d
   ```

6. **Verify Setup**

   Test the geoip-api service:
   ```bash
   # Test country lookup
   curl http://localhost:8080/country/8.8.8.8
   # Returns: US

   # Test city lookup (default format for this plugin)
   curl http://localhost:8080/city/8.8.8.8
   # Returns: US|Mountain View|CA

   # Test with JSON format
   curl http://localhost:8080/city/8.8.8.8?format=json
   # Returns: {"ip":"8.8.8.8","country":"US","city":"Mountain View","region":"CA"}
   ```

### Alternative API Endpoint Formats

The geoip-api provides different endpoints based on granularity needs:

```yaml
# For country-level filtering only (fastest)
geoAPIEndpoint: "http://geoip-api:8080/country/{ip}"
geoAPIResponseIsJSON: false  # Returns: US

# For country + region filtering
geoAPIEndpoint: "http://geoip-api:8080/region/{ip}"
geoAPIResponseIsJSON: false  # Returns: US|CA

# For full city-level filtering (recommended)
geoAPIEndpoint: "http://geoip-api:8080/city/{ip}"
geoAPIResponseIsJSON: false  # Returns: US|Mountain View|CA

# Using JSON format (add ?format=json to any endpoint)
geoAPIEndpoint: "http://geoip-api:8080/city/{ip}?format=json"
geoAPIResponseIsJSON: true   # Returns: {"ip":"...","country":"...","city":"...","region":"..."}
```

**Recommendation**: Use `/city/{ip}` endpoint for maximum flexibility, even if you only configure country-level rules. This allows you to add city/region rules later without changing the API endpoint.

### Using External GeoIP Services

While geoip-api is recommended, you can use any GeoIP service that returns location data:

```yaml
# Example with a hypothetical external service
geoAPIEndpoint: "https://external-geoip.example.com/lookup?ip={ip}"
geoAPIResponseIsJSON: true
geoAPITimeout: 1000  # Increase timeout for external services
```

Ensure the response format matches your `geoAPIResponseIsJSON` setting.

## Installation

This plugin uses Traefik's `localPlugins` feature. Follow these steps to install:

1. **Clone the plugin to your Traefik plugins directory:**

   ```bash
   mkdir -p /path/to/traefik/plugins-local/src/github.com/hululu75
   cd /path/to/traefik/plugins-local/src/github.com/hululu75
   git clone https://github.com/hululu75/geo-access-control.git
   ```

2. **Configure Traefik to use local plugins:**

   In your Traefik static configuration (e.g., `traefik.yml` or `traefik.toml`):

   ```yaml
   experimental:
     localPlugins:
       geo-access-control:
         moduleName: github.com/hululu75/geo-access-control
   ```

   Or in TOML format:

   ```toml
   [experimental.localPlugins.geo-access-control]
     moduleName = "github.com/hululu75/geo-access-control"
   ```

3. **Mount the plugins directory in Docker (if using Docker):**

   ```yaml
   services:
     traefik:
       image: traefik:latest
       volumes:
         - /path/to/traefik/plugins-local:/plugins-local
       command:
         - --experimental.localPlugins.geo-access-control.moduleName=github.com/hululu75/geo-access-control
   ```

4. **Restart Traefik** to load the local plugin.

**Note:** Local plugins are loaded from the `/plugins-local` directory by default. The directory structure must match the module name: `/plugins-local/src/github.com/hululu75/geo-access-control/`.

## Configuration

The plugin uses a powerful, unified configuration for both geo-based and IP-based access control. All rules are defined under the `accessRules` field.

### Rule Structure and Precedence

The `accessRules` field is a map where keys can be a country code, an IP address, or a CIDR range. The value for each key determines the action: `true` to allow, `false` to deny.

The filtering logic follows a strict order of precedence:
1.  **IP Rules (Most Specific Wins)**: If the request's IP matches an IP or CIDR rule, that rule is final, overriding any geo-rules. When multiple IP rules match (e.g., a `/16` deny and a `/32` allow), the most specific rule (longest prefix) wins.
2.  **Geo Rules ("Most Specific Wins"):** If no IP rule matches, the plugin evaluates geo-rules:
    *   A **City** rule overrides its **Region**.
    *   A **Region** rule overrides its **Country**.
    *   A **Country** rule is the most general.

### Example Configuration

```yaml
accessRules:
  # --- IP-Based Rules (Highest Priority) ---
  "1.1.1.1": false       # Explicitly deny this IP
  "8.8.0.0/16": true     # Explicitly allow this CIDR range

  # --- Geo-Based Rules ---
  US: true               # Allow all of the US...
  CN:
    regions:
      HK: false          # ...but deny Hong Kong region
      TW: true           # ...and allow Taiwan region
  
  GB:
    regions:
      ENG:
        cities:
          - London       # In England, only allow London
      SCO: false         # Deny all of Scotland
```

### Filtering Logic in Action

- A request from `1.1.1.1` in the US is **Denied** (IP rule wins).
- A request from `8.8.8.8` in France is **Allowed** (IP rule wins).
- A request from California, USA is **Allowed** (`US: true`).
- A request from Hong Kong is **Denied** (`HK: false` is more specific than a potential `CN: true`).
- A request from London is **Allowed** (City rule `London` is most specific).
- A request from Manchester is **Denied** (No city rule, and no `ENG: true` region rule).
- A request from Glasgow, Scotland is **Denied** (`SCO: false` region rule applies).

### Complete Configuration Example

#### YAML Configuration

```yaml
http:
  middlewares:
    geo-full-config:
      plugin:
        geo-access-control:
          geoAPIEndpoint: "http://my-geo-api.com/lookup/{ip}" # Required: URL of your geo IP API. {ip} will be replaced by the client's IP.
          geoAPITimeout: 500                      # Optional: Timeout for the API request in milliseconds. Default is 750ms.
          geoAPIResponseIsJSON: true                          # Optional: If your API returns JSON. Default is true.
          accessRules:
            # IP Rules
            "10.0.0.0/8": false
            "192.168.1.100": true
            # Geo Rules
            US: true
            CA: true
            KP: false
            GB:
              regions:
                SCO: false

          allowPrivateIPAccess: true
          allowRequestsWithoutGeoData: false
          cacheSize: 100
          cacheTTL: 3600
          deniedStatusCode: 404
          deniedResponseMessage: "Access Denied!"
          redirectURL: "https://example.com/denied"
          excludedPaths: ["/metrics", "/health"]
          logAllowedAccess: true
          logDeniedAccess: true
          logGeoAPICalls: true
          logPrivateIPAccess: true
          logLevel: "info"                                    # Optional: Log level. Options: debug, info, warn, error. Default is info.
          logFilePath: "/var/log/traefik/geo-access.log"     # Optional: Save logs to file for fail2ban integration. Default is empty (Traefik logs only).
```

#### TOML Configuration

```toml
[http.middlewares]
  [http.middlewares.geo-full-config.plugin.geo-access-control]
    geoAPIEndpoint = "http://my-geo-api.com/lookup/{ip}"
    geoAPITimeout = 500
    geoAPIResponseIsJSON = true
    allowPrivateIPAccess = true
    allowRequestsWithoutGeoData = false
    cacheSize = 100
    cacheTTL = 3600
    deniedStatusCode = 404
    deniedResponseMessage = "Access Denied!"
    redirectURL = "https://example.com/denied"
    excludedPaths = ["/metrics", "/health"]
    logAllowedAccess = true
    logDeniedAccess = true
    logGeoAPICalls = true
    logPrivateIPAccess = true
    logLevel = "info"
    logFilePath = "/var/log/traefik/geo-access.log"

    # Access Rules (IP and Geo Rules)
    [http.middlewares.geo-full-config.plugin.geo-access-control.accessRules]
      "10.0.0.0/8" = false
      "192.168.1.100" = true
      US = true
      CA = true
      KP = false

      # Country with region rules
      [http.middlewares.geo-full-config.plugin.geo-access-control.accessRules.GB]
        [http.middlewares.geo-full-config.plugin.geo-access-control.accessRules.GB.regions]
          SCO = false
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `geoAPIEndpoint` | `string` | `"http://geoip-api:8080/country/{ip}"` | URL of your geo IP API. `{ip}` will be replaced by the client's IP. |
| `geoAPITimeout` | `int` | `750` | Timeout for the API request in milliseconds. |
| `geoAPIResponseIsJSON` | `boolean` | `true` | If your API returns JSON. |
| `accessRules` | `map[string]interface{}` | `{}` | **Unified map of allow/deny rules.** Keys are country codes or IPs/CIDR. Values are `true` (allow) or `false` (deny), or a map for nested rules. |
| `allowPrivateIPAccess` | `boolean` | `true` | Allow requests from private IP ranges (e.g., 10.0.0.0/8, 192.168.0.0/16). |
| `allowRequestsWithoutGeoData` | `boolean` | `false` | Allow requests if the geographic data cannot be determined by the API. |
| `cacheSize` | `int` | `100` | Size of the LRU cache for geo IP lookups. |
| `cacheTTL` | `int` | `3600` | Cache entry time-to-live in seconds. Expired entries are automatically removed on access and re-fetched from the GeoIP API. Set to `0` to disable TTL (entries only evicted by capacity). |
| `deniedStatusCode` | `int` | `404` | HTTP status code to return for denied requests. |
| `deniedResponseMessage` | `string` | `"Not Found"` | Message to return for denied requests. |
| `redirectURL` | `string` | `""` | URL to redirect to for denied requests. Overrides `deniedStatusCode` and `deniedResponseMessage`. |
| `excludedPaths` | `[]string` | `[]` | A list of regular expression patterns for paths that should be excluded from geo-access control checks. |
| `logAllowedAccess` | `boolean` | `false` | Log allowed requests. |
| `logDeniedAccess` | `boolean` | `false` | Log blocked requests. |
| `logGeoAPICalls` | `boolean` | `false` | Log requests to the Geo IP API with User-Agent information. |
| `logPrivateIPAccess` | `boolean` | `false` | Log requests from private IP ranges. |
| `logWhiteListAccess` | `boolean` | `false` | Log requests allowed by IP whitelist rules. |
| `logLevel` | `string` | `"info"` | Log level: `debug`, `info`, `warn`, or `error`. |
| `logFilePath` | `string` | `""` | Path to save logs to file. If empty, logs only output to Traefik. Can be used for fail2ban integration. |

## Logging and fail2ban Integration

### Log Levels

The plugin supports four log levels via the `logLevel` configuration option:

- **debug**: Most verbose. Logs all requests with full URL paths (e.g., `https://example.com/api/users`), API calls with User-Agent information, cache hits, and detailed processing information.
- **info** (default): Logs allowed/denied requests (if enabled) showing only the website name (e.g., `example.com`), warnings, and errors.
- **warn**: Logs only warnings and errors, showing website name only.
- **error**: Logs only errors, showing website name only.

**URL Format by Log Level:**
- `debug`: Full URL with path → `https://example.com/api/users`
- `info`/`warn`/`error`: Website name only → `example.com`

**Log Format:**

Logs follow the format:
```
YYYY/MM/DD HH:MM:SS [PLUGIN_NAME] [LEVEL] message
```

**Log Examples:**

Debug level:
```
2026/01/11 08:40:32 [geo-access-control] [DEBUG] Processing request from IP: 1.2.3.4 to https://example.com/api/users
2026/01/11 08:40:32 [geo-access-control] [DEBUG] Making GeoAPI call to: http://geoip-api:8080/country/1.2.3.4 for IP: 1.2.3.4, User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
2026/01/11 08:40:32 [geo-access-control] [WARN] Denied request from IP: 1.2.3.4 (CN, , ) to https://example.com/api/users by geo rule
```

Info level:
```
2026/01/11 08:40:32 [geo-access-control] [INFO] Allowed request from IP: 5.6.7.8 (US, CA, Los Angeles) to example.com by geo rule
2026/01/11 08:40:32 [geo-access-control] [WARN] Denied request from IP: 1.2.3.4 (CN, , ) to example.com by geo rule
```

### Log File Path

By default, logs are output to stderr and appear in Traefik's logs. You can configure `logFilePath` to save logs to a separate file:

```yaml
logFilePath: "/var/log/traefik/geo-access.log"
```

When `logFilePath` is set:
- Logs are written to **both** stderr (Traefik logs) and the specified file
- This is useful for fail2ban integration, allowing you to monitor blocked requests separately

### fail2ban Integration Example

To use this plugin with fail2ban for additional protection:

1. **Configure the plugin to log denied requests to a file:**

```yaml
http:
  middlewares:
    geo-access:
      plugin:
        geo-access-control:
          logDeniedAccess: true
          logFilePath: "/var/log/traefik/geo-access.log"
          logLevel: "info"
```

2. **Create a fail2ban filter** (`/etc/fail2ban/filter.d/traefik-geo-access.conf`):

```ini
[Definition]
failregex = ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[.*\] \[WARN\] Denied request from IP: <HOST> .* to .* by (explicit IP rule|geo rule)$
ignoreregex =
```

**Note:** The log format shows the website name (e.g., `example.com`) at info level and above, and full URL path at debug level.

3. **Create a fail2ban jail** (`/etc/fail2ban/jail.d/traefik-geo-access.conf`):

```ini
[traefik-geo-access]
enabled = true
port = http,https
filter = traefik-geo-access
logpath = /var/log/traefik/geo-access.log
maxretry = 5
findtime = 600
bantime = 3600
```

This configuration will ban IPs that are denied by geo-access rules 5 times within 10 minutes for 1 hour.