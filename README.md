# Geo Access Control

A Traefik middleware plugin for controlling access based on geographic location (country, region, or city) and IP address.

## Features

- **Unified & Hierarchical Configuration**: Define allow/deny rules for countries, regions, cities, and IPs in a single, intuitive structure.
- **"Most Specific Rule Wins" Logic**: Granular control with predictable behavior.
- **Expressive Rules**: Use `true` for "allow" and `false` for "deny" at any level of the hierarchy.
- **IP-Based Rules**: Explicitly allow or deny individual IPs or CIDR ranges, with IP rules taking precedence over geo-rules.
- **JSON and text format support**: Automatic parsing of both JSON and text API responses.
- **Integration with geoip-api**: Optimized for use with your self-hosted GeoIP API.
- **LRU caching**: Fast IP lookups with configurable cache size.
- **Path exclusion**: Exclude specific paths from filtering (regex support).
- **Custom responses**: Configurable HTTP status codes, messages, or redirects.
- **Private IP handling**: Optionally bypass filtering for local requests.
- **Comprehensive logging**: Detailed logging options for debugging and monitoring.

## Installation

(No changes from before)

## Configuration

The plugin uses a powerful, unified configuration for both geo-based and IP-based access control. All rules are defined under the `accessRules` field.

### Rule Structure and Precedence

The `accessRules` field is a map where keys can be a country code, an IP address, or a CIDR range. The value for each key determines the action: `true` to allow, `false` to deny.

The filtering logic follows a strict order of precedence:
1.  **IP Rules**: If the request's IP matches an IP or CIDR rule, that rule is final. An IP deny (`false`) will block the request, and an IP allow (`true`) will permit it, overriding any geo-rules.
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
```yaml
http:
  middlewares:
    geo-full-config:
      plugin:
        geo-access-control:
          geoAPIEndpoint: "http://my-geo-api.com/lookup/{ip}" # Required: URL of your geo IP API. {ip} will be replaced by the client's IP.
          geoAPITimeoutMilliseconds: 500                      # Optional: Timeout for the API request in milliseconds. Default is 750ms.
          geoAPIResponseIsJSON: true                    # Optional: If your API returns JSON. Default is true.
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

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `geoAPIEndpoint` | `string` | `"http://geoip-api:8080/country/{ip}"` | URL of your geo IP API. `{ip}` will be replaced by the client's IP. |
| `geoAPITimeoutMilliseconds` | `int` | `750` | Timeout for the API request in milliseconds. |
| `geoAPIResponseIsJSON` | `boolean` | `true` | If your API returns JSON. |
| `accessRules` | `map[string]interface{}` | `{}` | **Unified map of allow/deny rules.** Keys are country codes or IPs/CIDR. Values are `true` (allow) or `false` (deny), or a map for nested rules. |
| `allowPrivateIPAccess` | `boolean` | `true` | Allow requests from private IP ranges (e.g., 10.0.0.0/8, 192.168.0.0/16). |
| `allowRequestsWithoutGeoData` | `boolean` | `false` | Allow requests if the geographic data cannot be determined by the API. |
| `cacheSize` | `int` | `100` | Size of the LRU cache for geo IP lookups. |
| `deniedStatusCode` | `int` | `404` | HTTP status code to return for denied requests. |
| `deniedResponseMessage` | `string` | `"Not Found"` | Message to return for denied requests. |
| `redirectURL` | `string` | `""` | URL to redirect to for denied requests. Overrides `deniedStatusCode` and `deniedResponseMessage`. |
| `excludedPaths` | `[]string` | `[]` | A list of regular expression patterns for paths that should be excluded from geo-access control checks. |
| `logAllowedAccess` | `boolean` | `false` | Log allowed requests. |
| `logDeniedAccess` | `boolean` | `false` | Log blocked requests. |
| `logGeoAPICalls` | `boolean` | `false` | Log requests to the Geo IP API. |
| `logPrivateIPAccess` | `boolean` | `false` | Log requests from private IP ranges. |
| `logLevel` | `string` | `"info"` | Log level: `debug`, `info`, `warn`, or `error`. |
| `logFilePath` | `string` | `""` | Path to save logs to file. If empty, logs only output to Traefik. Can be used for fail2ban integration. |

## Logging and fail2ban Integration

### Log Levels

The plugin supports four log levels via the `logLevel` configuration option:

- **debug**: Most verbose. Logs all requests with full URL paths (e.g., `https://example.com/api/users`), API calls, cache hits, and detailed processing information.
- **info** (default): Logs allowed/denied requests (if enabled) showing only the website name (e.g., `example.com`), warnings, and errors.
- **warn**: Logs only warnings and errors, showing website name only.
- **error**: Logs only errors, showing website name only.

**URL Format by Log Level:**
- `debug`: Full URL with path → `https://example.com/api/users`
- `info`/`warn`/`error`: Website name only → `example.com`

**Log Examples:**

Debug level:
```
[geo-access-control] [DEBUG] Processing request from IP: 1.2.3.4 to https://example.com/api/users
[geo-access-control] [WARN] Denied request from IP: 1.2.3.4 (CN, , ) to https://example.com/api/users by geo rule
```

Info level:
```
[geo-access-control] [INFO] Allowed request from IP: 5.6.7.8 (US, CA, Los Angeles) to example.com by geo rule
[geo-access-control] [WARN] Denied request from IP: 1.2.3.4 (CN, , ) to example.com by geo rule
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
failregex = ^\[.*\] \[WARN\] Denied request from IP: <HOST> .* to .* by (explicit IP rule|geo rule)$
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