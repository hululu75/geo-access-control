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
- **Header injection**: Add location information to request headers.
- **Private IP handling**: Optionally bypass filtering for local requests.
- **Comprehensive logging**: Detailed logging options for debugging and monitoring.

## Installation

(No changes from before)

## Configuration

The plugin uses a powerful, unified configuration for both geo-based and IP-based access control. All rules are defined under the `allowedLists` field.

### Rule Structure and Precedence

The `allowedLists` field is a map where keys can be a country code, an IP address, or a CIDR range. The value for each key determines the action: `true` to allow, `false` to deny.

The filtering logic follows a strict order of precedence:
1.  **IP Rules**: If the request's IP matches an IP or CIDR rule, that rule is final. An IP deny (`false`) will block the request, and an IP allow (`true`) will permit it, overriding any geo-rules.
2.  **Geo Rules ("Most Specific Wins"):** If no IP rule matches, the plugin evaluates geo-rules:
    *   A **City** rule overrides its **Region**.
    *   A **Region** rule overrides its **Country**.
    *   A **Country** rule is the most general.

### Example Configuration

```yaml
allowedLists:
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
          api: "http://geoip-api:8080/country/{ip}"
          allowedLists:
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

          allowLocalRequests: true
          allowUnknownCountries: false
          # ... other options
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowedLists` | `map[string]interface{}` | `{}` | **Unified map of allow/deny rules.** Keys are country codes or IPs/CIDRs. Values are `true` (allow) or `false` (deny), or a map for nested rules. |
| ... (other options remain, `blackListMode` is removed) |

(Rest of the README would follow, with updated Use Cases and Comparison table)