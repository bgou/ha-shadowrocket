# Changelog

## 3.0.0
- First shareable release.
- Reads the subscription URL (Clash YAML, or base64 SS/SSR/trojan/vmess lists) and refreshes it periodically.
- Adds url-test and fallback groups, plus an optional preferred node.
- Optionally manages HA DNS plugin servers through the Supervisor API, and restores them on stop.
- Includes a routing guard and a trial dead-man timer.
