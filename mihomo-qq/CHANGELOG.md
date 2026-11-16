# Changelog

## 3.0.1
- Docs and metadata only. The add-on slug and name are unchanged.
- Repository README heading is `ha-shadowrocket`. The add-on `url` is `https://github.com/bgou/ha-shadowrocket`.
- DNS rollback uses `ha dns reset` (resets DNS options to defaults). `ha dns options --servers ""` reports success but does not clear the server list on HA OS 18.4 / Supervisor (verified 2026-11-15).
- Document the SSH/Terminal alternative that posts `{"servers":[]}` to the Supervisor DNS options API, then runs `ha dns restart`. That restart can fail once with "Can't restart CoreDNS plugin" right after an options change; running it again works.
- `ha apps options` has no `--boot` or `--watchdog` flags. Set those on the add-on's page.

## 3.0.0
- First shareable release.
- Reads the subscription URL (Clash YAML, or base64 SS/SSR/trojan/vmess lists) and refreshes it periodically.
- Adds url-test and fallback groups, plus an optional preferred node.
- Optionally manages HA DNS plugin servers through the Supervisor API, and restores them on stop.
- Includes a routing guard and a trial dead-man timer.
