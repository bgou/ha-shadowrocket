# mihomo QQ Domain Proxy

## How it works

1. At start, the add-on downloads your subscription (User-Agent `clash.meta`). It parses Clash YAML, or falls back to a base64 list of `ss://`, `ssr://`, `trojan://` and `vmess://` URIs. It skips placeholder entries such as "剩余流量" or "到期时间", and drops invalid ones.
2. Node hostnames are resolved once over DNS-over-HTTPS (1.1.1.1 / 8.8.8.8) and pinned to IPs, so mihomo never relies on the DNS it serves. TLS SNI and WebSocket Host values are kept.
3. mihomo runs with **fake-ip DNS in whitelist mode**. Only names that match `proxy_domains` get a fake address in 198.18.0.0/16. Every other name gets its real answer from the upstream resolvers.
4. The add-on adds **one route**, `198.18.0.0/16 dev mihomo-qq`. TUN `auto-route` is off and no policy rules are added. Traffic to real addresses (your LAN, DuckDNS, Tailscale, remote access) never enters the tunnel.
5. With `manage_dns: true`, the add-on puts its own resolver first in the HA DNS plugin servers, using the Supervisor API (`/dns/options`). The previous servers are saved to `/data/dns_prev.json` and restored on every stop.

## Proxy groups
- `PREFERRED`: url-test over nodes whose name contains `preferred_node`. Only created if that option is set.
- `AUTO`: url-test over nodes whose name looks China-bound (回国, 中国, 国内, China, CN, 大陆).
- `AUTO-ANY`: url-test over all nodes.
- `PROXY`: fallback over the groups above, in that order. Health checks use `https://y.qq.com`.

## Options
| Option | Default | Meaning |
|---|---|---|
| `subscription_url` | – | Your subscription link. It is stored as a password field and never logged. |
| `proxy_domains` | QQ / Tencent suffixes | Domain suffixes to proxy. |
| `preferred_node` | empty | Case-insensitive substring of a node name to prefer, e.g. `港沪`. |
| `refresh_hours` | 6 | How often to re-download the subscription (0 = never). Open connections are not dropped. |
| `trial_minutes` | 15 | When `keep` is false, the add-on stops itself after this many minutes and reverts everything. |
| `keep` | false | Set to true once you have confirmed everything works. |
| `manage_dns` | true | Point the HA DNS plugin at the add-on, and restore it on stop. |
| `dns_listen` | auto | Advanced. Listen address for the resolver. Defaults to the hassio gateway (`172.30.32.1`) port 53. |
| `upstream_dns` | auto | Advanced. Comma-separated upstream resolvers. Defaults to the DNS plugin's `locals` (the DNS your network hands out, usually the router), falling back to 1.1.1.1. DoH URLs are allowed. |

## Safety design
- **Preflight:** the add-on refuses to start if anything already routes 198.18/15, if the TUN device already exists, or if a leftover mihomo policy rule (table 2022) is present.
- **Guard:** every 5 seconds the add-on compares the ip rules, the default route and the route to 1.1.1.1 against a baseline. On any change it tears down at once: DNS is restored first, then the route is removed and mihomo is stopped.
- **Dead-man:** while `keep` is false, the add-on reverts by itself after `trial_minutes`.
- **Stale repair:** after a crash or power loss, the next start detects its old resolver left in the DNS servers and restores the saved list.
- **No secrets in logs:** the subscription URL, node servers, passwords and all IPv4 addresses are redacted from the add-on log and mihomo output.

## Permissions
The add-on needs `host_network`, `NET_ADMIN` and `/dev/net/tun`. With `manage_dns`, it also needs `hassio_role: manager` to change DNS plugin settings. These permissions lower the add-on's security rating in the HA UI. If you'd rather not grant them, set `manage_dns: false` and add `dns://172.30.32.1` yourself with `ha dns options --servers dns://172.30.32.1`.

## Manual rollback
Stop the add-on. If HA DNS still looks wrong, reset DNS options to the defaults with `ha dns reset`.

`ha dns options --servers ""` reports success but does not clear the server list on HA OS 18.4 / Supervisor (verified 2026-11-15). Do not use it to roll back.

From the SSH or Terminal add-on, clear the server list and restart DNS:

```
curl -sX POST -H "Authorization: Bearer $SUPERVISOR_TOKEN" -H 'Content-Type: application/json' -d '{"servers":[]}' http://supervisor/dns/options && ha dns restart
```

`ha dns restart` can fail once with "Can't restart CoreDNS plugin" right after an options change. Run it again; the second attempt works.

`ha apps options` has no `--boot` or `--watchdog` flags. Set boot and watchdog on the add-on's page in the UI.
