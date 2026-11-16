#!/usr/bin/env python3
"""mihomo-qq v3: route only chosen domains through a subscription node.

Safety design (same as v2): TUN with auto-route OFF; the ONLY host routing change is one
main-table route 198.18.0.0/16 -> TUN. A guard compares ip rules / default route / probe routes
to a pre-start baseline every 5 s and tears down on any drift. Trial mode auto-stops unless keep.
Secrets (subscription URL, node servers/passwords) are never logged.
"""
import base64, ipaddress, json, os, re, secrets, signal, socket, ssl, struct
import subprocess, sys, threading, time, urllib.parse, urllib.request
import yaml

DATA = os.environ.get("MQ_DATA", "/data")
OPTIONS = os.environ.get("MQ_OPTIONS", os.path.join(DATA, "options.json"))
MIHOMO = os.environ.get("MIHOMO_BIN", "/mihomo")
SUP_URL = os.environ.get("SUPERVISOR_URL", "http://supervisor")
SUP_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
TEST_NO_TUN = os.environ.get("MQ_TEST_NO_TUN") == "1"   # box testing: localhost mixed port, no TUN
DEV, NET, FAKE_RANGE = "mihomo-qq", "198.18.0.0/16", "198.18.0.1/16"
CTRL = "127.0.0.1:19090"
PROVIDER = "subscription"
UA = "clash.meta"
PLACEHOLDER_RE = re.compile(
    r"(到期|过期|剩余|流量|套餐|官网|网址|重置|续费|公告|频道|群组|客服|订阅|"
    r"expire|traffic|remaining|website|reset|renew|telegram|\btg\b|subscription|官方)", re.I)
SENSITIVE: set = set()

def log(msg): print(f"[mihomo-qq] {msg}", flush=True)

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
def redact(line: str) -> str:
    for s in SENSITIVE:
        if s and len(s) >= 4:
            line = line.replace(s, "<redacted>")
    return _IP_RE.sub("<ip>", line)

# ---------------------------------------------------------------- subscription parsing
def _b64d(s: str) -> str:
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/").rstrip("=")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True).decode("utf-8", "replace")

def _qs(q): return {k: v[0] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}

def parse_ss(uri):
    body = uri[5:]
    name = ""
    if "#" in body:
        body, name = body.split("#", 1); name = urllib.parse.unquote(name)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    body = body.rstrip("/")
    if "@" in body:  # SIP002: base64(method:pass)@host:port  (userinfo may also be plain/urlencoded)
        ui, hp = body.rsplit("@", 1)
        ui = urllib.parse.unquote(ui)
        try:
            dec = _b64d(ui)
            if ":" not in dec: raise ValueError
        except Exception:
            dec = ui
        method, password = dec.split(":", 1)
    else:            # legacy: base64(method:pass@host:port)
        dec = _b64d(body)
        mp, hp = dec.rsplit("@", 1)
        method, password = mp.split(":", 1)
    host, port = hp.rsplit(":", 1)
    p = {"name": name or host, "type": "ss", "server": host.strip("[]"), "port": int(port),
         "cipher": method, "password": password, "udp": True}
    plugin = _qs(query).get("plugin", "")
    if plugin:
        parts = plugin.split(";")
        if parts[0] in ("obfs-local", "simple-obfs"):
            o = dict(x.split("=", 1) for x in parts[1:] if "=" in x)
            p["plugin"] = "obfs"; p["plugin-opts"] = {"mode": o.get("obfs", "http"), "host": o.get("obfs-host", "")}
        elif parts[0] in ("v2ray-plugin",):
            o = dict(x.split("=", 1) if "=" in x else (x, True) for x in parts[1:])
            p["plugin"] = "v2ray-plugin"
            p["plugin-opts"] = {"mode": "websocket", "tls": "tls" in o, "host": o.get("host", ""), "path": o.get("path", "/")}
        else:
            raise ValueError("unsupported ss plugin")
    return p

def parse_ssr(uri):
    dec = _b64d(uri[6:])
    main, _, query = dec.partition("/?")
    host, port, protocol, method, obfs, pw = main.rsplit(":", 5)
    q = _qs(query)
    d = lambda k: _b64d(q[k]) if q.get(k) else ""
    return {"name": d("remarks") or host, "type": "ssr", "server": host, "port": int(port),
            "cipher": method, "password": _b64d(pw), "protocol": protocol, "protocol-param": d("protoparam"),
            "obfs": obfs, "obfs-param": d("obfsparam"), "udp": True}

def parse_trojan(uri):
    u = urllib.parse.urlsplit(uri)
    q = _qs(u.query)
    p = {"name": urllib.parse.unquote(u.fragment) or u.hostname, "type": "trojan", "server": u.hostname,
         "port": u.port or 443, "password": urllib.parse.unquote(u.username or ""), "udp": True,
         "skip-cert-verify": q.get("allowInsecure", q.get("insecure", "0")) in ("1", "true")}
    if q.get("sni") or q.get("peer"): p["sni"] = q.get("sni") or q.get("peer")
    if q.get("type") == "ws":
        p["network"] = "ws"; p["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", "")} if q.get("host") else {}}
    elif q.get("type") == "grpc":
        p["network"] = "grpc"; p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    return p

def parse_vmess(uri):
    j = json.loads(_b64d(uri[8:]))
    p = {"name": j.get("ps") or j.get("add"), "type": "vmess", "server": j["add"], "port": int(j["port"]),
         "uuid": j["id"], "alterId": int(j.get("aid", 0) or 0), "cipher": j.get("scy") or "auto", "udp": True}
    if j.get("tls") == "tls":
        p["tls"] = True
        if j.get("sni"): p["servername"] = j["sni"]
    net = j.get("net", "tcp")
    if net == "ws":
        p["network"] = "ws"; p["ws-opts"] = {"path": j.get("path") or "/", "headers": {"Host": j["host"]} if j.get("host") else {}}
    elif net == "grpc":
        p["network"] = "grpc"; p["grpc-opts"] = {"grpc-service-name": j.get("path", "")}
    elif net == "h2":
        p["network"] = "h2"; p["h2-opts"] = {"path": j.get("path") or "/", "host": [j["host"]] if j.get("host") else []}
    return p

PARSERS = {"ss://": parse_ss, "ssr://": parse_ssr, "trojan://": parse_trojan, "vmess://": parse_vmess}

def parse_subscription(text: str):
    """Return (proxies, stats). Accepts Clash YAML, or (base64-wrapped) URI lists."""
    stats = {"format": None, "total": 0, "skipped_placeholder": 0, "skipped_invalid": 0}
    proxies = []
    try:
        y = yaml.safe_load(text)
    except Exception:
        y = None
    if isinstance(y, dict) and isinstance(y.get("proxies"), list):
        stats["format"] = "clash-yaml"
        raw = [p for p in y["proxies"] if isinstance(p, dict)]
    else:
        body = text.strip()
        if not any(body.startswith(k) for k in PARSERS):
            try:
                body = _b64d(body)
            except Exception:
                raise ValueError("subscription is neither Clash YAML nor a URI list")
        if not any(l.strip().startswith(k) for l in body.splitlines() for k in PARSERS):
            raise ValueError("subscription is neither Clash YAML nor a URI list")
        stats["format"] = "uri-list"
        raw = []
        for line in body.splitlines():
            line = line.strip()
            if not line: continue
            fn = next((f for k, f in PARSERS.items() if line.startswith(k)), None)
            if not fn:
                stats["skipped_invalid"] += 1; continue
            try:
                raw.append(fn(line))
            except Exception:
                stats["skipped_invalid"] += 1
    stats["total"] = len(raw)
    seen = set()
    for p in raw:
        name, server, port = str(p.get("name", "")), str(p.get("server", "")), p.get("port")
        if PLACEHOLDER_RE.search(name):
            stats["skipped_placeholder"] += 1; continue
        try:
            port = int(port)
            bad_ip = False
            try:
                ip = ipaddress.ip_address(server.strip("[]"))
                bad_ip = ip.is_loopback or ip.is_unspecified or ip.is_multicast
            except ValueError:
                pass
            if not server or port <= 1 or port > 65535 or bad_ip or not p.get("type"):
                raise ValueError
        except Exception:
            stats["skipped_invalid"] += 1; continue
        base, n = name, 2
        while name in seen:
            name = f"{base} ({n})"; n += 1
        seen.add(name); p["name"] = name; p["port"] = port
        proxies.append(p)
    return proxies, stats

# ---------------------------------------------------------------- DoH pinning
_DOH = [("https://1.1.1.1/dns-query?name={}&type=A", {"accept": "application/dns-json"}),
        ("https://8.8.8.8/resolve?name={}&type=A", {})]

def doh_a(host: str):
    for url, hdr in _DOH:
        try:
            req = urllib.request.Request(url.format(urllib.parse.quote(host)), headers=hdr)
            with urllib.request.urlopen(req, timeout=8) as r:
                ans = [a["data"] for a in json.load(r).get("Answer", []) if a.get("type") == 1]
            if ans: return ans[0]
        except Exception:
            continue
    return None

TLS_SNI_KEY = {"trojan": "sni", "hysteria": "sni", "hysteria2": "sni", "tuic": "sni", "anytls": "sni",
               "vmess": "servername", "vless": "servername"}

def pin_servers(proxies, resolver=doh_a):
    pinned = failed = 0
    for p in proxies:
        host = str(p["server"])
        SENSITIVE.add(host)
        try:
            ipaddress.ip_address(host.strip("[]")); continue
        except ValueError:
            pass
        ip = resolver(host)
        if not ip:
            failed += 1; continue
        k = TLS_SNI_KEY.get(p.get("type"))
        if k and (p.get("type") not in ("vmess", "vless") or p.get("tls")) and not p.get(k):
            p[k] = host                       # keep TLS name after replacing server with IP
        if p.get("network") == "ws":
            wo = p.setdefault("ws-opts", {}); h = wo.setdefault("headers", {})
            h.setdefault("Host", host)
        p["server"] = ip; SENSITIVE.add(ip); pinned += 1
    return pinned, failed

def fetch_subscription(url: str) -> str:
    if url.startswith("file://"):               # used by tests
        with open(url[7:], encoding="utf-8") as f: return f.read()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"subscription fetch failed: HTTP {e.code}") from None
    except Exception as e:
        raise RuntimeError(f"subscription fetch failed: {type(e).__name__}") from None

def load_nodes(opts):
    text = fetch_subscription(opts["subscription_url"])
    proxies, st = parse_subscription(text)
    for p in proxies:
        for k in ("password", "uuid", "protocol-param", "obfs-param"):
            if p.get(k): SENSITIVE.add(str(p[k]))
    pinned, failed = pin_servers(proxies)
    log(f"subscription: format={st['format']} entries={st['total']} usable={len(proxies)} "
        f"placeholders_skipped={st['skipped_placeholder']} invalid_skipped={st['skipped_invalid']} "
        f"pinned={pinned} pin_failed={failed}")
    if not proxies:
        raise RuntimeError("no usable nodes in subscription")
    return proxies

# ---------------------------------------------------------------- config
CN_HINT = r"(?i)(回国|中国|国内|china|\bcn\b|大陆|mainland)"

def build_config(opts, dns_listen, upstream, provider_path, ctrl_secret):
    domains = [d.strip().lstrip(".+").lower() for d in opts.get("proxy_domains", []) if d.strip()]
    pref = (opts.get("preferred_node") or "").strip()
    test_url = "https://" + ("y.qq.com" if "qq.com" in domains else domains[0])
    check = {"enable": True, "url": test_url, "interval": 600, "timeout": 5000, "lazy": False}
    groups = [{"name": "AUTO", "type": "url-test", "use": [PROVIDER], "url": test_url,
               "interval": 600, "tolerance": 100, "filter": CN_HINT}]
    groups.append({"name": "AUTO-ANY", "type": "url-test", "use": [PROVIDER], "url": test_url,
                   "interval": 600, "tolerance": 100})
    members = ["AUTO", "AUTO-ANY"]
    if pref:
        groups.insert(0, {"name": "PREFERRED", "type": "url-test", "use": [PROVIDER], "url": test_url,
                          "interval": 600, "filter": "(?i)" + re.escape(pref)})
        members = ["PREFERRED"] + members
    groups.append({"name": "PROXY", "type": "fallback", "proxies": members, "url": test_url, "interval": 300})
    cfg = {
        "mode": "rule", "log-level": "warning", "ipv6": False, "allow-lan": False,
        "external-controller": CTRL, "secret": ctrl_secret,
        "profile": {"store-selected": False, "store-fake-ip": False},
        "proxy-providers": {PROVIDER: {"type": "file", "path": provider_path, "health-check": check}},
        "proxy-groups": groups,
        "dns": {"enable": True, "listen": dns_listen, "ipv6": False, "enhanced-mode": "fake-ip",
                "fake-ip-range": FAKE_RANGE, "fake-ip-filter-mode": "whitelist",
                "fake-ip-filter": ["+." + d for d in domains],
                "default-nameserver": upstream, "nameserver": upstream},
        "rules": [f"DOMAIN-SUFFIX,{d},PROXY" for d in domains] + ["MATCH,DIRECT"],
    }
    if TEST_NO_TUN:
        cfg["mixed-port"] = 17890; cfg["bind-address"] = "127.0.0.1"
        cfg["tun"] = {"enable": False}
    else:
        cfg["tun"] = {"enable": True, "device": DEV, "stack": "gvisor", "auto-route": False,
                      "auto-redirect": False, "auto-detect-interface": False, "strict-route": False,
                      "dns-hijack": []}
    return cfg

def write_atomic(path, text):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f: f.write(text)
    os.replace(tmp, path)

def write_provider(path, proxies):
    write_atomic(path, yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False))

# ---------------------------------------------------------------- supervisor
def sup(method, path, body=None):
    req = urllib.request.Request(SUP_URL + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {SUP_TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        j = json.load(r)
    if j.get("result") != "ok": raise RuntimeError(f"supervisor {path}: {j.get('message')}")
    return j.get("data") or {}

class DnsManager:
    """Points the HA DNS plugin at our resolver; remembers and restores the previous servers."""
    def __init__(self, ours):
        self.ours = f"dns://{ours.split(':')[0]}"; self.state = os.path.join(DATA, "dns_prev.json"); self.applied = False
    def repair_stale(self):
        servers = sup("GET", "/dns/info").get("servers", [])
        if self.ours in servers:
            prev = self._load() if os.path.exists(self.state) else [s for s in servers if s != self.ours]
            log("found our resolver left in DNS servers from an unclean stop; restoring previous servers")
            sup("POST", "/dns/options", {"servers": prev})
    def apply(self):
        servers = sup("GET", "/dns/info").get("servers", [])
        prev = [s for s in servers if s != self.ours]
        write_atomic(self.state, json.dumps(prev))
        sup("POST", "/dns/options", {"servers": [self.ours] + prev})
        self.applied = True
        log(f"DNS plugin now uses {self.ours} first (previous servers saved: {len(prev)})")
    def restore(self):
        if not self.applied and not os.path.exists(self.state): return
        try:
            prev = self._load()
            sup("POST", "/dns/options", {"servers": prev})
            os.remove(self.state); self.applied = False
            log(f"DNS plugin servers restored ({len(prev)} entries)")
        except Exception as e:
            log(f"WARNING: DNS restore failed: {type(e).__name__}; plugin fallback still applies")
    def _load(self):
        with open(self.state) as f: return json.load(f)

# ---------------------------------------------------------------- routing / guard
def sh(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()

def route_get(ip):
    out = sh("ip", "-4", "route", "get", ip)
    return out.splitlines()[0] if out else ""

class Baseline:
    def __init__(self):
        self.rules = sh("ip", "-4", "rule", "show")
        self.default = sh("ip", "-4", "route", "show", "default")
        m = re.search(r"via (\S+)", self.default); self.gw = m.group(1) if m else None
        self.p_inet = route_get("1.1.1.1"); self.p_gw = route_get(self.gw) if self.gw else ""
    def drift(self):
        if sh("ip", "-4", "rule", "show") != self.rules: return "ip rules changed"
        if sh("ip", "-4", "route", "show", "default") != self.default: return "default route changed"
        if route_get("1.1.1.1") != self.p_inet: return "internet path changed"
        if self.gw and route_get(self.gw) != self.p_gw: return "gateway path changed"
        if f"dev {DEV}" not in route_get("198.18.1.1"): return "198.18 route missing"
        return None

def preflight():
    if re.search(r"(^|\n)(local )?198\.1[89]\.", sh("ip", "-4", "route", "show", "table", "all")):
        raise RuntimeError("something already routes 198.18.0.0/15")
    if subprocess.run(["ip", "link", "show", DEV], capture_output=True).returncode == 0:
        raise RuntimeError(f"device {DEV} already exists")
    if "lookup 2022" in sh("ip", "-4", "rule", "show"):
        raise RuntimeError("leftover ip rule for table 2022 present; remove it first")

# ---------------------------------------------------------------- tiny DNS client (self-test)
def dns_a(server, name, timeout=3):
    host, _, port = server.partition(":")
    qid = secrets.randbits(16)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(q, (host, int(port or 53))); r, _ = s.recvfrom(2048)
    finally:
        s.close()
    an = struct.unpack(">H", r[6:8])[0]; i = len(q)
    out = []
    for _ in range(an):
        if r[i] & 0xC0 == 0xC0: i += 2
        else:
            while r[i]: i += r[i] + 1
            i += 1
        t, _, _, ln = struct.unpack(">HHIH", r[i:i + 10]); i += 10
        if t == 1: out.append(socket.inet_ntoa(r[i:i + 4]))
        i += ln
    return out

# ---------------------------------------------------------------- controller
def ctrl(method, path, secret_):
    req = urllib.request.Request(f"http://{CTRL}{path}", method=method, headers={"Authorization": f"Bearer {secret_}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        b = r.read()
    return json.loads(b) if b else {}

# ---------------------------------------------------------------- main
class App:
    def __init__(self):
        with open(OPTIONS, encoding="utf-8") as f: self.o = json.load(f)
        if not self.o.get("subscription_url"): raise SystemExit("[mihomo-qq] subscription_url is empty")
        SENSITIVE.add(self.o["subscription_url"])
        SENSITIVE.add(urllib.parse.urlsplit(self.o["subscription_url"]).hostname or "")
        self.proc = None; self.route = False; self.dns = None; self.stopping = False
        self.secret = secrets.token_hex(16)
        self.provider = os.path.join(DATA, "provider.yaml"); self.cfg = os.path.join(DATA, "config.yaml")

    def resolve_net(self):
        listen = (self.o.get("dns_listen") or "auto").strip()
        up = [x.strip() for x in (self.o.get("upstream_dns") or "").split(",") if x.strip()]
        if TEST_NO_TUN:
            sysns = re.findall(r"^nameserver\s+(\S+)", open("/etc/resolv.conf").read(), re.M)
            return "127.0.0.1:15353", up or sysns[:1] or ["1.1.1.1"]
        if listen == "auto":
            gw = sup("GET", "/network/info").get("docker", {}).get("gateway") if SUP_TOKEN else None
            listen = f"{gw or '172.30.32.1'}:53"
        if not up:
            locs = sup("GET", "/dns/info").get("locals", []) if SUP_TOKEN else []
            up = [l.replace("dns://", "") for l in locs if l.startswith("dns://")] or ["1.1.1.1"]
        return listen, up

    def teardown(self, why):
        if self.stopping: return
        self.stopping = True
        log(f"teardown: {why}")
        if self.dns: self.dns.restore()
        if self.route: subprocess.run(["ip", "-4", "route", "del", NET, "dev", DEV], capture_output=True)
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(5)
            except subprocess.TimeoutExpired: self.proc.kill()
        base = getattr(self, "base", None)
        if base:                                                    # belt and braces
            for line in sh("ip", "-4", "rule", "show").splitlines():
                if "lookup 2022" in line and line not in base.rules.splitlines():
                    subprocess.run(["ip", "-4", "rule", "del", "pref", line.split(":")[0]], capture_output=True)

    def pump_logs(self):
        for line in self.proc.stdout:
            print(redact(line.rstrip()), flush=True)

    def refresh_loop(self, hours):
        while not self.stopping:
            for _ in range(int(hours * 3600)):
                if self.stopping: return
                time.sleep(1)
            try:
                nodes = load_nodes(self.o)
                write_provider(self.provider, nodes)
                ctrl("PUT", f"/providers/proxies/{PROVIDER}", self.secret)
                log(f"subscription refreshed: {len(nodes)} nodes (existing connections kept)")
            except Exception as e:
                log(f"refresh failed, keeping previous nodes: {redact(str(e))}")

    def selected(self):
        chain, now = [], "PROXY"
        while now and len(chain) < 4:
            try:
                now = ctrl("GET", "/proxies/" + urllib.parse.quote(now), self.secret).get("now")
            except Exception:
                break                      # provider nodes are not exposed under /proxies/<name>
            if now: chain.append(now)
        return " -> ".join(chain) or "unknown"

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: (self.teardown("signal"), sys.exit(0)))
        signal.signal(signal.SIGINT, lambda *_: (self.teardown("signal"), sys.exit(0)))
        listen, up = self.resolve_net()
        if self.o.get("manage_dns", True) and not TEST_NO_TUN:
            self.dns = DnsManager(listen); self.dns.repair_stale(); self.dns.applied = False
        nodes = load_nodes(self.o)
        if not TEST_NO_TUN:
            preflight(); self.base = Baseline()
        write_provider(self.provider, nodes)
        write_atomic(self.cfg, yaml.safe_dump(build_config(self.o, listen, up, self.provider, self.secret),
                                              allow_unicode=True, sort_keys=False))
        t = subprocess.run([MIHOMO, "-t", "-d", DATA, "-f", self.cfg], capture_output=True, text=True)
        if t.returncode != 0:
            raise RuntimeError("mihomo config test failed: " + redact((t.stdout + t.stderr).strip().splitlines()[-1]))
        log("config test OK")
        self.proc = subprocess.Popen([MIHOMO, "-d", DATA, "-f", self.cfg], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=self.pump_logs, daemon=True).start()
        if not TEST_NO_TUN:
            for _ in range(30):
                if subprocess.run(["ip", "link", "show", DEV], capture_output=True).returncode == 0: break
                if self.proc.poll() is not None: raise RuntimeError("mihomo exited during start")
                time.sleep(1)
            else:
                raise RuntimeError("TUN device never appeared")
            subprocess.run(["ip", "link", "set", DEV, "up"], capture_output=True)
            if subprocess.run(["ip", "-4", "route", "replace", NET, "dev", DEV]).returncode != 0:
                raise RuntimeError("route add failed")
            self.route = True
            if f"dev {DEV}" not in route_get("198.18.1.1"): raise RuntimeError("route check failed")
            log(f"route OK: {NET} -> {DEV}")
        # resolver self-test before touching HA DNS
        d0 = [d for d in self.o["proxy_domains"] if d.strip()][0].lstrip(".+")
        for _ in range(10):
            try:
                fake = dns_a(listen, "y." + d0 if d0 == "qq.com" else d0); real = dns_a(listen, "github.com"); break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("resolver self-test: no answer")
        if not any(a.startswith("198.18.") for a in fake):
            raise RuntimeError(f"resolver self-test failed: proxied domain got {len(fake)} answers, none fake-ip")
        if any(a.startswith("198.18.") for a in real):
            raise RuntimeError("resolver self-test failed: non-proxied domain got a fake-ip")
        if not real:
            log("WARNING: upstream DNS gave no answer for github.com (check upstream_dns)")
        log("resolver self-test OK (proxied domain -> fake-ip, other domains -> real)")
        if self.dns: self.dns.apply()
        threading.Thread(target=lambda: (time.sleep(20), log(f"selected path: {self.selected()}")), daemon=True).start()
        keep = bool(self.o.get("keep")); trial = int(self.o.get("trial_minutes", 15))
        log("keep=true: running until stopped" if keep else f"TRIAL mode: auto-stop in {trial} min unless keep=true")
        if float(self.o.get("refresh_hours", 6) or 0) > 0:
            threading.Thread(target=self.refresh_loop, args=(float(self.o["refresh_hours"]),), daemon=True).start()
        deadline = time.time() + trial * 60
        while True:
            time.sleep(5)
            if self.proc.poll() is not None: self.teardown("mihomo exited"); sys.exit(1)
            if not TEST_NO_TUN:
                why = self.base.drift()
                if why: self.teardown(f"guard tripped: {why}"); sys.exit(1)
            if not keep and time.time() >= deadline:
                self.teardown("trial expired"); sys.exit(0)

if __name__ == "__main__":
    app = None
    try:
        app = App(); app.run()
    except SystemExit:
        raise
    except Exception as e:
        log(f"ERROR: {redact(str(e))}")
        if app: app.teardown("startup error")
        sys.exit(1)
