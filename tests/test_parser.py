import base64, json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mihomo-qq", "rootfs"))
import run as R

b64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

SS_SIP002 = f"ss://{b64('aes-256-gcm:pw1')}@ss.example.com:8388#HK%20SS"
SS_LEGACY = f"ss://{b64('chacha20-ietf-poly1305:pw2@203.0.113.5:443')}#Legacy"
SS_OBFS = f"ss://{b64('aes-128-gcm:pw3')}@198.51.100.7:80/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.org#Obfs"
SSR = "ssr://" + b64("ssr.example.net:1234:auth_aes128_md5:rc4-md5:plain:" + b64("pw4") +
                    "/?obfsparam=" + b64("obf.example") + "&protoparam=" + b64("1:abc") + "&remarks=" + b64("港广专线_回国"))
TROJAN = "trojan://pw5@tj.example.com:443?sni=cdn.example.com&type=ws&path=%2Fws&host=cdn.example.com#JP%20Trojan"
VMESS = "vmess://" + base64.b64encode(json.dumps({"v": "2", "ps": "US vmess", "add": "vm.example.com", "port": "443",
        "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "net": "ws", "path": "/v", "host": "", "tls": "tls"}).encode()).decode()
PLACEHOLDER = f"trojan://x@127.0.0.1:1#{'服务到期日：2026-12-16'}"
PLACEHOLDER2 = f"ss://{b64('aes-256-gcm:x')}@1.2.3.4:443#剩余流量：100GB"
JUNK = "vless://whatever"

class T(unittest.TestCase):
    def test_uri_list_base64(self):
        body = "\n".join([SS_SIP002, SS_LEGACY, SS_OBFS, SSR, TROJAN, VMESS, PLACEHOLDER, PLACEHOLDER2, JUNK])
        px, st = R.parse_subscription(base64.b64encode(body.encode()).decode())
        names = [p["name"] for p in px]
        self.assertEqual(st["format"], "uri-list")
        self.assertEqual(names, ["HK SS", "Legacy", "Obfs", "港广专线_回国", "JP Trojan", "US vmess"])
        self.assertEqual(st["skipped_placeholder"], 2); self.assertEqual(st["skipped_invalid"], 1)
        d = {p["name"]: p for p in px}
        self.assertEqual((d["HK SS"]["cipher"], d["HK SS"]["password"], d["HK SS"]["port"]), ("aes-256-gcm", "pw1", 8388))
        self.assertEqual(d["Legacy"]["server"], "203.0.113.5")
        self.assertEqual(d["Obfs"]["plugin-opts"], {"mode": "http", "host": "example.org"})
        s = d["港广专线_回国"]
        self.assertEqual((s["protocol"], s["cipher"], s["obfs"], s["password"], s["obfs-param"], s["protocol-param"]),
                         ("auth_aes128_md5", "rc4-md5", "plain", "pw4", "obf.example", "1:abc"))
        t = d["JP Trojan"]; self.assertEqual((t["sni"], t["network"], t["ws-opts"]["path"]), ("cdn.example.com", "ws", "/ws"))
        v = d["US vmess"]; self.assertTrue(v["tls"]); self.assertEqual(v["uuid"][:8], "11111111")

    def test_plain_uri_list(self):
        px, st = R.parse_subscription(SSR + "\n" + TROJAN + "\n")
        self.assertEqual(len(px), 2)

    def test_clash_yaml_and_dupes(self):
        y = """proxies:
  - {name: "服务到期日：2026-12-16", type: trojan, server: 1.2.3.4, port: 443, password: x}
  - {name: A, type: ss, server: a.example.com, port: 1, cipher: aes-256-gcm, password: p}
  - {name: B, type: ss, server: b.example.com, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: B, type: ss, server: c.example.com, port: 8388, cipher: aes-256-gcm, password: p}
"""
        px, st = R.parse_subscription(y)
        self.assertEqual(st["format"], "clash-yaml")
        self.assertEqual([p["name"] for p in px], ["B", "B (2)"])
        self.assertEqual((st["skipped_placeholder"], st["skipped_invalid"]), (1, 1))

    def test_pin_sets_sni(self):
        px, _ = R.parse_subscription(TROJAN + "\n" + VMESS + "\n" + SSR)
        tj = {"name": "t2", "type": "trojan", "server": "only.example.com", "port": 443, "password": "x"}
        px.append(tj)
        pinned, failed = R.pin_servers(px, resolver=lambda h: "192.0.2.10")
        self.assertEqual((pinned, failed), (4, 0))
        self.assertTrue(all(p["server"] == "192.0.2.10" for p in px))
        self.assertEqual(tj["sni"], "only.example.com")                 # TLS name preserved
        vm = [p for p in px if p["type"] == "vmess"][0]
        self.assertEqual(vm["servername"], "vm.example.com"); self.assertEqual(vm["ws-opts"]["headers"]["Host"], "vm.example.com")
        self.assertNotIn("sni", [p for p in px if p["type"] == "ssr"][0])

    def test_redact(self):
        R.SENSITIVE.add("secret.example.com")
        self.assertEqual(R.redact("dial secret.example.com 1.2.3.4:443 failed"), "dial <redacted> <ip> failed")

    def test_garbage(self):
        with self.assertRaises(ValueError): R.parse_subscription("%%% not base64 at all %%%")

    def test_build_config(self):
        cfg = R.build_config({"proxy_domains": ["qq.com", ".gtimg.cn"], "preferred_node": "港广"}, "172.30.32.1:53",
                             ["192.168.2.1"], "/data/provider.yaml", "s")
        self.assertEqual(cfg["dns"]["fake-ip-filter"], ["+.qq.com", "+.gtimg.cn"])
        self.assertEqual(cfg["dns"]["fake-ip-filter-mode"], "whitelist")
        self.assertFalse(cfg["tun"]["auto-route"]); self.assertFalse(cfg["tun"]["auto-detect-interface"])
        self.assertNotIn("route-address", cfg["tun"])
        self.assertEqual(cfg["rules"][-1], "MATCH,DIRECT")
        self.assertEqual([g["name"] for g in cfg["proxy-groups"]], ["PREFERRED", "AUTO", "AUTO-ANY", "PROXY"])
        self.assertEqual(cfg["proxy-groups"][-1]["proxies"], ["PREFERRED", "AUTO", "AUTO-ANY"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
