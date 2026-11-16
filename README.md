# ha-mihomo-qq

Home Assistant add-on repository. It contains one add-on, **mihomo QQ Domain Proxy**. The add-on sends only a short list of domains (QQ Music / Tencent by default) through a proxy node from your Clash or SS/SSR/trojan/vmess subscription. All other traffic on the host stays untouched.

The use case is Music Assistant's QQ Music provider used from outside mainland China with a "回国" (China-return) node.

## Install

1. Settings → Add-ons → Add-on Store → ⋮ → Repositories → add `https://github.com/bgou/ha-shadowrocket`.
2. Install **mihomo QQ Domain Proxy**, paste your subscription URL, and start it. It starts in a 15-minute trial by default.
3. Check that QQ Music plays. Then set `keep: true`, restart the add-on, and turn on "Start on boot".

See [mihomo-qq/DOCS.md](mihomo-qq/DOCS.md) for the options and the safety design.

License: MIT.
