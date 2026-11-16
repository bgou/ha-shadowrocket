#!/bin/sh
# Runs INSIDE `unshare -rn`. Usage: netns_test.sh <scenario: trial|guard|sigterm|stale>
set -u
SC=$1; H=$(dirname "$0"); T=$(mktemp -d); chmod 700 $T
ip link set lo up
cat > $T/sub.yaml <<Y
proxies:
  - {name: "服务到期日：2026-12-16", type: trojan, server: 192.0.2.1, port: 443, password: x}
  - {name: "测试_回国", type: ss, server: 192.0.2.10, port: 8388, cipher: aes-256-gcm, password: testpw}
Y
DN=$(test "$SC" = stale && echo '["dns://127.0.0.2","dns://9.9.9.9"]' || echo '["dns://9.9.9.9"]')
echo "{\"servers\": $DN}" > $T/state.json
[ "$SC" = stale ] && echo '["dns://9.9.9.9"]' > $T/dns_prev.json
MOCK_STATE=$T/state.json python3 $H/mock_supervisor.py & MP=$!
TRIAL=$(test "$SC" = trial && echo 1 || echo 10)
cat > $T/options.json <<O
{"subscription_url":"file://$T/sub.yaml","proxy_domains":["qq.com","gtimg.cn"],"preferred_node":"","refresh_hours":0,
 "trial_minutes":$TRIAL,"keep":false,"manage_dns":true,"dns_listen":"auto","upstream_dns":""}
O
sleep 1
MQ_DATA=$T SUPERVISOR_URL=http://127.0.0.1:8099 SUPERVISOR_TOKEN=testtoken MIHOMO_BIN=/workspace/qqproxy/mihomo \
  python3 -u $H/../mihomo-qq/rootfs/run.py > $T/out.log 2>&1 & P=$!
sleep 8
echo "-- during run: routes: $(ip -4 route | grep -c 198.18) x198.18 | rules: $(ip -4 rule | wc -l) | DNS servers: $(python3 -c "import json;print(json.load(open('$T/state.json'))['servers'])")"
echo "-- route get 198.18.7.7: $(ip -4 route get 198.18.7.7 | head -1 | awk '{print $2,$3}')"
case $SC in
  guard) ip rule add pref 9000 from all lookup 2022 ;;
  sigterm|stale) kill -TERM $P ;;
esac
wait $P; RC=$?
grep "\[mihomo-qq\]" $T/out.log | sed 's/^/   /'
echo "-- exit=$RC | after: routes198=$(ip -4 route | grep -c 198.18) dev=$(ip link show mihomo-qq >/dev/null 2>&1 && echo present || echo gone) rules=$(ip -4 rule | wc -l) dns_prev=$(test -e $T/dns_prev.json && echo present || echo removed)"
echo "-- DNS history: $(python3 -c "import json;print(json.load(open('$T/state.json')).get('history'))") final: $(python3 -c "import json;print(json.load(open('$T/state.json'))['servers'])")"
kill $MP; rm -rf $T
