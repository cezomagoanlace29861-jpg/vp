#!/usr/bin/env bash
# Release gate, engine part. Prints GATE PASS/FAIL lines; exits 1 on any FAIL.
set -u
F=0; ok() { echo "GATE PASS $*"; }; bad() { echo "GATE FAIL $*"; F=1; }
D=/tmp/gdata; mkdir -p $D
start() { /tmp/app/albatross -headless -data $D > /tmp/url.txt 2>>/tmp/app.err & PID=$!
  for i in $(seq 1 30); do grep -q http /tmp/url.txt && break; sleep 1; done
  URL=$(grep -m1 http /tmp/url.txt); BASE=${URL%%/#*}; TOK=${URL##*#}; }
api() { curl -s -m 20 -H "X-Token: $TOK" -H 'Content-Type: application/json' -X "$1" "$BASE$2" ${3:+-d "$3"}; }
start
st=$(api GET /api/state)
for k in status settings countries help_available helping crowd_available version; do
  echo "$st" | jq -e "has(\"$k\")" >/dev/null && ok "state has $k" || bad "state lacks $k"; done
for k in allow_lan help_others share_stats; do echo "$st" | jq -e ".settings|has(\"$k\")" >/dev/null && ok "settings has $k" || bad "settings lacks $k"; done
for v in true false true; do r=$(api POST /api/settings "{\"allow_lan\":$v,\"share_stats\":$v}")
  [ "$(echo "$r" | jq -r .allow_lan)/$(echo "$r" | jq -r .share_stats)" = "$v/$v" ] && ok "toggle allow_lan+share_stats=$v round-trips" || bad "toggle =$v returned $r"; done
T0=$(date +%s); api POST /api/connect '{}' >/dev/null
for i in $(seq 1 60); do st=$(api GET /api/state); [ "$(echo "$st" | jq -r .status)" = connected ] && break; sleep 2; done
dt=$(( $(date +%s)-T0 )); d=$(echo "$st" | jq -r '.conn.delay // 0')
[ "$(echo "$st" | jq -r .status)" = connected ] && ok "connected in ${dt}s, ${d} ms" || bad "not connected after ${dt}s: $(echo "$st" | jq -r .message)"
[ "$d" -gt 0 ] && [ "$d" -lt 1500 ] && ok "chosen server delay ${d} ms < 1500" || bad "chosen server delay ${d} ms"
PORT=$(echo "$st" | jq -r '.settings.proxy_port // 10808'); P=http://127.0.0.1:$PORT
ip=$(curl -s -m 15 -x $P https://www.cloudflare.com/cdn-cgi/trace | grep '^ip='); me=$(curl -s -m 10 https://www.cloudflare.com/cdn-cgi/trace | grep '^ip=')
[ -n "$ip" ] && [ "$ip" != "$me" ] && ok "traffic exits elsewhere ($ip)" || bad "exit ip '$ip' vs runner '$me'"
# Sharing: addresses, a second client, PAC.
sh=$(echo "$st" | jq -r '.share // [] | join(",")'); pac=$(echo "$st" | jq -r '.share_pac // [] | .[0] // ""')
echo "$sh" | grep -q ":$PORT" && ok "share lists $sh" || bad "share list '$sh'"
echo "$sh" | grep -q "172.17.0.1" && bad "share lists the docker bridge" || ok "share has no docker bridge"
H=$(hostname -I | awk '{print $1}')
r=$(docker run --rm curlimages/curl:8.10.1 -s -m 20 -x http://$H:$PORT https://www.cloudflare.com/cdn-cgi/trace | grep '^ip=')
[ "$r" = "$ip" ] && ok "second device through $H:$PORT exits at $r" || bad "second device got '$r'"
if [ -n "$pac" ]; then body=$(docker run --rm curlimages/curl:8.10.1 -s -m 10 "${pac/127.0.0.1/$H}")
  echo "$body" | grep -q "PROXY" && ok "PAC served at $pac" || bad "PAC body: $body"
  echo "$body" | grep -q "isInNet\|dnsResolve" && bad "PAC resolves names" || ok "PAC never resolves names"
else bad "no share_pac"; fi
# Routing: Iranian sites direct, others through the server.
CFG=$(grep -rl clash_api $D | head -1); CTL=$(jq -r .experimental.clash_api.external_controller "$CFG"); SEC=$(jq -r .experimental.clash_api.secret "$CFG")
route() { curl -s -o /dev/null -m 10 --limit-rate 100 -x $P "https://$1/" & local p=$! s=""
  for k in 1 2 3 4 5 6 7 8; do sleep 0.5; s="$s $(curl -s -m 3 -H "Authorization: Bearer $SEC" "http://$CTL/connections" | jq -r --arg h "$1" '.connections[]?|select(.metadata.host==$h)|.chains[0]')"; done
  wait $p; echo $s | tr ' ' '\n' | sort -u | tr '\n' ' '; }
for h in digikala.com snapp.ir bmi.ir divar.ir www.bankmellat.ir; do r=$(route $h); echo "$r" | grep -qw direct && ok "$h direct" || bad "$h went '$r'"; done
for h in www.google.com www.youtube.com; do r=$(route $h); [ -n "$r" ] && ! echo "$r" | grep -qw direct && ok "$h via $r" || bad "$h went '$r'"; done
# Disconnect, reconnect, restart keeps settings.
api POST /api/disconnect >/dev/null; sleep 4; st=$(api GET /api/state)
[ "$(echo "$st" | jq -r .status)" = idle ] && ok "disconnect -> idle" || bad "after disconnect status=$(echo "$st" | jq -r .status)"
curl -s -m 5 -x $P https://www.cloudflare.com/cdn-cgi/trace >/dev/null && bad "proxy port still answers after disconnect" || ok "proxy port closed after disconnect"
api POST /api/connect '{}' >/dev/null
for i in $(seq 1 45); do [ "$(api GET /api/state | jq -r .status)" = connected ] && break; sleep 2; done
[ "$(api GET /api/state | jq -r .status)" = connected ] && ok "reconnects after disconnect" || bad "no reconnect"
kill $PID; sleep 3; pgrep -f "sing-box|xray|warp-plus" >/dev/null && bad "cores left running after the app quit: $(pgrep -fl 'sing-box|xray|warp-plus' | tr '\n' ' ')" || ok "no cores left after quit"
start; [ "$(api GET /api/state | jq -r .settings.allow_lan)" = true ] && ok "settings survive a restart" || bad "allow_lan lost on restart"
api GET /api/logs | jq -r '.[]|select(.level=="error")|.text' | head -5 | sed 's/^/GATE FAIL error log: /' | tee /tmp/errs; [ -s /tmp/errs ] && F=1
kill $PID 2>/dev/null; grep -i "panic" /tmp/app.err && bad "panic in stderr"
exit $F
