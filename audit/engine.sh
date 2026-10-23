#!/usr/bin/env bash
# Runs the real engine headless and checks connect time, chosen server,
# WARP, Iranian sites going direct and sharing to a second device.
set -u
D=/tmp/data; mkdir -p $D
/tmp/app/albatross -headless -data $D > /tmp/url.txt 2>/tmp/app.err &
for i in $(seq 1 30); do grep -q http /tmp/url.txt && break; sleep 1; done
URL=$(grep -m1 http /tmp/url.txt); BASE=${URL%%/#*}; TOK=${URL##*#}
api() { curl -s -m 20 -H "X-Token: $TOK" -H 'Content-Type: application/json' -X "$1" "$BASE$2" ${3:+-d "$3"}; }
api POST /api/settings '{"allow_lan":true}' >/dev/null
T0=$(date +%s)
api POST /api/connect '{}' >/dev/null
for i in $(seq 1 120); do
  st=$(api GET /api/state); [ "$(echo "$st" | jq -r .status)" = connected ] && break; sleep 2
done
T1=$(date +%s)
echo "RESULT connect_seconds=$((T1-T0)) status=$(echo "$st" | jq -r .status)"
echo "RESULT conn=$(echo "$st" | jq -c .conn)"
echo "RESULT countries=$(echo "$st" | jq -c '[.countries[]|{code,servers,best_delay}]')"
PORT=$(echo "$st" | jq -r '.settings.proxy_port // 10808'); P=http://127.0.0.1:$PORT
echo "RESULT exit_via_proxy=$(curl -s -m 15 -x $P https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc|warp)=' | tr '\n' ' ')"
echo "RESULT runner_ip=$(curl -s -m 10 https://www.cloudflare.com/cdn-cgi/trace | grep '^ip=')"
# Second client: a container on the docker bridge uses the shared port.
HOST=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
echo "RESULT lan_client=$(docker run --rm curlimages/curl:8.10.1 -s -m 20 -x http://$HOST:$PORT https://www.cloudflare.com/cdn-cgi/trace 2>&1 | grep -E '^(ip|loc)=|rror' | tr '\n' ' ')"
# Which outbound each site takes, from the core's own connection list.
CFG=$(grep -rl clash_api $D 2>/dev/null | head -1)
CTL=$(jq -r '.experimental.clash_api.external_controller' "$CFG"); SEC=$(jq -r '.experimental.clash_api.secret' "$CFG")
echo "config=$CFG controller=$CTL"
for h in digikala.com aparat.com snapp.ir bmi.ir www.bankmellat.ir sep.shaparak.ir divar.ir google.com; do
  curl -s -o /dev/null -m 12 --limit-rate 3k -x $P "https://$h/" & pid=$!
  sleep 3
  c=$(curl -s -m 5 -H "Authorization: Bearer $SEC" "http://$CTL/connections" | jq -c --arg h "$h" '[.connections[]?|select(.metadata.host==$h)|.chains]|unique')
  wait $pid
  echo "RESULT route $h -> $c"
done
sleep 150
echo "== logs"; api GET /api/logs | jq -r '.[]|"\(.time[11:19]) \(.level) \(.text)"' | tail -80
echo "RESULT final_conn=$(api GET /api/state | jq -c .conn)"
