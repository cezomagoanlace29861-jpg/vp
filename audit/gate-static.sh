#!/usr/bin/env bash
# Release gate, code part. Run from a checkout of the code under test, with
# the gate checkout at $G. Each line names the earlier bug it guards: [B1]..[B11].
set -u
G=${G:-gate}; F=0; ok() { echo "GATE PASS $*"; }; bad() { echo "GATE FAIL $*"; F=1; }
python3 - <<'PY' || F=1
import json
m=json.load(open("update.json")); v=lambda s: tuple(int(x) for x in s.split("."))
ok=lambda c,t: print(("GATE PASS " if c else "GATE FAIL ")+t) or c
f=m.get("files",{})
r=[ok(v(m["min_version"])<=v("0.3.0"),"[B1] min_version %s keeps 0.3.0 and 0.3.1 connecting"%m["min_version"]),
   ok("android-arm64-v8a" in f,"[B1] update.json has the android-arm64-v8a entry 0.3.2 reads"),
   ok(all(len(x["sha256"])==64 and x["urls"] and all(u.startswith("https://") for u in x["urls"]) for x in f.values()),"[B1] file entries well formed")]
raise SystemExit(0 if all(r) else 1)
PY
cp $G/audit/gate_ui_test.go internal/ui/; cp $G/audit/gate_pac_test.go internal/engine/
o=$(go test ./internal/ui -run TestGateUIContract -count=1 2>&1); [ $? = 0 ] && ok "[B2][B3] every state key and setting the page reads is sent (allow_lan, help_others, share_stats, notice, help/crowd rows)" || { bad "[B2][B3] UI contract:"; echo "$o" | grep gate_ui | sed 's/^/    /'; }
o=$(go test ./internal/engine -run TestGatePACNeverResolves -count=1 2>&1); [ $? = 0 ] && ok "[B4] PAC run in node with an Iran-style resolver: blocked sites go PROXY, LAN DIRECT, no name ever resolved" || { bad "[B4] PAC:"; echo "$o" | grep -E "PAC|undefined" | head -3 | sed 's/^/    /'; }
rm -f internal/engine/gate_pac_test.go; cp $G/audit/gate_update_test.go internal/engine/
o=$(go test ./internal/engine -run 'TestGateRequire|TestGateResumeWithoutRangeSupport|TestUpdateResumes|TestGateForcedUpdateNeverStrands' -count=1 -v 2>&1)
for t in TestGateRequire TestGateResumeWithoutRangeSupport TestUpdateResumes; do echo "$o" | grep -q -- "--- PASS: $t" && ok "[B7][B1] $t" || bad "[B7][B1] $t: $(echo "$o" | grep -E "$t|undefined" | head -2 | tr '\n' ' ')"; done
echo "$o" | grep -q -- "--- PASS: TestGateForcedUpdateNeverStrands" && ok "[N1] a forced update whose download fails leaves the user able to connect" || bad "[N1] a forced update whose download fails disconnects the user and blocks Connect; the retry can then only go direct (filtered in Iran)"
rm -f internal/ui/gate_ui_test.go internal/engine/gate_*_test.go
A=android/app/src/main/java/app/albatross/vpn
grep -qE 'static (volatile )?File ' $A/ApkProvider.java && bad "[B5] ApkProvider keeps the update file in a static field (lost when Android restarts the app)" || ok "[B5] ApkProvider has no static File"
grep -q getSharedPreferences $A/ApkProvider.java && ok "[B5] ApkProvider reads the update path from storage" || bad "[B5] ApkProvider does not persist the update path"
grep -q armeabi-v7a .github/workflows/build.yml && ok "[B6] build makes a 32-bit ARM APK" || echo "GATE NOTE [B6] known limitation (user asked to drop 32-bit): no armeabi-v7a APK"
GOARCH=arm go vet ./internal/engine >/dev/null 2>&1; k=$(cd internal/engine && awk '/^func updateKey/,/^}/' update.go); echo "$k" | grep -q 'GOARCH == "amd64"' && echo "$k" | grep -B1 -A0 'return "android-arm64-v8a"' | grep -q '^\s*}$\|^\s*return "android-x86_64"' && bad "[B6] updateKey sends 32-bit phones the arm64 APK" || ok "[B6] updateKey does not send 32-bit phones the arm64 APK"
grep -q 'm\["message"\] = os.environ.get("MESSAGE", "")' .github/workflows/build.yml && bad "[N2] a release without a message erases update.json's message (the uninstall-once note 0.3.0/0.3.1 users need)" || ok "[N2] a release keeps the update message"
grep -q 'R.string.connecting' $A/TunnelService.java && ok "[B9] notification shows Connecting until connected" || bad "[B9] notification says Connected while still searching"
grep -q 'lastProxySet' internal/engine/engine.go && ok "[B10] start undoes a crashed run's proxy at its old port (Windows test checks it live)" || bad "[B10] stale proxy at an old port is never cleared"
for w in .github/workflows/*.yml; do n=$(basename $w .yml); case $n in build|collect|hot|codeql|osv-scanner|delete-releases|deploy-backend|stale|summary|gate|dependabot*) ;; *) bad "[B11] unexpected workflow $n";; esac; done
python3 $G/audit/gate_persian.py internal/ui android/app/src/main/res android/app/src/main/java && ok "no Persian text in UI or Android sources" || bad "Persian text in the app (files above)"
go vet ./... >/tmp/vet 2>&1 && ok "go vet" || { bad "go vet"; head -5 /tmp/vet; }
go test ./... -count=1 >/tmp/t 2>&1 && ok "go test ./... ($(grep -c '^ok' /tmp/t) packages)" || { bad "go test"; grep -E "^(FAIL|---)" /tmp/t | head; }
exit $F
