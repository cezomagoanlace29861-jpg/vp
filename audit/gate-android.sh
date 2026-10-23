#!/usr/bin/env bash
# Release gate, Android part (emulator): upgrade paths and a clean start.
set -u
F=0; ok() { echo "GATE PASS $*"; }; bad() { echo "GATE FAIL $*"; F=1; }
r=$(adb install /tmp/0.3.2.apk 2>&1 | tail -1); [ "$r" = Success ] && ok "0.3.2 installs" || bad "0.3.2 install: $r"
r=$(adb install -r -d /tmp/cand.apk 2>&1 | tail -1); [ "$r" = Success ] && ok "candidate installs over 0.3.2 (same key)" || bad "candidate over 0.3.2: $r"
adb shell monkey -p app.albatross.vpn -c android.intent.category.LAUNCHER 1 >/dev/null; sleep 15
adb shell pidof app.albatross.vpn >/dev/null && ok "candidate starts and stays up 15 s" || bad "candidate not running after launch"
adb logcat -d | grep -E "FATAL EXCEPTION" | head -5 | sed 's/^/GATE FAIL crash: /' | tee /tmp/crash; [ -s /tmp/crash ] && F=1
v=$(adb shell dumpsys package app.albatross.vpn | grep -m1 versionName | tr -d ' \r'); echo "installed $v"
adb shell pm list permissions -g >/dev/null; adb shell dumpsys package app.albatross.vpn | grep -q "android.permission.REQUEST_INSTALL_PACKAGES" && ok "candidate can open the in-app installer (REQUEST_INSTALL_PACKAGES)" || bad "candidate lacks REQUEST_INSTALL_PACKAGES: in-app updates cannot install"
adb shell dumpsys package app.albatross.vpn | grep -q "app.albatross.vpn.apk" && ok "update FileProvider authority registered" || bad "ApkProvider authority missing"
adb uninstall app.albatross.vpn >/dev/null
r=$(adb install /tmp/cand.apk 2>&1 | tail -1); [ "$r" = Success ] && ok "candidate fresh install" || bad "fresh install: $r"
adb shell monkey -p app.albatross.vpn -c android.intent.category.LAUNCHER 1 >/dev/null; sleep 10
adb shell pidof app.albatross.vpn >/dev/null && ok "fresh install starts" || bad "fresh install not running"
adb logcat -d | grep -E "FATAL EXCEPTION" | head -3 | sed 's/^/GATE FAIL crash: /' | tee /tmp/crash2; [ -s /tmp/crash2 ] && F=1
exit $F
