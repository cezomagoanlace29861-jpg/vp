#!/usr/bin/env bash
# Release APKs on an emulator: update over 0.3.0, connect and disconnect
# by tapping the real UI, check the VPN is really gone afterwards.
set -u
echo "RESULT install: $(adb install /tmp/pr.apk 2>&1 | tail -1)"
adb shell appops set app.albatross.vpn ACTIVATE_VPN allow
adb shell pm grant app.albatross.vpn android.permission.POST_NOTIFICATIONS 2>/dev/null
vpn() { adb shell dumpsys connectivity | grep -c "VPN CONNECTED\|Transports: VPN"; }
tap() {
  for i in $(seq 1 10); do
    adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1
    b=$(adb shell cat /sdcard/ui.xml | grep -o "content-desc=\"$1\"[^>]*bounds=\"[^\"]*\"" | grep -o 'bounds="[^"]*"' | head -1 | grep -o '[0-9]*')
    if [ -n "$b" ]; then set -- $b; adb shell input tap $(( ($1+$3)/2 )) $(( ($2+$4)/2 )); return 0; fi
    sleep 3
  done
  echo "no element $1"; adb shell cat /sdcard/ui.xml | head -c 3000; return 1
}
adb logcat -c
adb shell monkey -p app.albatross.vpn -c android.intent.category.LAUNCHER 1 >/dev/null
sleep 10
echo "RESULT vpn_before=$(vpn)"
T0=$(date +%s); tap Connect
for i in $(seq 1 90); do [ "$(vpn)" -gt 0 ] && break; sleep 2; done
echo "RESULT vpn_up_after=$(( $(date +%s)-T0 ))s vpn=$(vpn)"
sleep 60
echo "RESULT vpn_still_up=$(vpn)"
adb shell ip addr | grep -A2 tun | head -4
tap Disconnect; sleep 6
echo "RESULT vpn_after_disconnect=$(vpn)"; adb shell ip link | grep -c tun | sed 's/^/RESULT tun_ifaces_after=/'
sleep 30; echo "RESULT vpn_30s_later=$(vpn)"
adb shell dumpsys activity services app.albatross.vpn | grep -m2 "ServiceRecord" | sed 's/^/RESULT service: /'
adb logcat -d | grep -i "albatross\|GoLog" | tail -40
