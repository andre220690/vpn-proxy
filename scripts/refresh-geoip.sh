#!/usr/bin/env bash
set -euo pipefail
set -o noclobber
DST=/etc/sing-box/rules/ru.srs
TMP=$(mktemp /etc/sing-box/rules/.ru.XXXXXXXX.srs)
trap 'rm -f "$TMP"' EXIT
curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 \
  https://raw.githubusercontent.com/Loyalsoldier/geoip/release/srs/ru.srs -o "$TMP"
test "$(wc -c < "$TMP")" -gt 1024
chmod 644 "$TMP"
mv -f "$TMP" "$DST"
