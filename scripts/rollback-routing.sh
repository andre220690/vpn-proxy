#!/usr/bin/env bash
set -euo pipefail
# Emergency path: disables only transparent interception. Existing RU VPN remains running.
nft delete table ip vpn_proxy 2>/dev/null || true
nft delete table ip6 vpn_proxy6 2>/dev/null || true
nft delete table inet vpn_proxy_input 2>/dev/null || true
ip -4 rule del pref 10000 2>/dev/null || true
ip -4 route flush table 100 2>/dev/null || true
