#!/usr/bin/env bash
set -euo pipefail
NFT=/etc/vpn-proxy/tproxy.nft
# Only modify our dedicated nftables table, never flush global firewall rules.
if nft list table ip vpn_proxy >/dev/null 2>&1; then
  # Already active. Do not duplicate a base chain on a second activation.
  nft list table ip6 vpn_proxy6 >/dev/null 2>&1 || { echo 'Incomplete TProxy tables: manual intervention required' >&2; exit 1; }
  nft list table inet vpn_proxy_input >/dev/null 2>&1 || { echo 'Missing input firewall table' >&2; exit 1; }
else
  nft -c -f "$NFT"
  nft -f "$NFT"
fi
if ! ip -4 rule show | grep -q '^10000:.*fwmark 0x64.*lookup 100'; then
  ip -4 rule add pref 10000 fwmark 100 lookup 100
fi
ip -4 route replace local 0.0.0.0/0 dev lo table 100
