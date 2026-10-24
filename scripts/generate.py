#!/usr/bin/env python3
"""Generate nftables rules for scoped Docker traffic interception."""
import argparse
import ipaddress
import sys
from pathlib import Path
from core import nft_text
import json
p=argparse.ArgumentParser()
p.add_argument('--nft',required=True,help='IPv4 of Russian VPS to exclude')
a=p.parse_args()
try:
    addr=ipaddress.ip_address(a.nft)
    if addr.version != 4:raise ValueError()
    state=json.loads(Path('/var/lib/vpn-proxy/state.json').read_text())
    target=Path('/etc/vpn-proxy/tproxy.nft')
    target.write_text(nft_text(state,str(addr)))
    target.chmod(0o600)
except (ValueError,OSError) as ex:
    sys.exit('Ошибка nft генерации: '+str(ex))
