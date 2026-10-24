#!/usr/bin/env bash
set -Eeuo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEST=/opt/vpn-proxy
export DEBIAN_FRONTEND=noninteractive
[[ $EUID -eq 0 ]] || { echo 'Требуется sudo/root' >&2; exit 1; }

say(){ printf '[VPN Proxy] %s\n' "$*"; }
require_clean(){
  [[ ! -e /var/lib/vpn-proxy/state.json && ! -e /etc/sing-box/config.json && ! -e /etc/vpn-proxy/tproxy.nft ]] || {
    echo 'Остановка: обнаружена существующая маршрутизация. Нельзя устанавливать поверх работающего RU VPS.' >&2; exit 2;
  }
}

prepare(){
  require_clean
  . /etc/os-release
  [[ $ID == ubuntu && ( $VERSION_ID == '24.04' || $VERSION_ID == '26.04' ) ]] || { echo 'Поддерживается только Ubuntu 24.04/26.04'; exit 1; }
  [[ $(uname -m) == x86_64 ]] || { echo 'Поддерживается только x86_64'; exit 1; }
  apt-get update
  apt-get install -y curl ca-certificates jq nftables iproute2 python3 git make gcc g++ pkg-config golang-go build-essential tar
  # Always install the pinned version for this new deployment.
  local version=1.14.4
  local tempdir
  tempdir=$(mktemp -d)
  curl -fsSL --retry 2 "https://dl.sing-box.org/releases/v${version}/sing-box-${version}-linux-amd64.tar.gz" -o "$tempdir/sb.tar.gz"
  tar -xzf "$tempdir/sb.tar.gz" -C "$tempdir"
  install -m 755 "$tempdir/sing-box-${version}-linux-amd64/sing-box" /usr/local/bin/sing-box
  rm -rf "$tempdir"
  # Official upstream tools. Can be pre-installed instead (e.g. by an operator who pins binaries).
  local tmp
  tmp=$(mktemp -d)
  if ! command -v awg >/dev/null || ! command -v awg-quick >/dev/null; then
    git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools "$tmp/tools"
    (cd "$tmp/tools/src" && make -j2 && make install)
  fi
  if ! command -v amneziawg-go >/dev/null; then
    git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$tmp/go"
    (cd "$tmp/go" && make -j2 && make install)
  fi
  rm -rf "$tmp"
  for binary in sing-box awg awg-quick amneziawg-go nft ip curl python3; do
    command -v "$binary" >/dev/null || { echo "Отсутствует $binary" >&2; exit 1; }
  done
  say 'Зависимости готовы. Далее: установить входной AmneziaWG2 через официальное приложение, затем deploy.'
}

read_env(){
  command -v docker >/dev/null || { echo 'Не найден Docker; сначала установи входной AmneziaWG2.' >&2; exit 1; }
  docker inspect amnezia-awg2 >/dev/null || { echo 'Не найден входной контейнер amnezia-awg2.' >&2; exit 1; }
  # Determine network and bridge, optionally override with explicit environment variables.
  export VPN_BRIDGE="${VPN_BRIDGE:-}"
  export VPN_CONTAINER_IP="${VPN_CONTAINER_IP:-}"
  if [[ -z $VPN_BRIDGE || -z $VPN_CONTAINER_IP ]]; then
    local details
    details=$(python3 - <<'PY'
import json,subprocess
c=json.loads(subprocess.check_output(['docker','inspect','amnezia-awg2']))[0]
for name,network in c['NetworkSettings']['Networks'].items():
    ni=json.loads(subprocess.check_output(['docker','network','inspect',name]))[0]
    if ni['Driver']!='bridge':continue
    opts=ni.get('Options',{}) or {}
    bridge=opts.get('com.docker.network.bridge.name') or ('br-'+ni['Id'][:12] if name!='bridge' else 'docker0')
    print(bridge,network.get('IPAddress',''))
    break
PY
)
    [[ -n $details ]] || { echo 'Не удалось определить Docker-мост'; exit 1; }
    VPN_BRIDGE=${VPN_BRIDGE:-${details%% *}}
    VPN_CONTAINER_IP=${VPN_CONTAINER_IP:-${details##* }}
  fi
  VPN_WAN=${VPN_WAN:-$(ip -4 route show default | awk '$1=="default" {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1);exit}}')}
  VPN_PORT=${VPN_PORT:-1234}
  ip link show "$VPN_BRIDGE" >/dev/null
  ip link show "$VPN_WAN" >/dev/null
  RU_PUBLIC_IP=$(ip -4 addr show dev "$VPN_WAN" scope global | awk '/inet / {sub(/\/.*/,"",$2);print $2;exit}')
  [[ -n $RU_PUBLIC_IP ]] || { echo 'Не удалось определить IPv4 интерфейса WAN'; exit 1; }
}

deploy(){
  require_clean
  for b in sing-box awg awg-quick amneziawg-go nft docker; do command -v "$b" >/dev/null || { echo "Сначала prepare: нет $b"; exit 1; }; done
  read_env
  say "Обнаружено WAN=$VPN_WAN, bridge=$VPN_BRIDGE, incoming=$VPN_CONTAINER_IP, UDP=$VPN_PORT"
  mkdir -p "$DEST" /etc/vpn-proxy/exits /etc/sing-box/rules /var/lib/vpn-proxy /etc/systemd/system
  chmod 700 /etc/vpn-proxy /etc/vpn-proxy/exits /var/lib/vpn-proxy
  cp -a "$HERE/scripts" "$HERE/panel" "$DEST/"
  cp "$HERE/install.sh" "$DEST/install.sh"
  chmod 755 "$DEST/install.sh"
  python3 - <<'PY'
import secrets
from pathlib import Path
for name in ['panel-password','clash-secret']:
    p=Path('/etc/vpn-proxy')/name
    if not p.exists():p.write_text(secrets.token_urlsafe(30)+'\n')
    p.chmod(0o600)
PY
  for rule in manual-ru manual-exit domain-ru domain-exit; do
    printf '{"version":3,"rules":[]}\n' > "/etc/sing-box/rules/${rule}.json"
  done
  bash "$DEST/scripts/refresh-geoip.sh"
  python3 "$DEST/scripts/manager.py" bootstrap "$VPN_WAN" "$VPN_BRIDGE" "$VPN_CONTAINER_IP" "$VPN_PORT" >/dev/null
  python3 "$DEST/scripts/generate.py" --nft "$RU_PUBLIC_IP"
  create_services
  systemctl daemon-reload
  systemctl enable --now vpn-proxy-restore.service vpn-proxy-singbox.service vpn-proxy-panel.service
  say 'Развёрнуто БЕЗ зарубежного клиента. TProxy выключен. Панель: ssh -L 8765:127.0.0.1:8765 root@RU_VPS'
  say 'Пароль admin: sudo cat /etc/vpn-proxy/panel-password'
  say 'Через панель добавить первый .conf, проверить и активировать. Затем activate / confirm для TProxy.'
}

create_services(){
cat > /etc/systemd/system/vpn-proxy-restore.service <<'EOF'
[Unit]
Description=VPN Proxy recreate egress AWG interfaces and routing
Wants=network-online.target
After=network-online.target
Before=vpn-proxy-singbox.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 /opt/vpn-proxy/scripts/manager.py restore
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/vpn-proxy-singbox.service <<'EOF'
[Unit]
Description=VPN Proxy sing-box
Wants=vpn-proxy-restore.service
After=network-online.target vpn-proxy-restore.service
[Service]
Type=simple
ExecStart=/usr/bin/env sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/vpn-proxy-panel.service <<'EOF'
[Unit]
Description=VPN Proxy localhost control panel
After=vpn-proxy-singbox.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/vpn-proxy/panel/panel.py
WorkingDirectory=/opt/vpn-proxy
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/vpn-proxy-tproxy.service <<'EOF'
[Unit]
Description=VPN Proxy incoming Docker TProxy redirect
Wants=vpn-proxy-singbox.service
After=network-online.target docker.service vpn-proxy-singbox.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /opt/vpn-proxy/scripts/apply-tproxy.sh
ExecStop=/bin/bash /opt/vpn-proxy/scripts/rollback-routing.sh
[Install]
WantedBy=multi-user.target
EOF
}

activate(){
  [[ -e /var/lib/vpn-proxy/state.json ]] || { echo 'Сначала deploy'; exit 1; }
  systemctl is-active --quiet vpn-proxy-singbox.service
  bash "$DEST/scripts/apply-tproxy.sh"
  # Temporary apply; no persistent enable until confirm. Auto-revert after 10m.
  systemctl stop vpn-proxy-auto-rollback.timer 2>/dev/null || true
  systemd-run --unit=vpn-proxy-auto-rollback --on-active=10m \
     /bin/bash "$DEST/install.sh" rollback >/dev/null
  say 'TProxy включён. Есть 10 минут проверить клиента и выполнить: sudo bash install.sh confirm'
  say 'Если нет активного EXIT, зарубежный трафик намеренно блокируется.'
}

confirm(){
  nft list table ip vpn_proxy >/dev/null || { echo 'Нет активной таблицы TProxy'; exit 1; }
  systemctl enable vpn-proxy-tproxy.service
  systemctl stop vpn-proxy-auto-rollback.timer 2>/dev/null || true
  say 'TProxy подтверждён: запустится после перезагрузки.'
}

rollback(){
  systemctl disable --now vpn-proxy-tproxy.service 2>/dev/null || true
  bash "$DEST/scripts/rollback-routing.sh"
  systemctl stop vpn-proxy-auto-rollback.timer 2>/dev/null || true
  say 'TProxy отключён; входной AmneziaWG2 не изменён. ВНИМАНИЕ: клиентский трафик может выходить напрямую через RU VPS.'
}

status(){
  if [[ -f /var/lib/vpn-proxy/state.json ]]; then python3 "$DEST/scripts/manager.py" status; fi
  systemctl --no-pager --plain status vpn-proxy-singbox vpn-proxy-panel vpn-proxy-tproxy 2>/dev/null | head -n 35 || true
  ip -4 rule show | grep -E '10000:|11[0-9]{3}:|12[0-9]{3}:' || true
  nft list table ip vpn_proxy >/dev/null 2>&1 && say 'TProxy: ON' || say 'TProxy: OFF'
}

case "${1:-}" in
  prepare) prepare;;
  deploy) deploy;;
  activate) activate;;
  confirm) confirm;;
  rollback) rollback;;
  status) status;;
  *) echo 'Использование: sudo bash install.sh {prepare|deploy|activate|confirm|rollback|status}';exit 2;;
esac
