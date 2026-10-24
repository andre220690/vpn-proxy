# VPN Proxy — universal installer, управление выходными VPN (v3 / 24.10.2026)

> Новая реализация на основе описания ранее работающего RU + Helsinki проекта. **Не является экспортом старого работающего скрипта.**
> Собран с нуля. Локально проверяются Python и Bash, но **сквозное развёртывание на реальных VPS пока не выполнялось**.

## Поведение

```text
AmneziaVPN clients --AWG2--> RU VPS (AmneziaWG2 Docker container)
                                  |
                           nftables TProxy
                                  |
                           sing-box + GeoIP RU
                            /             \
                        RU direct     exit-default Selector
                                              |
                                     только ОДИН выбранный VPN
                                     FI / DE / NL / ...
```

- Новый RU VPS разворачивается **без зарубежного клиента**. Зарубежный трафик до выбора источника блокируется (`reject`), российский — `RU direct`.
- Первый и дальнейшие клиенты импортируются с `.conf` **через веб-панель** на `127.0.0.1:8765`.
- Профиль сначала поднимается отдельно, затем проходит SOCKS-пробу с `routing_mark` и свежий AWG handshake. Лишь после успешной проверки появляется в списке.
- Добавление/удаление требует перезапуска sing-box (краткое прерывание текущих сессий), переключение уже добавленных активных — через локальный Clash API без перезапуска. Первое включение EXIT требует применения конфигурации.
- Все зарубежные соединения идут только через выбранный выход; без автоматического выбора резерва. Ручные маршруты сохраняют только направления `RU`/`EXIT`, без привязки к стране.
- Для каждого AWG-подключения отдельный **host interface**, `fwmark` / policy table 220–299. AWG-конфигурация передаётся в `awg-quick strip` / `awg setconf` с `Table = off`, без команд PreUp/PostUp. Зависит от официального userspace `amneziawg-go`; исходящие контейнеры не нужны.
- Сервер управляет **исходящими** peers; входные AmneziaWG2 клиенты продолжают создаваться официальным AmneziaVPN.
- Только IPv4. Неразрешённый IPv6 **блокируется** в Docker bridge FORWARD при включённом TProxy, но маршрутизация IPv6 не реализована; DNS-утечки вне этого пути не исключены.

## Обязательные условия

- **Новый, чистый** RU VPS Ubuntu 24.04/26.04 x86_64, root, SSH.
- Провайдер разрешает TUN и `CAP_NET_ADMIN` на хосте. Docker уже устанавливается официальным AmneziaVPN при установке входного VPN.
- После установки официального AmneziaWG2 контейнер должен называться `amnezia-awg2`, использовать отдельную Docker bridge-сеть и NAT клиентов (как эталонный проект).
- Установщик **не управляет** входными ключами и клиентскими профилями.
- Интернет на RU VPS для получения `sing-box`, `ru.srs` и сборки AWG-Go. Проект скачивает официальные исходники AWG Tools/Go (по умолчанию текущие ревизии); для строгой воспроизводимости/аудита следует зафиксировать коммиты и хэши бинарных поставок самостоятельно.
- Не запускать `deploy` поверх действующей установки (`/etc/sing-box/config.json`, `/etc/vpn-proxy/tproxy.nft` или `/var/lib/vpn-proxy/state.json`).

## Установка: новая схема

1. На **чистом** VPS установить Git, клонировать репозиторий и подготовить зависимости:

   ```bash
   sudo apt-get update && sudo apt-get install -y git
   git clone https://github.com/andre220690/vpn-proxy.git && cd vpn-proxy
   sudo bash install.sh prepare
   ```

   Репозиторий приватный: используйте учётную запись с доступом. После клонирования `install.sh` уже находится в каталоге `vpn-proxy`: скачивать или распаковывать архив и переходить в `vpn-auto-deploy` не нужно. Все дальнейшие команды `install.sh` выполняйте из `~/vpn-proxy` (если клонировали в домашнюю папку).

   `prepare` скачивает sing-box 1.14.4 из официального GitHub Releases SagerNet, собирает/устанавливает официальные `awg`, `awg-quick`, `amneziawg-go` при их отсутствии. Если сборка Go не проходит из-за версии Go, обновить Go по официальной инструкции и повторить `prepare`.

   Дождитесь сообщения `[VPN Proxy] Зависимости готовы`. Оно подтверждает только подготовку зависимостей: панель и маршрутизация ещё не развёрнуты. Затем переходите к шагу 2. Если команда завершилась ошибкой, сначала устраните её.

2. Через **официальное приложение AmneziaVPN** установить входной **AmneziaWG2** на этот RU VPS, создать профиль для телефона/ПК. Убедиться, что без TProxy IP — RU VPS. Установщик не трогает этот контейнер.

3. Развернуть **без `.conf`**:

   ```bash
   sudo bash install.sh deploy
   sudo bash install.sh status
   ```

   Параметры обычно определяются автоматически из Docker и маршрутов. При особой сети можно задать параметры окружения перед `deploy`:

   ```bash
   sudo VPN_WAN=enp3s0 VPN_BRIDGE=amn0 VPN_CONTAINER_IP=172.29.172.2 VPN_PORT=1234 bash install.sh deploy
   ```

4. На Windows открыть **только через SSH**:

   ```powershell
   ssh -L 8765:127.0.0.1:8765 root@IP_НОВОГО_RU_VPS
   ```

   В браузере: `http://127.0.0.1:8765`, пользователь `admin`, пароль прочитать на RU VPS:

   ```bash
   sudo cat /etc/vpn-proxy/panel-password
   ```

   Добавить первый native `.conf` иностранного AmneziaWG2 peer через панель. Должен содержать `[Interface]` + `[Peer]`, IPv4 Address, Endpoint, `AllowedIPs = 0.0.0.0/0`, AWG2 параметры Jc/Jmin/Jmax/S1.., ключи. Выбор активного выполняется отдельно кнопкой «Активировать».

5. Когда первый EXIT проверен, активировать **TProxy** с автоматическим аварийным откатом через 10 минут:

   ```bash
   sudo bash install.sh activate
   ```

   Проверить клиентом RU и зарубежный сайты (включив полный VPN-маршрут на клиенте). Если всё работает:

   ```bash
   sudo bash install.sh confirm
   ```

   Если не работает:

   ```bash
   sudo bash install.sh rollback
   ```

   **ВАЖНО:** emergency `rollback` прекращает перехват и может временно выпускать зарубежный трафик через RU WAN. Не считать это безопасным fail-closed режимом.

6. После перезагрузки источники восстанавливаются, выбранный EXIT берётся из `/var/lib/vpn-proxy/state.json`, TProxy включается только если выполнен `confirm`.

## Проверка и диагностика

Проверки исходников без root и без изменения маршрутизации (Python 3.10+):

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts panel tests
bash -n install.sh
for script in scripts/*.sh; do bash -n "$script"; done
```

GitHub Actions запускает эти проверки при push и pull request на Ubuntu с
Python 3.12. Они не заменяют проверку развёртывания и VPN на реальном VPS.
В Git хранятся только исходники: реальные `.conf`, ключи, пароли, состояние
сервера и служебные файлы исключены через `.gitignore`. Тестовые ключи в
`tests/test_core.py` — заведомо нерабочие заглушки.

```bash
sudo bash install.sh status
sudo systemctl status vpn-proxy-restore vpn-proxy-singbox vpn-proxy-panel vpn-proxy-tproxy --no-pager
sudo journalctl -u vpn-proxy-singbox -n 50 --no-pager
sudo ip -4 rule show
sudo ip -4 route show table 220
sudo nft list table ip vpn_proxy
sudo awg show
curl -4 --socks5-hostname 127.0.0.1:2080 https://api.ipify.org
```

Порт `2080` тестирует принудительно RU. Проверка EXIT встроена в «Проверить» панели и выполняется временным локальным SOCKS (`30220` и т. п.), без изменения Selector. **Не предоставляйте чужим людям исходные `.conf` и приватные ключи**.

## Безопасность и ограничения

- Панель `127.0.0.1:8765`, Clash API `127.0.0.1:9090`, TProxy `:2083`. Публично их не открывать.
- Панель `Basic Auth` за SSH и anti-CSRF; backend работает от root, потому что управляет интерфейсами. Предназначена только для доверенного админа, а не для публичного SaaS.
- Пароли: `/etc/vpn-proxy/panel-password`, `/etc/vpn-proxy/clash-secret`. Профили: `/etc/vpn-proxy/exits/*.conf` (0600). Их **не** размещать в Git.
- Не перехватывать UDP с источником `1234` входного контейнера: без этого AmneziaVPN перестанет подключаться. Проверяйте, что UDP-порт контейнера действительно тот, что указали.
- Kill-switch ограничен направлением sing-box EXIT и маршрутизацией `fwmark`; если TProxy отсутствует/отключен, контейнерный NAT может отправлять трафик напрямую. Для абсолютного fail-closed нужен отдельный Docker-side firewall и аудит DNS/IPv6.
- До маршрутизации отечественные IP определяются по `ru.srs` (снимок на момент `deploy`). Обновить GeoIP вручную: `/opt/vpn-proxy/scripts/refresh-geoip.sh`.
- Проверка доменов через sniff ограничена ECH и другими протоколами. В этой версии панель нацелена на *источники*, не содержит редактора ручных списков; файлы с направлениями RU/EXIT по-прежнему загружаются sing-box.
- Платформа и версии AWG2 могут отличаться. **Не проверено на реальном VPS**: проверка успешного handshake/внешнего IP имеет приоритет перед `confirm`.

## Состав

```text
vpn-auto-deploy/
├── install.sh                   # prepare/deploy/activate/confirm/rollback/status
├── panel/panel.py              # защищённая локальная веб-панель
├── scripts/core.py             # безопасный парсер и генератор конфигураций
├── scripts/manager.py          # добавление, тест, выбор, удаление AWG peers
├── scripts/generate.py         # scoped nftables, без global flush
├── scripts/apply-tproxy.sh     # входящий TProxy и ip rule
├── scripts/rollback-routing.sh # аварийный откат перехвата
├── scripts/refresh-geoip.sh    # GeoIP RU
├── tests/test_core.py          # unit tests
└── README.md
```

### Документация upstream

- https://sing-box.sagernet.org/configuration/outbound/selector/
- https://sing-box.sagernet.org/configuration/experimental/clash-api/
- https://sing-box.sagernet.org/configuration/inbound/tproxy/
- https://docs.amnezia.org/documentation/instructions/install-amneziawg-go/
- https://github.com/amnezia-vpn/amneziawg-tools
