# openwrt-utils — VLESS Reality toolkit

Скрипты для загрузки VLESS-подписки, проверки Reality-нод, выбора рабочего варианта и настройки sing-box/HomeProxy на Linux, macOS и OpenWrt.

Инструменты переносят только параметры VLESS Reality. Настройки Happ/Xray вроде `burstObservatory`, локальных SOCKS/HTTP-портов, путей логов, `level`, выключенного `mux`, DNS Happ и `leastLoad` не копируются в HomeProxy.

## Возможности

- подписки в виде Xray/Happ JSON, списка `vless://` или Base64;
- проверка обязательных полей VLESS Reality;
- полноценный тест ноды через временный sing-box и SOCKS;
- экспорт sing-box outbound;
- безопасное обновление существующего sing-box-конфига;
- ручная инструкция и UCI-команды для HomeProxy;
- применение HomeProxy-ноды с backup и rollback;
- диагностика и настройка DNS на OpenWrt;
- отсутствие реальных URL подписок, UUID и Reality-ключей в Git.

## Структура

```text
vpn_tool.py                 Linux/macOS CLI на Python
scripts/vpn                 короткий запуск Python CLI
scripts/openwrt-vless       BusyBox/ash версия для OpenWrt
scripts/openwrt-dns         проверка и настройка DNS OpenWrt
tests/                      обезличенные тестовые подписки и unit-тесты
```

## Требования

Linux/macOS:

- Python 3.9 или новее;
- `sing-box` для benchmark и проверки конфига;
- `curl` для проверки трафика;
- systemd на Linux или launchd на macOS для автоматического перезапуска.

OpenWrt:

```sh
opkg update
opkg install curl jq
```

Также необходим sing-box, обычно установленный вместе с HomeProxy. OpenWrt-скрипты не требуют Python.

Команда `base64` не обязательна для JSON и обычных списков `vless://`. Если провайдер отдаёт Base64-подписку, скрипт попробует `base64`, BusyBox applet или `openssl`. При отсутствии всех декодеров установите:

```sh
opkg install coreutils-base64
```

## Подписка и секреты

URL лучше передавать через переменную окружения:

```sh
export VPN_SUBSCRIPTION_URL='https://provider.example/subscription/token'
./scripts/vpn nodes
```

Скачать, проверить и сохранить подписку локально:

```sh
./scripts/vpn download --output ~/subscription.sub
```

Если файл уже существует, перед заменой создаётся `subscription.sub.bak-DATE`. Новый файл получает права `0600`.

Или через аргументы:

```sh
./scripts/vpn nodes --subscription-file ~/subscription.sub
./scripts/vpn nodes --subscription-url 'https://provider.example/subscription/token'
```

Не сохраняйте URL с токеном в README, shell history или Git. Файлы `*.sub`, `secrets.env` и `config.local.json` игнорируются.

## Benchmark на Linux и macOS

```sh
./scripts/vpn benchmark --subscription-file ~/subscription.sub
./scripts/vpn benchmark --subscription-file ~/subscription.sub --top 5
```

После теста выводятся поля лучшей ноды для ручной настройки HomeProxy. Чтобы одновременно установить лучшую ноду в sing-box:

```sh
sudo ./scripts/vpn benchmark \
  --subscription-file ~/subscription.sub \
  --apply-best \
  --config /etc/sing-box/config.json
```

Каждая нода проходит четыре этапа:

1. проверка обязательных Reality-параметров;
2. DNS-разрешение и TCP-подключение;
3. `sing-box check` временного конфига;
4. HTTP-запрос через временный SOCKS-прокси.

Если тестовый ответ достаточно большой, ноды ранжируются по скорости. Для небольшого ответа основным показателем становится полное время запроса.

## sing-box

Вывести outbound выбранной ноды:

```sh
./scripts/vpn export-sing-box --subscription-file ~/subscription.sub --node 2
./scripts/vpn export-sing-box --subscription-file ~/subscription.sub --node 2 --output outbound.json
```

Обновить outbound с тегом `proxy` в существующем конфиге:

```sh
sudo ./scripts/vpn apply-sing-box \
  --subscription-file ~/subscription.sub \
  --node 2 \
  --config /etc/sing-box/config.json
```

Порядок применения:

1. читается существующий конфиг;
2. заменяется только outbound `proxy`;
3. кандидат проходит `sing-box check`;
4. создаётся `config.json.bak-DATE`;
5. файл атомарно устанавливается и сервис перезапускается;
6. при ошибке перезапуска восстанавливается backup.

Для нестандартного systemd-сервиса используйте `--service NAME`. На macOS launchd label задаётся через `--launchd-label`.

## Ручная настройка HomeProxy

Получить инструкцию для всех нод:

```sh
./scripts/vpn homeproxy-manual --subscription-file ~/subscription.sub
```

Только для одной ноды:

```sh
./scripts/vpn homeproxy-manual --subscription-file ~/subscription.sub --node 2
```

В LuCI откройте `Services → HomeProxy → Nodes`, создайте VLESS-ноду и перенесите поля из вывода:

| Поле HomeProxy | Значение из подписки |
|---|---|
| Type | VLESS |
| Address | `host` |
| Port | `port` |
| UUID | `uuid` |
| TLS | включён |
| Reality | включён |
| Network/Transport | TCP |
| Flow | `xtls-rprx-vision` |
| SNI | `serverName` / `sni` |
| uTLS fingerprint | `fingerprint` / `fp` |
| Reality public key | `publicKey` / `pbk` |
| Reality short ID | `shortId` / `sid` |
| Packet encoding | `xudp` |
| Allow insecure | выключено |

Получить команды без применения:

```sh
./scripts/vpn homeproxy-uci \
  --subscription-file ~/subscription.sub \
  --node 2 \
  --section vless_manual
```

## OpenWrt и HomeProxy

Скопируйте `scripts/openwrt-vless` на роутер, затем:

```sh
scp scripts/openwrt-vless root@openwrt:/usr/bin/vpn
ssh root@openwrt chmod +x /usr/bin/vpn
```

На роутере используется тот же интерфейс команд, но без Python:

```sh
export VPN_SUBSCRIPTION_URL='https://provider.example/subscription/token'

vpn download --output /root/subscription.sub
vpn nodes --subscription-file /root/subscription.sub
vpn benchmark --subscription-file /root/subscription.sub --max 10
vpn homeproxy-manual --subscription-file /root/subscription.sub --node 2
vpn homeproxy-uci --subscription-file /root/subscription.sub --node 2
```

Проверить все ноды и сразу применить лучшую из того же результата:

```sh
vpn benchmark --subscription-file /root/subscription.sub --max 10 --apply-best
```

После `vpn download --output /root/subscription.sub` параметр `--subscription-file` можно не указывать:

```sh
vpn nodes
vpn benchmark --max 10
```

По умолчанию OpenWrt-версия ищет `/root/subscription.sub`, затем старый `/root/connliberty.sub`. Путь можно переопределить переменной `VPN_SUBSCRIPTION_FILE`.

Применение HomeProxy-ноды:

```sh
vpn homeproxy-apply \
  --subscription-file /root/subscription.sub \
  --node 2 \
  --section vless_auto
```

Если HomeProxy использует `routing_mode=custom`, скрипт обновляет существующий `routing_node`, а не неиспользуемый `main_node`. При нескольких routing nodes укажите нужный явно:

```sh
vpn homeproxy-apply --node 2 --section vless_auto --routing-node AutoVPN
```

Старый интерфейс скрипта также сохранён:

```sh
chmod +x /root/openwrt-vless

/root/openwrt-vless -f /root/subscription.sub --list
/root/openwrt-vless -f /root/subscription.sub --benchmark --max 10
/root/openwrt-vless -f /root/subscription.sub --manual --node 2
/root/openwrt-vless -f /root/subscription.sub --uci --node 2
```

Применение через старый интерфейс выполняется только явно:

```sh
/root/openwrt-vless -f /root/subscription.sub \
  --apply --node 2 --section vless_auto
```

Скрипт:

- создаёт `/etc/config/homeproxy.bak-DATE`;
- обновляет только `config node` и `homeproxy.config.main_node`;
- не заменяет маршрутизацию, DNS, subscription и control-секции;
- перезапускает HomeProxy;
- сверяет записанные UCI-поля до и после перезапуска;
- проверяет выбранную ноду в `/var/run/homeproxy/sing-box-c.json`;
- восстанавливает backup, если сервис не запустился или параметры изменились.

## DNS на OpenWrt

Диагностика:

```sh
/root/openwrt-dns check
/root/openwrt-dns check --test-domain example.com
```

Показать план настройки:

```sh
/root/openwrt-dns configure \
  --servers 1.1.1.1,9.9.9.9 \
  --disable-wan-peerdns \
  --force-lan-dns \
  --block-dot
```

Применить после проверки плана:

```sh
/root/openwrt-dns configure \
  --servers 1.1.1.1,9.9.9.9 \
  --disable-wan-peerdns \
  --force-lan-dns \
  --block-dot \
  --apply
```

Опции:

- `--disable-wan-peerdns` отключает DNS, полученный от провайдера;
- `--force-lan-dns` перенаправляет обычные TCP/UDP DNS-запросы LAN на роутер;
- `--block-dot` блокирует прямой DNS-over-TLS на порту 853 из LAN в WAN.

Скрипт не может универсально заблокировать DNS-over-HTTPS: он использует обычный HTTPS/443 и требует отдельного списка доменов/IP или контроля клиентских устройств. Настроенные DNS-серверы также должны маршрутизироваться через VPN, если требуется исключить их выход через WAN.

## Тесты

```sh
make check
```

Fixtures используют домены `.example.test`, искусственный UUID и искусственные Reality-ключи.

## Источники формата

- [официальная документация sing-box: VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/)
- [официальная документация sing-box: TLS/Reality](https://sing-box.sagernet.org/configuration/shared/tls/)
- [HomeProxy](https://github.com/immortalwrt/homeproxy)
- [OpenWrt UCI](https://openwrt.org/docs/techref/uci)

## Происхождение

Основой benchmark и безопасного обновления sing-box послужил рабочий Ubuntu-скрипт от 2026-08-03. OpenWrt/HomeProxy-часть объединяет предыдущие `vpnbench-openwrt.sh` и `vpnbench-homeproxy.sh`, но не перезаписывает конфигурацию HomeProxy целиком.
