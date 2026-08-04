#!/usr/bin/env python3
"""VLESS Reality subscription, benchmark and configuration toolkit."""

import argparse
import base64
import copy
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid as uuid_lib
from datetime import datetime
from pathlib import Path

BASE_TEST_PORT = 18080
DEFAULT_TEST_URL = "https://detectportal.firefox.com/success.txt"


def run(command, timeout=30):
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def compact_error(text, limit=240):
    value = " ".join((text or "").strip().split())
    return value[-limit:] if value else "unknown error"


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Happ/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def load_source(path=None, url=None):
    if path:
        return Path(path).expanduser().read_bytes()
    if url:
        return download(url)
    env_url = os.environ.get("VPN_SUBSCRIPTION_URL")
    if env_url:
        return download(env_url)
    raise ValueError("укажите --subscription-file, --subscription-url или VPN_SUBSCRIPTION_URL")


def save_subscription(url, output):
    raw = download(url)
    nodes = parse_subscription(decode_subscription(raw))
    accepted = [node for node in nodes if not validation_errors(node)]
    if not accepted:
        raise ValueError("скачанный файл не содержит валидных VLESS Reality-нод")
    target = Path(output).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    fd, candidate_name = tempfile.mkstemp(prefix=f".{target.name}-", dir=target.parent)
    candidate = Path(candidate_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        os.chmod(candidate, 0o600)
        if target.exists():
            backup = Path(f"{target}.bak-{datetime.now():%Y%m%d-%H%M%S}")
            shutil.copy2(target, backup)
        os.replace(candidate, target)
        candidate = None
    finally:
        if candidate:
            candidate.unlink(missing_ok=True)
    return target, backup, len(accepted)


def decode_subscription(raw):
    text = raw.decode("utf-8", "ignore").strip()
    if not text:
        return ""
    if text.startswith(("[", "{", "vless://")) or "\nvless://" in text:
        return text
    compact = "".join(text.split())
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded).decode("utf-8", "ignore").strip()
            if decoded and ("vless://" in decoded or decoded.startswith(("[", "{"))):
                return decoded
        except Exception:
            pass
    return text


def normalize_node(node):
    try:
        port = int(node.get("port") or 443)
    except (TypeError, ValueError):
        port = 0
    result = {
        "name": str(node.get("name") or "node"),
        "uuid": str(node.get("uuid") or ""),
        "host": str(node.get("host") or ""),
        "port": port,
        "flow": str(node.get("flow") or "xtls-rprx-vision"),
        "network": str(node.get("network") or "tcp").lower(),
        "sni": str(node.get("sni") or node.get("host") or ""),
        "fp": str(node.get("fp") or "firefox"),
        "pbk": str(node.get("pbk") or ""),
        "sid": str(node.get("sid") or ""),
        "packet_encoding": str(node.get("packet_encoding") or "xudp"),
        "allow_insecure": bool(node.get("allow_insecure", False)),
    }
    return result


def parse_vless_uri(uri):
    parsed = urllib.parse.urlsplit(uri.strip())
    if parsed.scheme != "vless":
        return None
    query = urllib.parse.parse_qs(parsed.query)

    def value(*names, default=""):
        for name in names:
            if query.get(name):
                return query[name][0]
        return default

    security = value("security").lower()
    if security not in ("", "reality"):
        return None
    return normalize_node({
        "name": urllib.parse.unquote(parsed.fragment) or parsed.hostname or "node",
        "uuid": urllib.parse.unquote(parsed.username or ""),
        "host": parsed.hostname or "",
        "port": parsed.port or 443,
        "flow": value("flow", default="xtls-rprx-vision"),
        "network": value("type", "network", default="tcp"),
        "sni": value("sni", "serverName", default=parsed.hostname or ""),
        "fp": value("fp", "fingerprint", default="firefox"),
        "pbk": value("pbk", "publicKey"),
        "sid": value("sid", "shortId"),
        "packet_encoding": value("packetEncoding", default="xudp"),
        "allow_insecure": value("allowInsecure", default="0") in ("1", "true"),
    })


def parse_xray_json(text):
    data = json.loads(text)
    configs = data if isinstance(data, list) else [data]
    nodes = []
    for config in configs:
        if not isinstance(config, dict):
            continue
        remarks = config.get("remarks", "node")
        for outbound in config.get("outbounds", []):
            if outbound.get("type") == "vless":
                tls = outbound.get("tls", {})
                reality = tls.get("reality", {})
                nodes.append(normalize_node({
                    "name": outbound.get("tag") or remarks,
                    "uuid": outbound.get("uuid"),
                    "host": outbound.get("server"),
                    "port": outbound.get("server_port", 443),
                    "flow": outbound.get("flow"),
                    "network": outbound.get("network", "tcp"),
                    "sni": tls.get("server_name", outbound.get("server")),
                    "fp": tls.get("utls", {}).get("fingerprint", "firefox"),
                    "pbk": reality.get("public_key"),
                    "sid": reality.get("short_id"),
                    "packet_encoding": outbound.get("packet_encoding", "xudp"),
                    "allow_insecure": tls.get("insecure", False),
                }))
                continue
            if outbound.get("protocol") != "vless":
                continue
            vnext = outbound.get("settings", {}).get("vnext", [])
            if not vnext or not vnext[0].get("users"):
                continue
            server = vnext[0]
            user = server["users"][0]
            stream = outbound.get("streamSettings", {})
            reality = stream.get("realitySettings", {})
            if stream.get("security") not in (None, "", "reality"):
                continue
            nodes.append(normalize_node({
                "name": outbound.get("tag") or remarks,
                "uuid": user.get("id"),
                "host": server.get("address"),
                "port": server.get("port", 443),
                "flow": user.get("flow"),
                "network": stream.get("network", "tcp"),
                "sni": reality.get("serverName", server.get("address")),
                "fp": reality.get("fingerprint", "firefox"),
                "pbk": reality.get("publicKey"),
                "sid": reality.get("shortId"),
                "allow_insecure": reality.get("allowInsecure", stream.get("allowInsecure", False)),
            }))
    return nodes


def parse_subscription(text):
    if "vless://" in text:
        nodes = []
        for token in text.replace("\r", "\n").split():
            if token.startswith("vless://"):
                try:
                    node = parse_vless_uri(token)
                except (ValueError, urllib.parse.Error):
                    node = None
                if node:
                    nodes.append(node)
        return nodes
    try:
        return parse_xray_json(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []


def validation_errors(node):
    errors = []
    try:
        parsed_uuid = uuid_lib.UUID(node["uuid"])
        if str(parsed_uuid) != node["uuid"].lower():
            errors.append("UUID записан не в каноническом формате")
    except (ValueError, AttributeError):
        errors.append("некорректный UUID")
    if not node["host"] or re.search(r"\s", node["host"]):
        errors.append("нет address")
    if not 1 <= node["port"] <= 65535:
        errors.append("некорректный port")
    if node["network"] != "tcp":
        errors.append(f"transport {node['network']} вместо TCP")
    if node["flow"] != "xtls-rprx-vision":
        errors.append(f"неподдерживаемый flow {node['flow'] or '(пусто)'}")
    if not node["sni"]:
        errors.append("нет SNI")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", node["pbk"]):
        errors.append("некорректный Reality public key")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}", node["sid"]):
        errors.append("некорректный Reality short ID")
    if node["allow_insecure"]:
        errors.append("allow insecure включён")
    return errors


def valid_nodes(args):
    raw = load_source(args.subscription_file, args.subscription_url)
    nodes = parse_subscription(decode_subscription(raw))
    accepted = []
    for node in nodes:
        errors = validation_errors(node)
        if errors:
            print(f"SKIP {node['name']}: {', '.join(errors)}", file=sys.stderr)
        else:
            accepted.append(node)
    return accepted


def resolve_all(host):
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []


def tcp_latency(ip, port, timeout=3):
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return round((time.monotonic() - started) * 1000)
    except OSError:
        return None


def make_outbound(node, server=None):
    outbound = {
        "type": "vless", "tag": "proxy", "server": server or node["host"],
        "server_port": node["port"], "uuid": node["uuid"], "flow": node["flow"],
        "network": "tcp", "packet_encoding": node["packet_encoding"],
        "tls": {
            "enabled": True, "server_name": node["sni"], "insecure": False,
            "utls": {"enabled": True, "fingerprint": node["fp"]},
            "reality": {"enabled": True, "public_key": node["pbk"], "short_id": node["sid"]},
        },
    }
    return outbound


def make_test_config(node, ip, local_port):
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": local_port}],
        "outbounds": [make_outbound(node, ip), {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


def curl_test(local_port, url, timeout=25):
    fields = "\t".join(("%{http_code}", "%{time_connect}", "%{time_total}", "%{speed_download}", "%{size_download}"))
    result = run(["curl", "-4", "-sS", "-L", "-o", "/dev/null", "--socks5-hostname", f"127.0.0.1:{local_port}", "--connect-timeout", "7", "--max-time", str(timeout), "-w", fields, url], timeout + 5)
    if not result or result.returncode:
        return None, compact_error(result.stderr if result else "curl timeout")
    try:
        code, connect, total, speed, size = result.stdout.split("\t")
        return {"http_code": int(code), "connect_s": float(connect), "total_s": float(total), "speed_bps": float(speed), "size_bytes": float(size)}, None
    except ValueError:
        return None, "unexpected curl output"


def test_node(node, ip, port, test_url):
    config_path = log_path = None
    process = None
    log_handle = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as handle:
            json.dump(make_test_config(node, ip, port), handle, indent=2)
            config_path = handle.name
        check = run(["sing-box", "check", "-c", config_path], 10)
        if not check or check.returncode:
            return None, f"CONFIG FAIL: {compact_error((check.stderr or check.stdout) if check else 'timeout')}"
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as handle:
            log_path = handle.name
        log_handle = open(log_path, "w", encoding="utf-8")
        process = subprocess.Popen(["sing-box", "run", "-c", config_path], stdout=log_handle, stderr=subprocess.STDOUT)
        time.sleep(1)
        if process.poll() is not None:
            log_handle.close(); log_handle = None
            return None, f"START FAIL: {compact_error(Path(log_path).read_text(errors='ignore'))}"
        return curl_test(port, test_url)
    finally:
        if log_handle:
            log_handle.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(3)
        for path in (config_path, log_path):
            if path:
                Path(path).unlink(missing_ok=True)


def benchmark(nodes, test_url, top):
    if not shutil.which("sing-box") or not shutil.which("curl"):
        raise RuntimeError("нужны команды sing-box и curl")
    results = []
    for index, node in enumerate(nodes):
        print(f"[{index + 1}/{len(nodes)}] {node['name']} {node['host']}:{node['port']}")
        for ip_index, ip in enumerate(resolve_all(node["host"])):
            latency = tcp_latency(ip, node["port"])
            if latency is None:
                print(f"  {ip}: TCP FAIL")
                continue
            metrics, error = test_node(node, ip, BASE_TEST_PORT + index * 10 + ip_index, test_url)
            if error:
                print(f"  {ip}: {error}")
                continue
            print(f"  {ip}: tcp={latency}ms proxy={metrics['total_s'] * 1000:.0f}ms HTTP={metrics['http_code']}")
            results.append({"node": node, "ip": ip, "tcp_ms": latency, **metrics})
    if not results:
        return []
    median_size = statistics.median(item["size_bytes"] for item in results)
    key = (lambda item: (-item["speed_bps"], item["total_s"], item["tcp_ms"])) if median_size >= 128 * 1024 else (lambda item: (item["total_s"], item["tcp_ms"]))
    results.sort(key=key)
    print("\nTOP:")
    for item in results[:max(1, top)]:
        print(f"  {item['total_s'] * 1000:5.0f}ms tcp={item['tcp_ms']:4}ms {item['node']['name']} {item['node']['host']} -> {item['ip']}")
    return results


def node_id(node):
    raw = f"{node['host']}:{node['port']}:{node['uuid']}:{node['sid']}".encode()
    return "vless_" + hashlib.sha256(raw).hexdigest()[:24]


def homeproxy_uci_lines(node, section=None, select=True):
    section = section or node_id(node)
    values = {
        "label": node["name"], "type": "vless", "address": node["host"], "port": node["port"],
        "uuid": node["uuid"], "tls": "1", "tls_sni": node["sni"], "tls_reality": "1",
        "tls_reality_public_key": node["pbk"], "tls_reality_short_id": node["sid"],
        "tls_utls": node["fp"], "vless_flow": node["flow"], "packet_encoding": node["packet_encoding"],
    }
    lines = [f"uci set homeproxy.{section}='node'"]
    for key, value in values.items():
        escaped = str(value).replace("'", "'\\''")
        lines.append(f"uci set homeproxy.{section}.{key}='{escaped}'")
    if select:
        lines.extend((f"uci set homeproxy.config.main_node='{section}'", "uci set homeproxy.config.main_udp_node='same'"))
    lines.extend(("uci commit homeproxy", "/etc/init.d/homeproxy restart"))
    return lines


def print_homeproxy_manual(nodes):
    print("ОБЩИЕ ПОЛЯ ДЛЯ HOMEPROXY")
    print("Type: VLESS\nTLS: включён\nReality: включён\nNetwork/Transport: TCP")
    print("Flow: xtls-rprx-vision\nuTLS: включён\nPacket encoding: xudp\nAllow insecure: выключено")
    for index, node in enumerate(nodes, 1):
        print(f"\nНОДА {index}: {node['name']}")
        print(f"Address: {node['host']}\nPort: {node['port']}\nUUID: {node['uuid']}")
        print(f"SNI: {node['sni']}\nuTLS fingerprint: {node['fp']}")
        print(f"Reality public key: {node['pbk']}\nReality short ID: {node['sid']}")
    print("\nНЕ ПЕРЕНОСИТЬ ИЗ HAPP/XRAY")
    print("burstObservatory; SOCKS/HTTP-порты; пути логов; level; mux; DNS Happ; leastLoad")


def atomic_install_config(node, target, service, launchd_label):
    if os.geteuid() != 0:
        raise RuntimeError("применение требует root/sudo")
    target = Path(target).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    current = None
    if target.exists():
        try:
            current = json.loads(target.read_text())
        except (json.JSONDecodeError, OSError):
            current = None
    config = copy.deepcopy(current) if isinstance(current, dict) else make_test_config(node, node["host"], 10808)
    outbounds = config.setdefault("outbounds", [])
    replacement = make_outbound(node)
    for index, outbound in enumerate(outbounds):
        if outbound.get("tag") == "proxy":
            outbounds[index] = replacement
            break
    else:
        outbounds.insert(0, replacement)
    config.setdefault("route", {})["final"] = "proxy"
    fd, candidate_name = tempfile.mkstemp(prefix=".sing-box-", suffix=".json", dir=target.parent)
    candidate = Path(candidate_name)
    backup = None
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(config, handle, indent=2, ensure_ascii=False); handle.write("\n")
        check = run(["sing-box", "check", "-c", str(candidate)], 15)
        if not check or check.returncode:
            raise RuntimeError(f"sing-box check: {compact_error((check.stderr or check.stdout) if check else 'timeout')}")
        if target.exists():
            backup = Path(f"{target}.bak-{datetime.now():%Y%m%d-%H%M%S}")
            shutil.copy2(target, backup)
            os.chmod(candidate, target.stat().st_mode & 0o777)
        else:
            os.chmod(candidate, 0o600)
        os.replace(candidate, target)
        candidate = None
        if platform.system() == "Darwin":
            restart = run(["launchctl", "kickstart", "-k", launchd_label], 30)
        else:
            restart = run(["systemctl", "restart", service], 30)
        if not restart or restart.returncode:
            if backup:
                shutil.copy2(backup, target)
            raise RuntimeError("сервис не перезапустился; предыдущий конфиг восстановлен" if backup else "сервис не перезапустился")
        print(f"Установлено: {target}")
        if backup:
            print(f"Backup: {backup}")
    finally:
        if candidate:
            candidate.unlink(missing_ok=True)


def add_source_options(parser):
    parser.add_argument("--subscription-file")
    parser.add_argument("--subscription-url")


def select_nodes(nodes, index):
    if index is None:
        return nodes
    if index < 1 or index > len(nodes):
        raise ValueError(f"номер ноды должен быть от 1 до {len(nodes)}")
    return [nodes[index - 1]]


def parse_args():
    parser = argparse.ArgumentParser(description="VLESS Reality toolkit for Linux, macOS and OpenWrt/HomeProxy")
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("download", help="скачать и проверить подписку с backup"); fetch.add_argument("--subscription-url"); fetch.add_argument("--output", default="subscription.sub")
    nodes = sub.add_parser("nodes", help="проверить и вывести ноды подписки"); add_source_options(nodes)
    bench = sub.add_parser("benchmark", help="проверить ноды через sing-box"); add_source_options(bench); bench.add_argument("--test-url", default=DEFAULT_TEST_URL); bench.add_argument("--top", type=int, default=15); bench.add_argument("--apply-best", action="store_true"); bench.add_argument("--config", default="/etc/sing-box/config.json"); bench.add_argument("--service", default="sing-box"); bench.add_argument("--launchd-label", default="system/io.nekohasekai.sing-box")
    manual = sub.add_parser("homeproxy-manual", help="инструкция для ручной настройки HomeProxy"); add_source_options(manual); manual.add_argument("--node", type=int)
    uci = sub.add_parser("homeproxy-uci", help="готовые UCI-команды HomeProxy"); add_source_options(uci); uci.add_argument("--node", type=int, required=True); uci.add_argument("--section")
    export = sub.add_parser("export-sing-box", help="вывести sing-box outbound JSON"); add_source_options(export); export.add_argument("--node", type=int, required=True); export.add_argument("--output")
    apply = sub.add_parser("apply-sing-box", help="установить ноду в существующий sing-box config"); add_source_options(apply); apply.add_argument("--node", type=int, required=True); apply.add_argument("--config", default="/etc/sing-box/config.json"); apply.add_argument("--service", default="sing-box"); apply.add_argument("--launchd-label", default="system/io.nekohasekai.sing-box")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        if args.command == "download":
            url = args.subscription_url or os.environ.get("VPN_SUBSCRIPTION_URL")
            if not url:
                raise ValueError("укажите --subscription-url или VPN_SUBSCRIPTION_URL")
            target, backup, count = save_subscription(url, args.output)
            print(f"Сохранено: {target}; найдено VLESS-нод: {count}")
            if backup:
                print(f"Backup: {backup}")
            return 0
        nodes = valid_nodes(args)
        if not nodes:
            raise RuntimeError("валидные VLESS Reality-ноды не найдены")
        if args.command == "nodes":
            for index, node in enumerate(nodes, 1):
                print(f"{index:3} {node['name']} {node['host']}:{node['port']} sni={node['sni']}")
        elif args.command == "benchmark":
            results = benchmark(nodes, args.test_url, args.top)
            if not results:
                return 2
            best = results[0]["node"]
            print("\nЛУЧШАЯ НОДА — ПОЛЯ HOMEPROXY")
            print_homeproxy_manual([best])
            if args.apply_best:
                atomic_install_config(best, args.config, args.service, args.launchd_label)
            return 0
        elif args.command == "homeproxy-manual":
            print_homeproxy_manual(select_nodes(nodes, args.node))
        elif args.command == "homeproxy-uci":
            print("\n".join(homeproxy_uci_lines(select_nodes(nodes, args.node)[0], args.section)))
        elif args.command == "export-sing-box":
            data = json.dumps(make_outbound(select_nodes(nodes, args.node)[0]), indent=2, ensure_ascii=False) + "\n"
            if args.output:
                Path(args.output).write_text(data)
            else:
                print(data, end="")
        elif args.command == "apply-sing-box":
            atomic_install_config(select_nodes(nodes, args.node)[0], args.config, args.service, args.launchd_label)
        return 0
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
