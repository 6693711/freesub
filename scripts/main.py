import os
import re
import json
import base64
import shutil
import asyncio
import urllib.parse
import subprocess
import time
import datetime
import requests
import aiohttp
import yaml
import maxminddb

# ==================== 1. 订阅源与基础配置 ====================
SUBSCRIBE_SOURCES = [
    "https://wild-cloud-9893.heleimail.workers.dev",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TW.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://open.heleimail.workers.dev/",
    "https://www.ermao.net/sub/v2ray/ermao.net",
]

# GitHub 用户名与仓库名（用于拼接首页的 CDN 与 Raw 链接）
REPO_USER = "hezhanleiok"
REPO_NAME = "freesub"

OUTPUT_DIR = "output"
MIHOMO_TEMP_DIR = "/tmp/mihomo_runner"
CONTROLLER_PORT = 9090
MIXED_PORT = 7890
CONTROLLER_SECRET = "freesub-test-token"

UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_=/+")

VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf"
}

RISK_KEYWORDS = [
    "官网", "通知", "返利", "备用", "地址", "购买", "广告", "群", "频道",
    "tg:", "t.me", "traffic", "expire", "reset", "bandwidth", "left", "gb",
    "剩余", "到期", "续费", "测速", "aff", "vip", "free"
]

# 国家代码到中文名称映射（不带臃肿英文全称）
COUNTRY_NAMES = {
    "TW": "中国台湾", "HK": "中国香港", "MO": "中国澳门", "CN": "中国大陆",
    "JP": "日本", "KR": "韩国", "SG": "新加坡", "US": "美国",
    "CA": "加拿大", "GB": "英国", "DE": "德国", "FR": "法国",
    "NL": "荷兰", "RU": "俄罗斯", "AU": "澳大利亚", "IN": "印度",
    "MY": "马来西亚", "TH": "泰国", "VN": "越南", "PH": "菲律宾",
    "ID": "印尼", "TR": "土耳其", "BR": "巴西", "AE": "阿联酋",
    "ZA": "南非", "OTHER": "其他地区"
}


# ==================== 2. 全协议解析与严苛清洗 ====================
def decode_base64(s: str) -> str:
    s = s.strip().replace("\r", "").replace("\n", "")
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        try:
            return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def clean_name(name: str, used_names: set) -> str:
    name = re.sub(r"[\r\n\t:,]+", " ", name).strip()
    if not name:
        name = "node"
    unique_name = name
    idx = 1
    while unique_name in used_names:
        unique_name = f"{name}_{idx}"
        idx += 1
    used_names.add(unique_name)
    return unique_name


def clean_reality_sid(sid: str) -> str:
    """严格校验 Reality short-id，不截断、不修补，非法值直接丢弃"""
    if sid is None:
        return ""
    sid = str(sid).strip().lower()
    if not sid or sid in {"null", "none", "undefined", "nan", "nil", "false", "true"}:
        return ""
    if not all(c in HEX_CHARS for c in sid):
        return ""
    if len(sid) % 2 != 0:
        return ""
    if len(sid) > 16:
        return ""
    return sid


def is_private_host(host: str) -> bool:
    host = host.strip().lower()
    if not host or host in ["127.0.0.1", "localhost", "0.0.0.0"]:
        return True
    if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)", host):
        return True
    return False


def is_valid_clash_proxy(p: dict) -> bool:
    try:
        port = p.get("port")
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False

        server = str(p.get("server", "")).strip()
        if not server or is_private_host(server):
            return False

        name_lower = p.get("name", "").lower()
        if any(kw in name_lower for kw in RISK_KEYWORDS):
            return False

        ptype = p.get("type")
        if ptype in ["vmess", "vless"]:
            uuid = str(p.get("uuid", "")).strip()
            if not UUID_PATTERN.match(uuid):
                return False

            if ptype == "vless" and p.get("reality-opts"):
                ro = p["reality-opts"]
                pbk = str(ro.get("public-key", "")).strip()
                if not pbk or len(pbk) not in (43, 44) or not all(c in BASE64_CHARS for c in pbk):
                    return False
                sid = str(ro.get("short-id", "")).strip()
                if sid:
                    if len(sid) > 16 or len(sid) % 2 != 0 or not all(c in HEX_CHARS for c in sid):
                        return False

        elif ptype == "ss":
            cipher = str(p.get("cipher", "")).lower().strip()
            password = str(p.get("password", "")).strip()
            if cipher not in VALID_SS_CIPHERS or not password:
                return False

        elif ptype in ["trojan", "hysteria2"]:
            password = str(p.get("password", "")).strip()
            if not password:
                return False

        return True
    except Exception:
        return False


def parse_vmess(uri: str, used_names: set):
    try:
        b64_part = uri[8:]
        raw_json = decode_base64(b64_part)
        data = json.loads(raw_json)
        server = str(data.get("add", "")).strip()
        port = int(data.get("port", 0))
        uuid = str(data.get("id", "")).strip()

        if not server or port <= 0 or not uuid:
            return None

        name = clean_name(data.get("ps", f"vmess_{server}_{port}"), used_names)
        net = str(data.get("net", "tcp")).lower()
        tls = str(data.get("tls", "")).lower() == "tls"
        host = str(data.get("host", "")).strip()
        path = str(data.get("path", "")).strip()

        clash_proxy = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": uuid,
            "alterId": int(data.get("aid", 0)),
            "cipher": "auto",
            "udp": True,
        }
        if tls:
            clash_proxy["tls"] = True
            if host:
                clash_proxy["servername"] = host
        if net == "ws":
            clash_proxy["network"] = "ws"
            clash_proxy["ws-opts"] = {"path": path or "/", "headers": {"Host": host} if host else {}}
        elif net == "grpc":
            clash_proxy["network"] = "grpc"
            clash_proxy["grpc-opts"] = {"grpc-service-name": path}

        singbox_out = {
            "type": "vmess",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "security": "auto",
            "alter_id": int(data.get("aid", 0)),
        }
        if tls:
            singbox_out["tls"] = {"enabled": True, "server_name": host or server}
        if net == "ws":
            singbox_out["transport"] = {"type": "ws", "path": path or "/", "headers": {"Host": host} if host else {}}
        elif net == "grpc":
            singbox_out["transport"] = {"type": "grpc", "service_name": path}

        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_vless(uri: str, used_names: set):
    try:
        u = urllib.parse.urlparse(uri)
        uuid = str(u.username or "").strip()
        server = str(u.hostname or "").strip()
        port = u.port
        if not uuid or not server or not port:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"vless_{server}_{port}"
        name = clean_name(raw_name, used_names)

        security = str(params.get("security", "")).lower()
        net = str(params.get("type", "tcp")).lower()
        sni = str(params.get("sni", "")).strip()
        flow = str(params.get("flow", "")).strip()
        fp = str(params.get("fp", "chrome")).strip()
        pbk = str(params.get("pbk", "")).strip()

        raw_sid = params.get("sid") or params.get("short-id") or params.get("shortId") or params.get("short_id") or ""
        sid = clean_reality_sid(raw_sid)

        path = str(params.get("path", "")).strip()
        host = str(params.get("host", "")).strip()
        service_name = str(params.get("serviceName", "")).strip()

        clash_proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True,
        }
        if flow:
            clash_proxy["flow"] = flow
        if security in ["tls", "reality"]:
            clash_proxy["tls"] = True
            if sni:
                clash_proxy["servername"] = sni
            if fp:
                clash_proxy["client-fingerprint"] = fp
            if security == "reality" and pbk:
                clash_proxy["reality-opts"] = {"public-key": str(pbk)}
                if sid:
                    clash_proxy["reality-opts"]["short-id"] = str(sid)

        if net == "ws":
            clash_proxy["network"] = "ws"
            clash_proxy["ws-opts"] = {"path": path or "/", "headers": {"Host": host} if host else {}}
        elif net == "grpc":
            clash_proxy["network"] = "grpc"
            clash_proxy["grpc-opts"] = {"grpc-service-name": service_name or path}

        singbox_out = {
            "type": "vless",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": uuid,
        }
        if flow:
            singbox_out["flow"] = flow
        if security in ["tls", "reality"]:
            singbox_out["tls"] = {
                "enabled": True,
                "server_name": sni or server,
                "utls": {"enabled": True, "fingerprint": fp or "chrome"},
            }
            if security == "reality" and pbk:
                singbox_out["tls"]["reality"] = {"enabled": True, "public_key": str(pbk)}
                if sid:
                    singbox_out["tls"]["reality"]["short_id"] = str(sid)
        if net == "ws":
            singbox_out["transport"] = {"type": "ws", "path": path or "/", "headers": {"Host": host} if host else {}}
        elif net == "grpc":
            singbox_out["transport"] = {"type": "grpc", "service_name": service_name or path}

        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_ss(uri: str, used_names: set):
    try:
        raw_uri = uri
        u = urllib.parse.urlparse(uri)
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else ""
        if "@" in u.netloc:
            user_part, host_part = u.netloc.split("@", 1)
            decoded_user = decode_base64(user_part)
            if ":" in decoded_user:
                method, password = decoded_user.split(":", 1)
            else:
                method, password = user_part.split(":", 1)
            server, port = host_part.split(":", 1)
        else:
            decoded = decode_base64(u.netloc)
            user_part, host_part = decoded.split("@", 1)
            method, password = user_part.split(":", 1)
            server, port = host_part.split(":", 1)

        port = int(port)
        method = method.strip().lower()
        password = password.strip()
        server = server.strip()
        name = clean_name(raw_name or f"ss_{server}_{port}", used_names)

        clash_proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }
        singbox_out = {
            "type": "shadowsocks",
            "tag": name,
            "server": server,
            "server_port": port,
            "method": method,
            "password": password,
        }
        return {"name": name, "raw": raw_uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_trojan(uri: str, used_names: set):
    try:
        u = urllib.parse.urlparse(uri)
        password = str(u.username or "").strip()
        server = str(u.hostname or "").strip()
        port = u.port
        if not password or not server or not port:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"trojan_{server}_{port}"
        name = clean_name(raw_name, used_names)
        sni = str(params.get("sni", server)).strip()

        clash_proxy = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "udp": True,
            "sni": sni,
        }
        singbox_out = {
            "type": "trojan",
            "tag": name,
            "server": server,
            "server_port": port,
            "password": password,
            "tls": {"enabled": True, "server_name": sni},
        }
        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_hy2(uri: str, used_names: set):
    try:
        u = urllib.parse.urlparse(uri)
        password = str(u.username or u.password or "").strip()
        server = str(u.hostname or "").strip()
        port = u.port
        if not server or not port or not password:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"hy2_{server}_{port}"
        name = clean_name(raw_name, used_names)
        sni = str(params.get("sni", server)).strip()
        insecure = params.get("insecure", "0") in ["1", "true"]

        clash_proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
            "sni": sni,
            "skip-cert-verify": insecure,
        }
        singbox_out = {
            "type": "hysteria2",
            "tag": name,
            "server": server,
            "server_port": port,
            "password": password,
            "tls": {"enabled": True, "server_name": sni, "insecure": insecure},
        }
        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_tuic(uri: str, used_names: set):
    try:
        u = urllib.parse.urlparse(uri)
        uuid = str(u.username or "").strip()
        password = str(u.password or "").strip()
        server = str(u.hostname or "").strip()
        port = u.port
        if not server or not port or not uuid:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"tuic_{server}_{port}"
        name = clean_name(raw_name, used_names)
        sni = str(params.get("sni", server)).strip()
        alpn = str(params.get("alpn", "h3")).strip()

        clash_proxy = {
            "name": name,
            "type": "tuic",
            "server": server,
            "port": port,
            "uuid": uuid,
            "password": password,
            "sni": sni,
            "alpn": [alpn],
            "reduce-rtt": True,
            "udp": True,
        }
        singbox_out = {
            "type": "tuic",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "password": password,
            "tls": {"enabled": True, "server_name": sni, "alpn": [alpn]},
        }
        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_socks(uri: str, used_names: set):
    try:
        u = urllib.parse.urlparse(uri)
        server = str(u.hostname or "").strip()
        port = u.port
        if not server or not port:
            return None
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"socks_{server}_{port}"
        name = clean_name(raw_name, used_names)

        clash_proxy = {"name": name, "type": "socks5", "server": server, "port": port}
        if u.username:
            clash_proxy["username"] = u.username
            clash_proxy["password"] = u.password or ""

        singbox_out = {"type": "socks", "tag": name, "server": server, "server_port": port}
        if u.username:
            singbox_out["username"] = u.username
            singbox_out["password"] = u.password or ""

        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_node(uri: str, used_names: set):
    uri = uri.strip()
    node = None
    if uri.startswith("vmess://"):
        node = parse_vmess(uri, used_names)
    elif uri.startswith("vless://"):
        node = parse_vless(uri, used_names)
    elif uri.startswith("ss://"):
        node = parse_ss(uri, used_names)
    elif uri.startswith("trojan://"):
        node = parse_trojan(uri, used_names)
    elif uri.startswith("hysteria2://") or uri.startswith("hy2://"):
        node = parse_hy2(uri, used_names)
    elif uri.startswith("tuic://"):
        node = parse_tuic(uri, used_names)
    elif uri.startswith("socks://") or uri.startswith("socks5://"):
        node = parse_socks(uri, used_names)

    if node and is_valid_clash_proxy(node["clash"]):
        return node
    return None


# ==================== 3. 订阅抓取 ====================
def fetch_all_nodes() -> list:
    print("[*] Fetching subscription sources...")
    raw_lines = set()
    headers = {"User-Agent": "ClashMeta/1.19.0 v2rayN/6.23"}

    for url in SUBSCRIBE_SOURCES:
        try:
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code != 200:
                continue
            content = resp.text.strip()
            if not any(proto in content for proto in ["vmess://", "vless://", "ss://", "trojan://", "hy2://"]):
                decoded = decode_base64(content)
                if decoded:
                    content = decoded
            for line in content.splitlines():
                line = line.strip()
                if any(line.startswith(p) for p in ["vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://", "tuic://", "socks://", "socks5://"]):
                    raw_lines.add(line)
        except Exception as e:
            print(f"[-] Failed to fetch {url}: {e}")

    print(f"[+] Total raw nodes collected: {len(raw_lines)}")
    used_names = set()
    parsed_nodes = []
    for uri in raw_lines:
        node = parse_node(uri, used_names)
        if node:
            parsed_nodes.append(node)
    print(f"[+] Cleaned and validated nodes for Mihomo: {len(parsed_nodes)}")
    return parsed_nodes


# ==================== 4. 预检自愈与内核启动 ====================
def test_and_fix_mihomo_config(clash_proxies: list) -> list:
    os.makedirs(MIHOMO_TEMP_DIR, exist_ok=True)
    if os.path.exists("GeoLite2-Country.mmdb"):
        shutil.copy("GeoLite2-Country.mmdb", f"{MIHOMO_TEMP_DIR}/Country.mmdb")

    current_proxies = list(clash_proxies)
    max_retries = 60

    for attempt in range(max_retries):
        proxy_names = [p["name"] for p in current_proxies]
        config = {
            "mixed-port": MIXED_PORT,
            "mode": "rule",
            "log-level": "info",
            "allow-lan": False,
            "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
            "secret": CONTROLLER_SECRET,
            "geodata-mode": False,
            "proxies": current_proxies,
            "proxy-groups": [
                {"name": "GLOBAL", "type": "select", "proxies": proxy_names}
            ],
        }
        with open(f"{MIHOMO_TEMP_DIR}/config.yaml", "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True)

        res = subprocess.run(
            ["mihomo", "-t", "-d", MIHOMO_TEMP_DIR],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            print(f"[+] Mihomo config pre-check passed! Safe nodes: {len(current_proxies)}")
            return current_proxies

        err = (res.stderr + "\n" + res.stdout).strip()
        match = re.search(r"proxy\s+(\d+):", err, re.IGNORECASE)
        if match:
            bad_idx = int(match.group(1))
            if 0 <= bad_idx < len(current_proxies):
                dropped = current_proxies.pop(bad_idx)
                print(f"[!] Pre-check auto-healed (attempt {attempt + 1}): removed bad proxy at index {bad_idx} ({dropped.get('name')})")
                continue

        print(f"[!] Unhandled syntax error during pre-check:\n{err}")
        break

    return current_proxies


def start_mihomo(clash_proxies: list) -> tuple:
    safe_proxies = test_and_fix_mihomo_config(clash_proxies)
    log_path = f"{MIHOMO_TEMP_DIR}/mihomo.log"
    log_file = open(log_path, "w", encoding="utf-8")

    proc = subprocess.Popen(
        ["mihomo", "-d", MIHOMO_TEMP_DIR],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    for _ in range(40):
        if proc.poll() is not None:
            log_file.close()
            with open(log_path, "r", encoding="utf-8") as f:
                output = f.read()
            raise RuntimeError(f"Mihomo exited unexpectedly. Log:\n{output}")
        try:
            r = requests.get(
                f"http://127.0.0.1:{CONTROLLER_PORT}/version",
                headers={"Authorization": f"Bearer {CONTROLLER_SECRET}"},
                timeout=0.4
            )
            if r.status_code == 200:
                print("[+] Mihomo core started successfully.")
                return proc, safe_proxies
        except Exception:
            time.sleep(0.3)

    log_file.close()
    with open(log_path, "r", encoding="utf-8") as f:
        output = f.read()
    raise RuntimeError(f"Failed to start Mihomo controller within timeout. Log:\n{output}")


# ==================== 5. 两阶段防断流与落地识别 ====================
async def run_delay_ping(proxy_names: list, timeout_ms: int = 3500) -> dict:
    test_url = "http://cp.cloudflare.com/generate_204"
    headers = {"Authorization": f"Bearer {CONTROLLER_SECRET}"}
    timeout = aiohttp.ClientTimeout(total=4.5)
    conn = aiohttp.TCPConnector(limit=50)
    alive = {}

    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        async def check(name):
            enc_name = urllib.parse.quote(name, safe="")
            req_url = f"http://127.0.0.1:{CONTROLLER_PORT}/proxies/{enc_name}/delay?url={test_url}&timeout={timeout_ms}"
            try:
                async with session.get(req_url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alive[name] = data.get("delay", 0)
            except Exception:
                pass

        tasks = [check(name) for name in proxy_names]
        await asyncio.gather(*tasks)
    return alive


def inspect_egress_and_stability(proxy_name: str, country_db, asn_db) -> dict:
    try:
        requests.put(
            f"http://127.0.0.1:{CONTROLLER_PORT}/proxies/GLOBAL",
            headers={"Authorization": f"Bearer {CONTROLLER_SECRET}"},
            json={"name": proxy_name},
            timeout=2.0,
        )
    except Exception:
        return None

    # 留出 0.15 秒让内核完全切路上游连接
    time.sleep(0.15)
    local_proxy = {"http": f"http://127.0.0.1:{MIXED_PORT}", "https": f"http://127.0.0.1:{MIXED_PORT}"}

    # 防劫持与断流二阶验证（必须严格返回 204，拒绝 301/302 反诈跳转）
    try:
        check_204 = requests.get(
            "http://cp.cloudflare.com/generate_204",
            proxies=local_proxy,
            timeout=3.0,
            allow_redirects=False
        )
        if check_204.status_code != 204:
            return None
    except Exception:
        return None

    egress_ip = None
    country_code = None
    is_hosting = None
    as_info = ""

    # 1. 穿透节点出口请求免限频的 ip-api
    try:
        resp = requests.get("http://ip-api.com/json/?fields=status,countryCode,isp,org,as,hosting,query", proxies=local_proxy, timeout=3.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                egress_ip = data.get("query")
                country_code = data.get("countryCode")
                is_hosting = data.get("hosting")
                as_info = f"{data.get('isp', '')} {data.get('org', '')} {data.get('as', '')}".lower()
    except Exception:
        pass

    # 2. 备用端点兜底出口 IP
    if not egress_ip:
        try:
            resp = requests.get("http://api-ipv4.ip.sb/ip", proxies=local_proxy, timeout=3.0)
            if resp.status_code == 200:
                egress_ip = resp.text.strip()
        except Exception:
            pass

    if not egress_ip:
        return None

    # 3. 微软云本地离线高精国家库校验
    if country_db:
        try:
            res = country_db.get(egress_ip)
            if res and "country" in res:
                country_code = res["country"]["iso_code"]
        except Exception:
            pass
    if not country_code:
        country_code = "OTHER"

    # 4. 家宽（Residential）与机房甄别
    if asn_db:
        try:
            asn_res = asn_db.get(egress_ip)
            if asn_res:
                as_info += f" {asn_res.get('autonomous_system_organization', '')}".lower()
        except Exception:
            pass

    datacenter_keywords = [
        "amazon", "aws", "google", "microsoft", "azure", "cloudflare",
        "digitalocean", "hetzner", "ovh", "vultr", "choopa", "linode",
        "oracle", "alibaba", "tencent", "m247", "leaseweb", "datapacket",
        "cogent", "akamai", "fastly", "datacenter", "data center",
        "hosting", "server", "vps", "cloud"
    ]

    is_residential = False
    if is_hosting is False:
        if not any(kw in as_info for kw in datacenter_keywords):
            is_residential = True
    elif is_hosting is None:
        if not any(kw in as_info for kw in datacenter_keywords):
            isp_keywords = ["telecom", "broadband", "fiber", "cable", "hinet", "hkt", "hkbn", "comcast", "charter", "spectrum", "at&t", "verizon", "softbank", "kddi"]
            if any(kw in as_info for kw in isp_keywords):
                is_residential = True

    return {
        "egress_ip": egress_ip,
        "country": country_code.upper(),
        "is_residential": is_residential,
    }


# ==================== 6. 首页 README 动态生成（国旗图标 + 防错行排版） ====================
def render_flag(code: str) -> str:
    """生成不受 Windows 字体限制的彩色国旗图标"""
    code = code.upper()
    if code == "OTHER":
        return "🌐"
    return f'<img src="https://flagcdn.com/20x15/{code.lower()}.png" width="20" height="15" alt="{code}">'


def generate_readme(classified_nodes: list):
    """自动生成无错位、带真实国旗、数据实时同步的首页 README.md"""
    total_nodes = len(classified_nodes)
    res_nodes = [n for n in classified_nodes if n["is_residential"]]
    total_res = len(res_nodes)

    # 统计国家与家宽数量
    country_stats = {}
    res_country_stats = {}
    for n in classified_nodes:
        c = n["country"]
        country_stats[c] = country_stats.get(c, 0) + 1
        if n["is_residential"]:
            res_country_stats[c] = res_country_stats.get(c, 0) + 1

    # 降序排序
    sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)
    sorted_res = sorted(res_country_stats.items(), key=lambda x: x[1], reverse=True)

    update_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 构建家宽表格内容
    res_rows = []
    if sorted_res:
        for c, count in sorted_res:
            c_name = COUNTRY_NAMES.get(c, c)
            flag = render_flag(c)
            loc = f"<nobr>{flag} {c} {c_name}</nobr>"
            v2_cdn = f"https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/residential-by-country/{c}.txt"
            v2_raw = f"https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/residential-by-country/{c}.txt"
            cl_cdn = f"https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/residential-by-country/clash-{c}.yaml"
            cl_raw = f"https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/residential-by-country/clash-{c}.yaml"
            sb_cdn = f"https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/residential-by-country/singbox-{c}.json"
            sb_raw = f"https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/residential-by-country/singbox-{c}.json"

            v2_links = f"<nobr>[⚡CDN]({v2_cdn}) · [🌐Raw]({v2_raw})</nobr>"
            cl_links = f"<nobr>[⚡CDN]({cl_cdn}) · [🌐Raw]({cl_raw})</nobr>"
            sb_links = f"<nobr>[⚡CDN]({sb_cdn}) · [🌐Raw]({sb_raw})</nobr>"

            res_rows.append(f"| {loc} | {count} | {v2_links} | {cl_links} | {sb_links} |")
    else:
        res_rows.append("| <nobr>暂无家宽</nobr> | 0 | - | - | - |")

    # 构建国家分类表格内容
    country_rows = []
    for c, count in sorted_countries:
        c_name = COUNTRY_NAMES.get(c, c)
        flag = render_flag(c)
        loc = f"<nobr>{flag} {c} {c_name}</nobr>"
        v2_cdn = f"https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/by-country/{c}.txt"
        v2_raw = f"https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/by-country/{c}.txt"
        cl_cdn = f"https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/by-country/clash-{c}.yaml"
        cl_raw = f"https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/by-country/clash-{c}.yaml"
        sb_cdn = f"https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/by-country/singbox-{c}.json"
        sb_raw = f"https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/by-country/singbox-{c}.json"

        v2_links = f"<nobr>[⚡CDN]({v2_cdn}) · [🌐Raw]({v2_raw})</nobr>"
        cl_links = f"<nobr>[⚡CDN]({cl_cdn}) · [🌐Raw]({cl_raw})</nobr>"
        sb_links = f"<nobr>[⚡CDN]({sb_cdn}) · [🌐Raw]({sb_raw})</nobr>"

        country_rows.append(f"| {loc} | {count} | {v2_links} | {cl_links} | {sb_links} |")

    res_table_str = "\n".join(res_rows)
    country_table_str = "\n".join(country_rows)

    readme_content = f"""# 🚀 FreeSub - 免费多协议节点自动聚合与测活池

> 🤖 **自动更新时间**：`{update_time}`  
> 🛡️ **节点经过双重防断流探测、抗欺诈拦截与真实落地 Egress IP 归类**。

---

### 🌟 全量测活节点订阅（全协议合并）

| 客户端类型 | 有效节点数 | ⚡ 免翻 CDN 直链 | 🌐 官方 Raw 直链 |
| :--- | :---: | :--- | :--- |
| **🐱 Clash / Mihomo (YAML)** | **{total_nodes}** | [⚡ CDN 订阅](https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/clash.yaml) | [🌐 Raw 订阅](https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/clash.yaml) |
| **⚡ V2RayN (Base64 格式)** | **{total_nodes}** | [⚡ CDN 订阅](https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/v2ray.txt) | [🌐 Raw 订阅](https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/v2ray.txt) |
| **📦 sing-box (JSON 格式)** | **{total_nodes}** | [⚡ CDN 订阅](https://fastly.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@main/output/singbox.json) | [🌐 Raw 订阅](https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/main/output/singbox.json) |

---

### 🏠 按照家宽分类节点订阅（住宅 IP 专区）

> 经 MaxMind ASN 离线库与核心运营商白名单严格甄别，剔除数据中心及云厂商，保留民用住宅宽带。当前可用家宽节点：**{total_res}** 个。

| 家宽地区 | 数量 | V2RayN 订阅 | Clash 订阅 | sing-box 订阅 |
| :--- | :---: | :--- | :--- | :--- |
{res_table_str}

---

### 🌍 按照国家/地区分类节点订阅（落地出口）

| 地区代码 | 数量 | V2RayN 订阅 | Clash 订阅 | sing-box 订阅 |
| :--- | :---: | :--- | :--- | :--- |
{country_table_str}

---

### 📌 订阅使用提示
1. **CDN 直链**：适合国内网络直连拉取，已配置 jsDelivr 全球加速节点。
2. **Raw 直链**：GitHub 官方源文件，适合挂代理环境下获取实时配置。
"""

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    print(f"[+] README.md successfully generated with {total_nodes} alive nodes ({total_res} residential).")


# ==================== 7. 文件分发与导出 ====================
def export_files(classified_nodes: list):
    print("[*] Exporting result files...")
    shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
    os.makedirs(f"{OUTPUT_DIR}/by-country", exist_ok=True)
    os.makedirs(f"{OUTPUT_DIR}/residential-by-country", exist_ok=True)

    def write_clash(path: str, proxies: list):
        cfg = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "proxies": proxies,
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [p["name"] for p in proxies]}],
            "rules": ["MATCH,PROXY"],
        }
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, allow_unicode=True)

    def write_singbox(path: str, outbounds: list):
        cfg = {
            "version": 1,
            "outbounds": outbounds + [{"type": "direct", "tag": "direct"}, {"type": "dns", "tag": "dns-out"}],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

    def write_v2ray(path: str, raw_links: list):
        encoded = base64.b64encode("\n".join(raw_links).encode("utf-8")).decode("utf-8")
        with open(path, "w", encoding="utf-8") as f:
            f.write(encoded)

    all_clash = [n["clash"] for n in classified_nodes]
    all_singbox = [n["singbox"] for n in classified_nodes]
    all_raw = [n["raw"] for n in classified_nodes]

    write_clash(f"{OUTPUT_DIR}/clash.yaml", all_clash)
    write_singbox(f"{OUTPUT_DIR}/singbox.json", all_singbox)
    write_v2ray(f"{OUTPUT_DIR}/v2ray.txt", all_raw)

    res_nodes = [n for n in classified_nodes if n["is_residential"]]
    write_clash(f"{OUTPUT_DIR}/residential-clash.yaml", [n["clash"] for n in res_nodes])
    write_singbox(f"{OUTPUT_DIR}/residential-singbox.json", [n["singbox"] for n in res_nodes])
    write_v2ray(f"{OUTPUT_DIR}/residential.txt", [n["raw"] for n in res_nodes])

    country_map = {}
    res_country_map = {}
    for n in classified_nodes:
        c = n["country"]
        country_map.setdefault(c, []).append(n)
        if n["is_residential"]:
            res_country_map.setdefault(c, []).append(n)

    for c, nodes in country_map.items():
        write_clash(f"{OUTPUT_DIR}/by-country/clash-{c}.yaml", [n["clash"] for n in nodes])
        write_singbox(f"{OUTPUT_DIR}/by-country/singbox-{c}.json", [n["singbox"] for n in nodes])
        write_v2ray(f"{OUTPUT_DIR}/by-country/{c}.txt", [n["raw"] for n in nodes])

    for c, nodes in res_country_map.items():
        write_clash(f"{OUTPUT_DIR}/residential-by-country/clash-{c}.yaml", [n["clash"] for n in nodes])
        write_singbox(f"{OUTPUT_DIR}/residential-by-country/singbox-{c}.json", [n["singbox"] for n in nodes])
        write_v2ray(f"{OUTPUT_DIR}/residential-by-country/{c}.txt", [n["raw"] for n in nodes])

    # 导出文件后，同步重新生成 README.md 首页
    generate_readme(classified_nodes)
    print(f"[SUCCESS] Export complete! Verified stable: {len(classified_nodes)}, Quality Residential: {len(res_nodes)}")


# ==================== 8. 主控流程 ====================
def main():
    nodes = fetch_all_nodes()
    if not nodes:
        print("[-] No valid nodes parsed. Exiting.")
        return

    clash_proxies = [n["clash"] for n in nodes]
    mihomo_proc, safe_clash_proxies = start_mihomo(clash_proxies)

    try:
        safe_names = {p["name"] for p in safe_clash_proxies}
        working_nodes = [n for n in nodes if n["name"] in safe_names]

        # 【阶段一：全量并发初筛】
        print(f"[*] Phase 1: Rapid concurrent ping for {len(working_nodes)} nodes...")
        alive_map = asyncio.run(run_delay_ping([n["name"] for n in working_nodes], timeout_ms=3500))
        print(f"[+] Phase 1 survivors: {len(alive_map)}")
        if not alive_map:
            print("[-] No nodes survived Phase 1.")
            return

        # 【抗断流静置缓冲 3 秒】
        print("[*] Waiting 3 seconds for connection stability check...")
        time.sleep(3)

        # 【阶段 1.5：二次复测剔除闪断/断流节点】
        print("[*] Phase 1.5: Re-testing survivors to eliminate flapping/disconnecting nodes...")
        stable_alive_map = asyncio.run(run_delay_ping(list(alive_map.keys()), timeout_ms=3500))
        stable_nodes = [n for n in working_nodes if n["name"] in stable_alive_map]
        print(f"[+] Stable non-flapping nodes verified: {len(stable_nodes)} (Filtered {len(alive_map) - len(stable_nodes)} dropping nodes)")

        country_db = maxminddb.open_database("GeoLite2-Country.mmdb") if os.path.exists("GeoLite2-Country.mmdb") else None
        asn_db = maxminddb.open_database("GeoLite2-ASN.mmdb") if os.path.exists("GeoLite2-ASN.mmdb") else None

        # 【阶段二：穿透中转落地识别、防劫持验证与家宽甄别】
        print(f"[*] Phase 2: Inspecting egress, anti-interception & residential attributes for {len(stable_nodes)} nodes...")
        final_nodes = []
        for idx, node in enumerate(stable_nodes, 1):
            meta = inspect_egress_and_stability(node["name"], country_db, asn_db)
            if meta:
                node["country"] = meta["country"]
                node["egress_ip"] = meta["egress_ip"]
                node["is_residential"] = meta["is_residential"]
                final_nodes.append(node)
            if idx % 15 == 0 or idx == len(stable_nodes):
                print(f"[*] Processed {idx}/{len(stable_nodes)} nodes (Kept: {len(final_nodes)})...")

        export_files(final_nodes)

    finally:
        mihomo_proc.terminate()
        mihomo_proc.wait()
        shutil.rmtree(MIHOMO_TEMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
