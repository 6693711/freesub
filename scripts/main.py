import os
import re
import json
import base64
import shutil
import asyncio
import urllib.parse
import subprocess
import time
import requests
import aiohttp
import yaml
import maxminddb

# ==================== 1. 订阅源配置 ====================
# 请在此处填入您的订阅源链接（支持订阅 URL 或直接输出 Base64/明文节点的 Raw 链接）
SUBSCRIBE_SOURCES = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
]

OUTPUT_DIR = "output"
MIHOMO_TEMP_DIR = "/tmp/mihomo_runner"
CONTROLLER_PORT = 9090
MIXED_PORT = 7890
CONTROLLER_SECRET = "freesub-test-token"


# ==================== 2. 全协议解析模块 ====================
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


def parse_vmess(uri: str, used_names: set):
    try:
        b64_part = uri[8:]
        raw_json = decode_base64(b64_part)
        data = json.loads(raw_json)
        server = data.get("add")
        port = int(data.get("port", 0))
        uuid = data.get("id")
        if not server or not port or not uuid:
            return None

        name = clean_name(data.get("ps", f"vmess_{server}_{port}"), used_names)
        net = data.get("net", "tcp").lower()
        tls = data.get("tls", "").lower() == "tls"
        host = data.get("host", "")
        path = data.get("path", "")

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
        uuid = u.username
        server = u.hostname
        port = u.port
        if not uuid or not server or not port:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"vless_{server}_{port}"
        name = clean_name(raw_name, used_names)

        security = params.get("security", "").lower()
        net = params.get("type", "tcp").lower()
        sni = params.get("sni", "")
        flow = params.get("flow", "")
        fp = params.get("fp", "chrome")
        pbk = params.get("pbk", "")
        sid = params.get("sid", "")
        path = params.get("path", "")
        host = params.get("host", "")
        service_name = params.get("serviceName", "")

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
            if security == "reality":
                clash_proxy["reality-opts"] = {"public-key": pbk, "short-id": sid}
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
            if security == "reality":
                singbox_out["tls"]["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid}
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
        password = u.username
        server = u.hostname
        port = u.port
        if not password or not server or not port:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"trojan_{server}_{port}"
        name = clean_name(raw_name, used_names)

        sni = params.get("sni", server)
        net = params.get("type", "tcp").lower()

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
        password = u.username or u.password
        server = u.hostname
        port = u.port
        if not server or not port:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"hy2_{server}_{port}"
        name = clean_name(raw_name, used_names)
        sni = params.get("sni", server)
        insecure = params.get("insecure", "0") in ["1", "true"]

        clash_proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password or "",
            "sni": sni,
            "skip-cert-verify": insecure,
        }
        singbox_out = {
            "type": "hysteria2",
            "tag": name,
            "server": server,
            "server_port": port,
            "password": password or "",
            "tls": {"enabled": True, "server_name": sni, "insecure": insecure},
        }
        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_tuic(uri: str, used_names: set):
    try:
        u = urllib.parse.urlparse(uri)
        uuid = u.username
        password = u.password
        server = u.hostname
        port = u.port
        if not server or not port:
            return None

        params = dict(urllib.parse.parse_qsl(u.query))
        raw_name = urllib.parse.unquote(u.fragment) if u.fragment else f"tuic_{server}_{port}"
        name = clean_name(raw_name, used_names)
        sni = params.get("sni", server)
        alpn = params.get("alpn", "h3")

        clash_proxy = {
            "name": name,
            "type": "tuic",
            "server": server,
            "port": port,
            "uuid": uuid or "",
            "password": password or "",
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
            "uuid": uuid or "",
            "password": password or "",
            "tls": {"enabled": True, "server_name": sni, "alpn": [alpn]},
        }
        return {"name": name, "raw": uri, "clash": clash_proxy, "singbox": singbox_out}
    except Exception:
        return None


def parse_socks(uri: str, used_names: set):
    try:
        u = urllib.parse.urlparse(uri)
        server = u.hostname
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
    if uri.startswith("vmess://"):
        return parse_vmess(uri, used_names)
    elif uri.startswith("vless://"):
        return parse_vless(uri, used_names)
    elif uri.startswith("ss://"):
        return parse_ss(uri, used_names)
    elif uri.startswith("trojan://"):
        return parse_trojan(uri, used_names)
    elif uri.startswith("hysteria2://") or uri.startswith("hy2://"):
        return parse_hy2(uri, used_names)
    elif uri.startswith("tuic://"):
        return parse_tuic(uri, used_names)
    elif uri.startswith("socks://") or uri.startswith("socks5://"):
        return parse_socks(uri, used_names)
    return None


# ==================== 3. 订阅抓取与预处理 ====================
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
            # 兼容 Base64 订阅文本
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
    print(f"[+] Successfully parsed nodes: {len(parsed_nodes)}")
    return parsed_nodes


# ==================== 4. 内核拉起与健康检查 ====================
def start_mihomo(clash_proxies: list) -> subprocess.Popen:
    os.makedirs(MIHOMO_TEMP_DIR, exist_ok=True)
    proxy_names = [p["name"] for p in clash_proxies]
    config = {
        "mixed-port": MIXED_PORT,
        "mode": "rule",
        "log-level": "silent",
        "allow-lan": False,
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "secret": CONTROLLER_SECRET,
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "GLOBAL", "type": "select", "proxies": proxy_names}
        ],
    }
    with open(f"{MIHOMO_TEMP_DIR}/config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)

    proc = subprocess.Popen(
        ["mihomo", "-d", MIHOMO_TEMP_DIR],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 等待内核初始化就绪
    for _ in range(30):
        try:
            r = requests.get(f"http://127.0.0.1:{CONTROLLER_PORT}/version", headers={"Authorization": f"Bearer {CONTROLLER_SECRET}"}, timeout=0.5)
            if r.status_code == 200:
                print("[+] Mihomo core started successfully.")
                return proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("Failed to start Mihomo external controller.")


async def batch_health_check(proxy_names: list) -> dict:
    """
    通过内核对所有节点并发进行真实 HTTP 204 通道握手探测
    """
    print(f"[*] Starting concurrent health check for {len(proxy_names)} nodes...")
    alive_map = {}
    test_url = "http://cp.cloudflare.com/generate_204"
    headers = {"Authorization": f"Bearer {CONTROLLER_SECRET}"}
    timeout = aiohttp.ClientTimeout(total=5)
    conn = aiohttp.TCPConnector(limit=50)

    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        async def check(name):
            enc_name = urllib.parse.quote(name, safe="")
            req_url = f"http://127.0.0.1:{CONTROLLER_PORT}/proxies/{enc_name}/delay?url={test_url}&timeout=3800"
            try:
                async with session.get(req_url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alive_map[name] = data.get("delay", 0)
            except Exception:
                pass

        tasks = [check(name) for name in proxy_names]
        await asyncio.gather(*tasks)

    print(f"[+] Alive nodes verified: {len(alive_map)}")
    return alive_map


# ==================== 5. 穿透中转：落地出口识别与家宽检测 ====================
def inspect_egress(proxy_name: str, country_db, asn_db) -> dict:
    """
    让流量真实穿透该节点，从落地端点反显真实出口 IP、国家与住宅属性
    """
    try:
        requests.put(
            f"http://127.0.0.1:{CONTROLLER_PORT}/proxies/GLOBAL",
            headers={"Authorization": f"Bearer {CONTROLLER_SECRET}"},
            json={"name": proxy_name},
            timeout=2,
        )
    except Exception:
        return None

    local_proxy = {"http": f"http://127.0.0.1:{MIXED_PORT}", "https": f"http://127.0.0.1:{MIXED_PORT}"}
    egress_ip = None
    country_code = None
    is_hosting = None
    as_info = ""

    # 1. 优先通过落地出口请求免限频的 ip-api（包含机房 hosting 布尔值字段）
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

    # 2. 备用兜底轻量出口端点
    if not egress_ip:
        try:
            resp = requests.get("http://api-ipv4.ip.sb/ip", proxies=local_proxy, timeout=3)
            if resp.status_code == 200:
                egress_ip = resp.text.strip()
        except Exception:
            pass

    if not egress_ip:
        return None

    # 3. 微软云端离线高精国家识别（本地 MMDB 最高权威校验）
    if country_db:
        try:
            res = country_db.get(egress_ip)
            if res and "country" in res:
                country_code = res["country"]["iso_code"]
        except Exception:
            pass
    if not country_code:
        country_code = "OTHER"

    # 4. 家宽（Residential）属性识别
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
        # 当在线接口未响应时，依托 ASN 规则引擎进行二阶判断
        if not any(kw in as_info for kw in datacenter_keywords):
            isp_keywords = ["telecom", "broadband", "fiber", "cable", "hinet", "hkt", "hkbn", "comcast", "charter", "spectrum", "at&t", "verizon", "softbank", "kddi"]
            if any(kw in as_info for kw in isp_keywords):
                is_residential = True

    return {
        "egress_ip": egress_ip,
        "country": country_code.upper(),
        "is_residential": is_residential,
    }


# ==================== 6. 文件分发与归档导出 ====================
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

    # 1. 全量存活节点导出
    all_clash = [n["clash"] for n in classified_nodes]
    all_singbox = [n["singbox"] for n in classified_nodes]
    all_raw = [n["raw"] for n in classified_nodes]

    write_clash(f"{OUTPUT_DIR}/clash.yaml", all_clash)
    write_singbox(f"{OUTPUT_DIR}/singbox.json", all_singbox)
    write_v2ray(f"{OUTPUT_DIR}/v2ray.txt", all_raw)

    # 2. 全量家宽节点导出
    res_nodes = [n for n in classified_nodes if n["is_residential"]]
    write_clash(f"{OUTPUT_DIR}/residential-clash.yaml", [n["clash"] for n in res_nodes])
    write_singbox(f"{OUTPUT_DIR}/residential-singbox.json", [n["singbox"] for n in res_nodes])
    write_v2ray(f"{OUTPUT_DIR}/residential.txt", [n["raw"] for n in res_nodes])

    # 3. 国家分类导出
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

    print(f"[SUCCESS] Export complete! Total valid: {len(classified_nodes)}, Residential: {len(res_nodes)}")


# ==================== 7. 主控入口 ====================
def main():
    nodes = fetch_all_nodes()
    if not nodes:
        print("[-] No nodes found. Exiting.")
        return

    clash_proxies = [n["clash"] for n in nodes]
    mihomo_proc = start_mihomo(clash_proxies)

    try:
        proxy_names = [n["name"] for n in nodes]
        alive_map = asyncio.run(batch_health_check(proxy_names))
        if not alive_map:
            print("[-] No nodes survived health check.")
            return

        alive_nodes = [n for n in nodes if n["name"] in alive_map]

        country_db = maxminddb.open_database("GeoLite2-Country.mmdb") if os.path.exists("GeoLite2-Country.mmdb") else None
        asn_db = maxminddb.open_database("GeoLite2-ASN.mmdb") if os.path.exists("GeoLite2-ASN.mmdb") else None

        print(f"[*] Inspecting egress and residential info for {len(alive_nodes)} alive nodes...")
        final_nodes = []
        for idx, node in enumerate(alive_nodes, 1):
            meta = inspect_egress(node["name"], country_db, asn_db)
            if meta:
                node["country"] = meta["country"]
                node["egress_ip"] = meta["egress_ip"]
                node["is_residential"] = meta["is_residential"]
                final_nodes.append(node)
            if idx % 20 == 0 or idx == len(alive_nodes):
                print(f"[*] Processed {idx}/{len(alive_nodes)} nodes...")

        export_files(final_nodes)

    finally:
        mihomo_proc.terminate()
        mihomo_proc.wait()
        shutil.rmtree(MIHOMO_TEMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
