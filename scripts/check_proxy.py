import asyncio
import json
import time
import socks
import ssl
from pathlib import Path
from country_map import COUNTRY_MAP

BASE = Path(__file__).resolve().parent.parent

PROXY_FILE = BASE / "proxy.txt"
PUBLIC_FILE = BASE / "public" / "proxies.json"
HISTORY_FILE = BASE / "data" / "history.json"

FAST_TIMEOUT = 10
DEEP_TIMEOUT = 10

TEST_APIS = [
    ("httpbin.org", 443, "/ip", True),
    ("api.ipify.org", 443, "/?format=json", True),
    ("api.i.pn", 443, "/json", True),
    ("ifconfig.me", 443, "/ip", True),
]

TEST_APIS_SOCKS4 = [
    ("3.95.121.17", 80, "/ip", False),  # HTTP + IPv4
    ("3.210.41.225", 80, "/ip", False),
    ("44.197.91.61", 80, "/ip", False),
    ("52.204.75.48", 80, "/ip", False),
    ("54.236.169.179", 80, "/ip", False),
    ("98.91.115.81", 80, "/ip", False),
]


def parse_proxy(line: str):
    proto, rest = line.split("//", 1)
    ip, port, country = rest.strip().split(":")
    proto = proto.replace(":", "")
    if proto == "http":
        proto = "https"
    return proto, ip, int(port), country


# ─────────────────────────────
# 第一阶段：延迟检测
# ─────────────────────────────
async def check_latency(ip, port):
    start = time.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=FAST_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return int((time.time() - start) * 1000)
    except Exception:
        return None

def socks4_latency(ip, port, timeout=FAST_TIMEOUT):
    import socket, struct, time

    target_ip = "3.210.41.225"
    target_port = 80

    t0 = time.time()
    s = socket.socket()
    s.settimeout(timeout)

    try:
        s.connect((ip, port))

        # SOCKS4 CONNECT
        req = struct.pack(
            "!BBH4sB",
            0x04,          # VN
            0x01,          # CD = CONNECT
            target_port,
            socket.inet_aton(target_ip),
            0x00           # USERID null
        )

        s.sendall(req)
        resp = s.recv(8)

        if len(resp) != 8 or resp[1] != 0x5A:
            return None

        return int((time.time() - t0) * 1000)

    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass
# ─────────────────────────────
# 第二阶段：深度检测（status-only）
# ─────────────────────────────
def deep_check(proto, ip, port):
    apis = TEST_APIS_SOCKS4 if proto == "socks4" else TEST_APIS

    for host, hport, path, use_ssl in apis:
        try:
            s = socks.socksocket()

            if proto == "socks4":
                s.set_proxy(socks.SOCKS4, ip, port)
            elif proto == "socks5":
                s.set_proxy(socks.SOCKS5, ip, port)
            else:
                s.set_proxy(socks.HTTP, ip, port)

            s.settimeout(DEEP_TIMEOUT)
            s.connect((host, hport))

            if use_ssl:
                ctx = ssl.create_default_context()
                ss = ctx.wrap_socket(s, server_hostname=host)
            else:
                ss = s

            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: proxy-check\r\n"
                f"Connection: close\r\n\r\n"
            )
            ss.sendall(req.encode())
            data = ss.recv(256)
            ss.close()

            if not data:
                continue

            status_line = data.split(b"\r\n", 1)[0]
            if b" 200 " in status_line:
                return True

        except Exception:
            continue

    return False


# ─────────────────────────────
# 主流程
# ─────────────────────────────
async def main():
    # 读取历史
    history = {}
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            for i in json.load(f):
                history[i["id"]] = i

    results = []
    loop = asyncio.get_event_loop()
    now = int(time.time())

    for line in PROXY_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        proto, ip, port, country = parse_proxy(line)
        pid = f"{proto}_{ip}_{port}"

        record = history.get(pid)
        if not record:
            record = {
                "id": pid,
                "ip": ip,
                "port": port,
                "protocol": proto,
                "country": country,
                "country_cn": COUNTRY_MAP.get(country, country),
                "success": 0,
                "total": 0,
            }

        # 每次检测都计入 total
        record["total"] += 1

        if proto == "socks4":
            latency = socks4_latency(ip, port)
        else:
            latency = await check_latency(ip, port)

        if latency is None:
            history[pid] = record
            continue

        ok = await loop.run_in_executor(
            None, deep_check, proto, ip, port
        )

        if ok:
            record["success"] += 1
            record["latency"] = latency
            record["last_check"] = now
            results.append(record)

        # 无论成功失败，都写回历史
        history[pid] = record

    HISTORY_FILE.parent.mkdir(exist_ok=True)
    PUBLIC_FILE.parent.mkdir(exist_ok=True)

    # 写全量历史（永不删）
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(list(history.values()), f, ensure_ascii=False, indent=2)

    # 写当前可用节点（给前端）
    with open(PUBLIC_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
