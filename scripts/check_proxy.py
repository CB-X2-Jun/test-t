import asyncio
import json
import time
import socks
import ssl
import subprocess
import random
from pathlib import Path
from country_map import COUNTRY_MAP

BASE = Path(__file__).resolve().parent.parent

PROXY_FILE = BASE / "proxy.txt"
PUBLIC_FILE = BASE / "public" / "proxies.json"
HISTORY_FILE = BASE / "data" / "history.json"

FAST_TIMEOUT = 10
DEEP_TIMEOUT = 10

TEST_APIS = [
    ("httpbin.org", 80, "/ip", False),
    ("api.ipify.org", 80, "/?format=json", False),
    ("api.i.pn", 80, "/json", False),
    ("ifconfig.me", 80, "/ip", False),
    ("ipin.io", 80, "/", False),
]

def parse_proxy(line: str):
    proto, rest = line.split("//", 1)
    ip, port, country, anon = rest.strip().split(":")
    proto = proto.replace(":", "")
    return proto, ip, int(port), country, anon

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

# ─────────────────────────────
# 第二阶段：深度检测（status-only）
# ─────────────────────────────
def deep_check(proto, ip, port):
    if proto in ("http"):
        apis = TEST_APIS
        for host, hport, path, use_ssl in apis:
            try:
                s = socks.socksocket()

                # ───────── proxy 类型设置 ─────────
                if proto == "http":
                    s.set_proxy(socks.HTTP, ip, port)

                s.settimeout(DEEP_TIMEOUT)
                s.connect((host, hport))

                if use_ssl:
                    ctx = ssl.create_default_context()
                    ss = ctx.wrap_socket(s, server_hostname=host)
                else:
                    ss = s

                # ───────── 发送 HTTP 请求 ─────────
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: proxy-check\r\n"
                    f"Connection: close\r\n\r\n"
                )
                ss.sendall(req.encode())
                data = ss.recv(256)
                ss.close()

                if data and b"200" in data.split(b"\r\n", 1)[0]:
                    return True
            except Exception:
                continue
        return False
    else:
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

        proto, ip, port, country, anon = parse_proxy(line)
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
                "anonymity": anon,
                "success": 0,
                "total": 0,
            }

        # 每次检测都计入 total
        record["total"] += 1
        
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
