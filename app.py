#!/usr/bin/env python3
import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(os.environ.get("XP_BASE_DIR") or Path(__file__).resolve().parent)
DATA_DIR = Path(os.environ.get("XP_DATA_DIR") or (BASE_DIR / "data"))
DB_PATH = DATA_DIR / "xray_pulse.db"
INDEX_HTML_PATH = BASE_DIR / "index.html"
INITIAL_PASSWORD_PATH = DATA_DIR / "initial_password.txt"

REALITY_PORT = int(os.environ.get("XP_REALITY_PORT", "2443"))
CDN_WS_PORT = int(os.environ.get("XP_CDN_WS_PORT", "31297"))
XRAY_API_SERVER = os.environ.get("XP_XRAY_API_SERVER", "127.0.0.1:10085").strip() or "127.0.0.1:10085"
CDN_LOG_PATH = os.environ.get("XP_CDN_LOG_PATH", "/var/log/nginx/cdn-ws.log").strip() or "/var/log/nginx/cdn-ws.log"
CDN_RATE_MAP_PATH = os.environ.get("XP_CDN_RATE_MAP_PATH", "/etc/nginx/conf.d/cdn-rate-map.conf").strip() or "/etc/nginx/conf.d/cdn-rate-map.conf"
DEFAULT_ADMIN_USER = os.environ.get("XP_ADMIN_USER", "admin").strip() or "admin"


def get_default_iface() -> str:
    env_if = os.environ.get("XP_IFACE", "").strip()
    if env_if:
        return env_if
    try:
        with open("/proc/net/route", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception:
        pass
    return "eth0"


def _detect_server_ips() -> set:
    ips = {"127.0.0.1", "::1", "0.0.0.0", "255.255.255.255"}
    for raw in os.environ.get("XP_SERVER_IP", "").split(","):
        val = raw.strip()
        if not val:
            continue
        try:
            ips.add(ipaddress.ip_address(val).compressed.lower())
        except Exception:
            ips.add(val)
    try:
        out = subprocess.check_output(
            ["ip", "-o", "addr", "show", "scope", "global"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        for line in out.splitlines():
            m = re.search(r"\binet6?\s+([0-9a-fA-F:.]+)/", line)
            if m:
                try:
                    ips.add(ipaddress.ip_address(m.group(1)).compressed.lower())
                except Exception:
                    pass
    except Exception:
        pass
    return ips


IFACE = get_default_iface()
SERVER_SELF_IPS = _detect_server_ips()

DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Xray-Pulse 控制台", version="1.1.0", docs_url=None, redoc_url=None, openapi_url=None)


def hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


def get_db():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


@contextmanager
def db_session():
    conn = get_db()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def safe_run(cmd: List[str], *, input_text: Optional[str] = None, timeout: float = 5.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"Subprocess timeout ({timeout}s): {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr="timeout")
    except Exception as e:
        print(f"Subprocess error: {' '.join(cmd)}: {e}")
        return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr=str(e))


def safe_check_output(cmd: List[str], *, timeout: float = 5.0) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""


CF_NETS = [
    ipaddress.ip_network(cidr)
    for cidr in [
        # IPv4
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        # IPv6
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]
]


def canonical_ip(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    if "%" in s:
        return None
    if s.startswith("::ffff:"):
        s = s[7:]
    try:
        ip_obj = ipaddress.ip_address(s)
        if getattr(ip_obj, "ipv4_mapped", None):
            ip_obj = ip_obj.ipv4_mapped
        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_link_local or ip_obj.is_reserved:
            return None
        res = ip_obj.compressed.lower()
        if res in SERVER_SELF_IPS:
            return None
        return res
    except Exception:
        return None


def normalize_ip(ip_str: str) -> str:
    cip = canonical_ip(ip_str)
    return cip if cip else ip_str.strip()


def valid_ip(ip_str: str) -> bool:
    return canonical_ip(ip_str) is not None


def is_ipv6(ip_str: str) -> bool:
    cip = canonical_ip(ip_str)
    if not cip:
        return False
    try:
        return ipaddress.ip_address(cip).version == 6
    except Exception:
        return False


def is_cloudflare_ip(ip_str: str) -> bool:
    cip = canonical_ip(ip_str)
    if not cip:
        return False
    try:
        ip_obj = ipaddress.ip_address(cip)
        return any(ip_obj.version == net.version and ip_obj in net for net in CF_NETS)
    except Exception:
        return False


def safe_float(val, default: float = 0.0, min_v: float = 0.0, max_v: float = 100000.0) -> float:
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return max(min_v, min(f, max_v))
    except Exception:
        return default


def valid_ipv4(ip_str: str) -> bool:
    try:
        s = ip_str.strip()
        if s in SERVER_SELF_IPS:
            return False
        ip_obj = ipaddress.ip_address(s)
        return ip_obj.version == 4 and not ip_obj.is_loopback and not ip_obj.is_multicast and not ip_obj.is_unspecified
    except Exception:
        return False


MIN_PERSIST_BYTES = 51200
STATE_LOCK = asyncio.Lock()
INTERNAL_SETTING_KEYS = {
    "auth_username", "auth_password_hash", "session_secret",
    "cdn_log_offset", "cdn_log_inode", "traffic_reset_ts",
}


def get_initial_password() -> str:
    def read_existing() -> str:
        fd = os.open(INITIAL_PASSWORD_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("初始密码路径不是普通文件")
            if os.name == "posix" and (stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()):
                raise RuntimeError("初始密码文件必须由当前用户拥有且权限为 0600")
            password = f.read().rstrip("\n")
        if not password:
            raise RuntimeError("初始密码文件为空")
        return password

    try:
        return read_existing()
    except FileNotFoundError:
        pass

    password = secrets.token_urlsafe(16)
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, prefix=".initial-password-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.chmod(tmp_path, 0o600)
            f.write(password + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp_path, INITIAL_PASSWORD_PATH)
        except FileExistsError:
            return read_existing()
        if os.name == "posix":
            dir_fd = os.open(DATA_DIR, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        print(f"初始密码已保存至 {INITIAL_PASSWORD_PATH}，请读取后妥善保管")
        return password
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def normalize_stored_client_ips(cur):
    cur.execute(
        """CREATE TABLE IF NOT EXISTS client_ip_migration_backup (
               old_ip TEXT PRIMARY KEY, canonical_ip TEXT NOT NULL, row_json TEXT NOT NULL)"""
    )
    for table in ("client_aliases", "geo_cache", "traffic_resets", "client_deletions"):
        for row in cur.execute(f"SELECT * FROM {table}").fetchall():
            canonical = canonical_ip(row["ip"])
            if not canonical or canonical == row["ip"]:
                continue
            existing = cur.execute(f"SELECT * FROM {table} WHERE ip = ?", (canonical,)).fetchone()
            if existing is None:
                cur.execute(f"UPDATE {table} SET ip = ? WHERE ip = ?", (canonical, row["ip"]))
            elif table == "client_aliases":
                if (row["updated_at"] or 0) > (existing["updated_at"] or 0):
                    cur.execute(
                        "UPDATE client_aliases SET alias = ?, updated_at = ? WHERE ip = ?",
                        (row["alias"], row["updated_at"], canonical),
                    )
                cur.execute("DELETE FROM client_aliases WHERE ip = ?", (row["ip"],))
            elif table == "geo_cache":
                if (row["updated_at"] or 0) > (existing["updated_at"] or 0):
                    cur.execute(
                        """UPDATE geo_cache SET country = ?, region = ?, city = ?, isp = ?, org = ?,
                           asn = ?, updated_at = ? WHERE ip = ?""",
                        (*(row[key] for key in ("country", "region", "city", "isp", "org", "asn", "updated_at")), canonical),
                    )
                cur.execute("DELETE FROM geo_cache WHERE ip = ?", (row["ip"],))
            elif table == "client_deletions":
                cur.execute(
                    "UPDATE client_deletions SET delete_ts = ? WHERE ip = ?",
                    (max(row["delete_ts"], existing["delete_ts"]), canonical),
                )
                cur.execute("DELETE FROM client_deletions WHERE ip = ?", (row["ip"],))
            else:
                cur.execute(
                    "UPDATE traffic_resets SET reset_ts = ? WHERE ip = ?",
                    (max(row["reset_ts"], existing["reset_ts"]), canonical),
                )
                cur.execute("DELETE FROM traffic_resets WHERE ip = ?", (row["ip"],))

    for row in cur.execute("SELECT * FROM clients").fetchall():
        canonical = canonical_ip(row["ip"])
        if not canonical or canonical == row["ip"]:
            continue
        existing = cur.execute("SELECT * FROM clients WHERE ip = ?", (canonical,)).fetchone()
        if existing is None:
            cur.execute("UPDATE clients SET ip = ? WHERE ip = ?", (canonical, row["ip"]))
            continue
        cur.execute(
            "INSERT OR IGNORE INTO client_ip_migration_backup VALUES (?, ?, ?)",
            (row["ip"], canonical, json.dumps(dict(row), ensure_ascii=False)),
        )
        def counters(prefix):
            base_key, last_key = f"base_{prefix}_bytes", f"last_nft_{prefix}"
            source = existing if existing[base_key] or existing[last_key] else row
            return source[base_key] or 0, source[last_key] or 0
        base_up, last_up = counters("up")
        base_down, last_down = counters("down")
        first_seen = min((v for v in (row["first_seen"] or 0, existing["first_seen"] or 0) if v > 0), default=0)
        cur.execute(
            """UPDATE clients SET alias = ?, base_up_bytes = ?, base_down_bytes = ?,
               last_nft_up = ?, last_nft_down = ?, peak_up_bps = ?, peak_down_bps = ?,
               down_limit_mbps = ?, up_limit_mbps = ?, quota_gb = ?, is_whitelisted = ?,
               first_seen = ?, last_seen = ?, is_cdn = ? WHERE ip = ?""",
            (existing["alias"] or row["alias"], base_up, base_down, last_up, last_down,
             max(row["peak_up_bps"] or 0, existing["peak_up_bps"] or 0),
             max(row["peak_down_bps"] or 0, existing["peak_down_bps"] or 0),
             max(row["down_limit_mbps"] or 0, existing["down_limit_mbps"] or 0),
             max(row["up_limit_mbps"] or 0, existing["up_limit_mbps"] or 0),
             max(row["quota_gb"] or 0, existing["quota_gb"] or 0),
             int(bool(row["is_whitelisted"] or existing["is_whitelisted"])),
             first_seen, max(row["last_seen"] or 0, existing["last_seen"] or 0),
             int(bool(row["is_cdn"] or existing["is_cdn"])), canonical),
        )
        cur.execute("DELETE FROM clients WHERE ip = ?", (row["ip"],))


def init_db():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                ip TEXT PRIMARY KEY,
                alias TEXT DEFAULT '',
                base_up_bytes INTEGER DEFAULT 0,
                base_down_bytes INTEGER DEFAULT 0,
                last_nft_up INTEGER DEFAULT 0,
                last_nft_down INTEGER DEFAULT 0,
                peak_up_bps INTEGER DEFAULT 0,
                peak_down_bps INTEGER DEFAULT 0,
                down_limit_mbps REAL DEFAULT 0,
                up_limit_mbps REAL DEFAULT 0,
                quota_gb REAL DEFAULT 0,
                is_whitelisted INTEGER DEFAULT 0,
                first_seen INTEGER DEFAULT 0,
                last_seen INTEGER DEFAULT 0,
                is_cdn INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY,
                reason TEXT DEFAULT '手动拉黑',
                created_at INTEGER DEFAULT 0,
                expires_at INTEGER DEFAULT 0,
                base_dropped_pkts INTEGER DEFAULT 0,
                base_dropped_bytes INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                country TEXT DEFAULT '',
                region TEXT DEFAULT '',
                city TEXT DEFAULT '',
                isp TEXT DEFAULT '',
                org TEXT DEFAULT '',
                asn TEXT DEFAULT '',
                updated_at INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS client_aliases (
                ip TEXT PRIMARY KEY,
                alias TEXT DEFAULT '',
                updated_at INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS revoked_sessions (
                token_hash TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_resets (
                ip TEXT PRIMARY KEY,
                reset_ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS client_deletions (
                ip TEXT PRIMARY KEY,
                delete_ts REAL NOT NULL
            );
            """
        )

        # 平滑迁移 clients 表 is_cdn 字段
        cols = [r["name"] for r in cur.execute("PRAGMA table_info(clients)").fetchall()]
        if "is_cdn" not in cols:
            cur.execute("ALTER TABLE clients ADD COLUMN is_cdn INTEGER DEFAULT 0")

        # 平滑迁移历史硬编码的 'CDN 节点用户'
        cur.execute("UPDATE clients SET is_cdn = 1, alias = '' WHERE alias = 'CDN 节点用户'")
        cur.execute("DELETE FROM client_aliases WHERE alias = 'CDN 节点用户'")

        # 严格清理数据库中任何残留的 Cloudflare Anycast/反向代理 IP
        for r in cur.execute("SELECT ip FROM clients").fetchall():
            if is_cloudflare_ip(r["ip"]):
                cur.execute("DELETE FROM clients WHERE ip = ?", (r["ip"],))
        for r in cur.execute("SELECT ip FROM client_aliases").fetchall():
            if is_cloudflare_ip(r["ip"]):
                cur.execute("DELETE FROM client_aliases WHERE ip = ?", (r["ip"],))

        # Legacy IPv6 spellings must use the same key as CDN authentication.
        for r in cur.execute("SELECT * FROM blacklist").fetchall():
            canonical = canonical_ip(r["ip"])
            if canonical and canonical != r["ip"]:
                existing = cur.execute("SELECT * FROM blacklist WHERE ip = ?", (canonical,)).fetchone()
                if existing:
                    expires_at = 0 if 0 in (r["expires_at"], existing["expires_at"]) else max(r["expires_at"], existing["expires_at"])
                    cur.execute(
                        """UPDATE blacklist SET expires_at = ?,
                           base_dropped_pkts = base_dropped_pkts + ?,
                           base_dropped_bytes = base_dropped_bytes + ? WHERE ip = ?""",
                        (expires_at, r["base_dropped_pkts"], r["base_dropped_bytes"], canonical),
                    )
                else:
                    cur.execute(
                        """INSERT INTO blacklist
                           (ip, reason, created_at, expires_at, base_dropped_pkts, base_dropped_bytes)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (canonical, r["reason"], r["created_at"], r["expires_at"],
                         r["base_dropped_pkts"], r["base_dropped_bytes"]),
                    )
                cur.execute("DELETE FROM blacklist WHERE ip = ?", (r["ip"],))

        normalize_stored_client_ips(cur)

        # 清理小于 50KB（51200 字节）的公网扫描器探测包残留记录（无备注、非白名单、无限速、未拉黑）
        cur.execute(
            """
            DELETE FROM clients
            WHERE (base_up_bytes + base_down_bytes) < ?
              AND ip NOT IN (SELECT ip FROM traffic_resets)
              AND (alias IS NULL OR alias = '')
              AND (is_whitelisted IS NULL OR is_whitelisted = 0)
              AND (down_limit_mbps IS NULL OR down_limit_mbps = 0)
              AND (up_limit_mbps IS NULL OR up_limit_mbps = 0)
              AND (quota_gb IS NULL OR quota_gb = 0)
              AND ip NOT IN (SELECT ip FROM blacklist)
            """,
            (MIN_PERSIST_BYTES,),
        )

        cur.execute(
            """
            INSERT OR IGNORE INTO client_aliases (ip, alias, updated_at)
            SELECT ip, alias, last_seen FROM clients WHERE alias IS NOT NULL AND alias != ''
            """
        )

        defaults = {
            "global_down_limit_mbps": "0",
            "default_ip_down_limit_mbps": "0",
            "default_ip_up_limit_mbps": "0",
            "default_ip_quota_gb": "0",
            "auto_ban_conn_limit": "0",
            "auth_username": DEFAULT_ADMIN_USER,
            "session_secret": secrets.token_hex(32),
        }
        for k, v in defaults.items():
            cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
        password_row = cur.execute(
            "SELECT value FROM settings WHERE key = 'auth_password_hash'"
        ).fetchone()
        if password_row is None:
            initial_password = os.environ.get("XP_INIT_PASS") or get_initial_password()
            cur.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("auth_password_hash", hash_password(initial_password, secrets.token_hex(16))),
            )
        conn.commit()
    finally:
        conn.close()


init_db()


def get_raw_setting(key: str, default: str = "") -> str:
    with db_session() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


SESSION_SECRET = get_raw_setting("session_secret") or secrets.token_hex(32)
LOGIN_FAILURES: Dict[str, List[float]] = {}  # ip -> list of failure timestamps


def check_csrf(request: Request):
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        if origin and host:
            origin_clean = origin.split("://")[-1].split("/")[0].lower()
            host_clean = host.split("/")[0].lower()
            if origin_clean != host_clean:
                raise HTTPException(status_code=403, detail="CSRF check failed: cross-origin forbidden")


def create_session_token(username: str) -> str:
    now_ts = int(time.time())
    exp = now_ts + 86400 * 14  # 14 days
    payload = f"{username}:{exp}:{now_ts}:{secrets.token_hex(16)}"
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: str) -> Optional[str]:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with db_session() as conn:
        if conn.execute(
            "SELECT 1 FROM revoked_sessions WHERE token_hash = ?", (token_hash,)
        ).fetchone():
            return None
    # Current tokens include a random nonce; accept older tokens during transition.
    if token.count(":") in (3, 4):
        parts = token.split(":")
        username, exp_str, issue_str = parts[:3]
        sig = parts[-1]
        try:
            exp = int(exp_str)
            issue_ts = int(issue_str)
        except Exception:
            return None
        if time.time() > exp:
            return None
        min_ts_str = get_raw_setting("session_min_ts", "0")
        try:
            min_ts = int(min_ts_str) if min_ts_str else 0
            if issue_ts < min_ts:
                return None
        except Exception:
            pass
        payload = ":".join(parts[:-1])
        expected = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            expected_user = get_raw_setting("auth_username") or DEFAULT_ADMIN_USER
            if username == expected_user:
                return username
        return None
    # Backwards compatibility for old 2-colon tokens during transition
    if token.count(":") == 2:
        username, exp_str, sig = token.split(":", 2)
        try:
            exp = int(exp_str)
        except Exception:
            return None
        if time.time() > exp:
            return None
        payload = f"{username}:{exp_str}"
        expected = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            expected_user = get_raw_setting("auth_username") or DEFAULT_ADMIN_USER
            if username == expected_user:
                return username
    return None


def require_auth(request: Request) -> str:
    check_csrf(request)
    token = request.cookies.get("xp_session", "")
    user = verify_session_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="请先登录控制台")
    return user


# In-memory state for real-time metrics
STATE = {
    "clients_live": {},  # ip -> dict
    "nft_tracked_ips": set(),
    "nft_banned_ips": set(),
    "nft_ban_retry_at": {},  # ip -> next retry timestamp after an nft failure
    "nft_counters": {},  # ip -> {"up_bytes": 0, "down_bytes": 0, "drop_pkts": 0, "drop_bytes": 0}
    "traffic_mutation_seq": 0,  # reset/delete invalidates socket and nft snapshots
    "tc_reload_pending": False,
    "prev_totals": {},   # ip -> (ts, total_up, total_down)
    "history": [],       # list of {"ts", "up_bps", "down_bps", "online_ips", "active_conns"}
    "inbound_stats": {"reality_conns": 0, "ws_cdn_conns": 0},
    "admin_ips": set(),
    "admin_sessions": {},  # ip -> last_seen_ts (用于管理端安全豁免，超时1小时自动失效)
    "cdn_rate_map_dirty": False,
    "cdn_rate_map_retry_at": 0.0,
    "session_device_map": {},  # token_sig -> viewer_ip (每个浏览器端精确绑定本机 IP，互不干扰)
    "xray_info": {"running": True, "pid": 0, "uptime": "", "mem_mb": 0.0, "cpu_pct": 0.0},
    "sys_info": {"cpu_pct": 0.0, "mem_pct": 0.0, "mem_used_mb": 0, "mem_total_mb": 0, "load": ""},
    "geo_pending": set(),
    "geo_retry_after": {},  # ip -> next eligible lookup time
    "cdn_real_clients": {},  # ip -> {"ip": ip, "last_seen": int, "open_hint": int, "last_open_ts": int}
    "cdn_pending_traffic": {},  # ip -> {"up": int, "down": int, "first_seen": int, "last_seen": int}
    "traffic_reset_map": {},    # ip -> float_ts (清空流量时间戳，防止未断开的 CDN 连接关闭时旧账回灌)
    "client_delete_map": {},    # ip -> float_ts (删除客户端时间戳，防止未断开的旧 CDN 连接关闭时重建记录)
    "cdn_socket_prev": {},   # (local, peer) -> (bytes_sent, bytes_received)
    "cdn_socket_sample_ts": 0.0,
    "xray_api_stats": {"inbounds": {}, "users": {}, "updated_at": 0},
}

with db_session() as conn:
    STATE["traffic_reset_map"] = {
        row["ip"]: float(row["reset_ts"])
        for row in conn.execute("SELECT ip, reset_ts FROM traffic_resets").fetchall()
    }
    STATE["client_delete_map"] = {
        row["ip"]: float(row["delete_ts"])
        for row in conn.execute("SELECT ip, delete_ts FROM client_deletions").fetchall()
    }


def get_all_settings() -> Dict[str, float]:
    with db_session() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    res = {}
    for r in rows:
        if r["key"] in INTERNAL_SETTING_KEYS:
            continue
        try:
            res[r["key"]] = float(r["value"])
        except Exception:
            res[r["key"]] = 0.0
    return res


def default_client_limits(ip: str) -> Tuple[float, float, float]:
    if ip in STATE["admin_ips"]:
        return 0.0, 0.0, 0.0
    settings = get_all_settings()
    return (
        settings.get("default_ip_down_limit_mbps", 0.0),
        settings.get("default_ip_up_limit_mbps", 0.0),
        settings.get("default_ip_quota_gb", 0.0),
    )


def update_setting(key: str, value: Any):
    with db_session() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()


# ==================== NFTABLES KERNEL ACCOUNTING & BLACKLIST ====================

def init_nftables():
    script = """
table inet xray_pulse {
    chain input {
        type filter hook input priority -10; policy accept;
    }
    chain output {
        type filter hook output priority -10; policy accept;
    }
}
"""
    safe_run(["nft", "-f", "-"], input_text=script, timeout=5.0)
    STATE["nft_tracked_ips"].clear()
    STATE["nft_banned_ips"].clear()
    sync_nftables_from_db()


def sync_nftables_from_db():
    r = safe_run(["nft", "-j", "list", "table", "inet", "xray_pulse"], timeout=5.0)
    if r.returncode != 0 or not r.stdout.strip():
        logging.warning("Could not list nft rules for reconciliation: %s", r.stderr)
        return
    try:
        data = json.loads(r.stdout)
        existing_up, existing_down = set(), set()
        existing_ban, existing_ban_udp = set(), set()
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            comment = rule.get("comment", "")
            if comment.startswith("xp_up_"):
                existing_up.add(comment[len("xp_up_"):])
            elif comment.startswith("xp_down_"):
                existing_down.add(comment[len("xp_down_"):])
            elif comment.startswith("xp_ban_udp_"):
                existing_ban_udp.add(comment[len("xp_ban_udp_"):])
            elif comment.startswith("xp_ban_"):
                existing_ban.add(comment[len("xp_ban_"):])
    except Exception:
        logging.exception("Could not parse nft rule listing")
        return

    STATE["nft_tracked_ips"] = existing_up & existing_down
    STATE["nft_banned_ips"] = existing_ban & existing_ban_udp

    with db_session() as conn:
        clients = [row["ip"] for row in conn.execute("SELECT ip FROM clients").fetchall() if not is_cloudflare_ip(row["ip"])]
        bans = [row["ip"] for row in conn.execute("SELECT ip FROM blacklist").fetchall() if not is_cloudflare_ip(row["ip"])]

    for ip in bans:
        if valid_ip(ip) and ip not in STATE["nft_banned_ips"]:
            add_nft_ban_rule(ip, add_tcp=ip not in existing_ban, add_udp=ip not in existing_ban_udp)

    for ip in (existing_ban | existing_ban_udp) - set(bans):
        canonical = canonical_ip(ip)
        if canonical in bans and canonical not in STATE["nft_banned_ips"]:
            continue  # Keep the legacy rule if its replacement failed.
        remove_nft_ban_rule(ip)

    for ip in clients:
        if valid_ip(ip) and ip not in STATE["nft_tracked_ips"]:
            add_nft_counter_rule(ip, add_up=ip not in existing_up, add_down=ip not in existing_down)

    # 清理数据库中已不存在的 IP 遗留的计数规则（扫描器/已删除 IP）
    client_set = set(clients)
    for ip in existing_up | existing_down:
        if ip not in client_set:
            remove_nft_counter_rule(ip)


def _list_nft_rule_comments(kind: str, *extra: str) -> Optional[set]:
    r = safe_run(["nft", "-j", "list", kind, "inet", "xray_pulse", *extra], timeout=5.0)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        data = json.loads(r.stdout)
        comments = set()
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if rule and rule.get("comment"):
                comments.add(rule["comment"])
        return comments
    except Exception:
        return None


def add_nft_counter_rule(ip: str, *, add_up: Optional[bool] = None, add_down: Optional[bool] = None):
    if not valid_ip(ip) or is_cloudflare_ip(ip):
        return False
    if ip in STATE["nft_tracked_ips"]:
        return True
    if add_up is None or add_down is None:
        comments = _list_nft_rule_comments("table")
        if comments is None:
            return False
        add_up = f"xp_up_{ip}" not in comments
        add_down = f"xp_down_{ip}" not in comments
    if not add_up and not add_down:
        STATE["nft_tracked_ips"].add(ip)
        return True
    proto = "ip6" if is_ipv6(ip) else "ip"
    cmds = []
    if add_up:
        cmds.append(f'add rule inet xray_pulse input {proto} saddr {ip} tcp dport 443 counter comment "xp_up_{ip}"')
    if add_down:
        cmds.append(f'add rule inet xray_pulse output {proto} daddr {ip} tcp sport 443 counter comment "xp_down_{ip}"')
    r = safe_run(["nft", "-f", "-"], input_text="\n".join(cmds) + "\n", timeout=5.0)
    if r.returncode == 0:
        STATE["nft_tracked_ips"].add(ip)
        return True
    return False


def remove_nft_counter_rule(ip: str):
    def handles():
        r = safe_run(["nft", "-j", "list", "table", "inet", "xray_pulse"], timeout=5.0)
        if r.returncode != 0 or not r.stdout.strip():
            return None
        try:
            data = json.loads(r.stdout)
            found = []
            for item in data.get("nftables", []):
                rule = item.get("rule")
                if not rule:
                    continue
                comment = rule.get("comment", "")
                chain = rule.get("chain", "")
                handle = rule.get("handle")
                if handle and comment in (f"xp_up_{ip}", f"xp_down_{ip}"):
                    found.append((chain, handle))
            return found
        except Exception:
            return None

    found = handles()
    if found is None:
        return False
    for chain, handle in found:
        r = safe_run(["nft", "delete", "rule", "inet", "xray_pulse", chain, "handle", str(handle)], timeout=5.0)
        if r.returncode != 0:
            return False
    remaining = handles()
    if remaining is None or remaining:
        return False
    STATE["nft_tracked_ips"].discard(ip)
    return True


def add_nft_ban_rule(ip: str, *, add_tcp: Optional[bool] = None, add_udp: Optional[bool] = None):
    if not valid_ip(ip) or is_cloudflare_ip(ip):
        return False
    if ip in STATE["nft_banned_ips"]:
        return True
    if add_tcp is None or add_udp is None:
        comments = _list_nft_rule_comments("chain", "input")
        if comments is None:
            return False
        add_tcp = f"xp_ban_{ip}" not in comments
        add_udp = f"xp_ban_udp_{ip}" not in comments
    if not add_tcp and not add_udp:
        STATE["nft_banned_ips"].add(ip)
        STATE["nft_ban_retry_at"].pop(ip, None)
        kill_ip_connections(ip)
        return True
    proto = "ip6" if is_ipv6(ip) else "ip"
    cmds = []
    if add_tcp:
        cmds.append(f'insert rule inet xray_pulse input {proto} saddr {ip} tcp dport {{ 80, 443 }} counter drop comment "xp_ban_{ip}"')
    if add_udp:
        cmds.append(f'insert rule inet xray_pulse input {proto} saddr {ip} udp dport 443 counter drop comment "xp_ban_udp_{ip}"')
    r = safe_run(["nft", "-f", "-"], input_text="\n".join(cmds) + "\n", timeout=5.0)
    if r.returncode == 0:
        STATE["nft_banned_ips"].add(ip)
        STATE["nft_ban_retry_at"].pop(ip, None)
        kill_ip_connections(ip)
        return True
    return False


def remove_nft_ban_rule(ip: str):
    def handles():
        r = safe_run(["nft", "-j", "list", "chain", "inet", "xray_pulse", "input"], timeout=5.0)
        if r.returncode != 0 or not r.stdout.strip():
            return None
        try:
            data = json.loads(r.stdout)
            found = []
            for item in data.get("nftables", []):
                rule = item.get("rule")
                if not rule:
                    continue
                comment = rule.get("comment", "")
                if comment in (f"xp_ban_{ip}", f"xp_ban_udp_{ip}"):
                    handle = rule.get("handle")
                    if handle:
                        found.append(handle)
            return found
        except Exception:
            return None

    found = handles()
    if found is None:
        return False
    for handle in found:
        r = safe_run(["nft", "delete", "rule", "inet", "xray_pulse", "input", "handle", str(handle)], timeout=5.0)
        if r.returncode != 0:
            return False
    remaining = handles()
    if remaining is None or remaining:
        return False
    STATE["nft_banned_ips"].discard(ip)
    STATE["nft_ban_retry_at"].pop(ip, None)
    return True


def kill_ip_connections(ip: str):
    if not valid_ip(ip) or is_cloudflare_ip(ip):
        return
    if is_ipv6(ip):
        safe_run(["ss", "-K", "dst", f"[{ip}]", "sport", "=", ":443"], timeout=5.0)
    else:
        safe_run(["ss", "-K", "dst", ip, "sport", "=", ":443"], timeout=5.0)


def disconnect_cdn_if_safe(target_ip: str) -> Tuple[bool, str]:
    """
    针对 CDN 用户连接断开的多用户安全保护机制：
    - 若该 IP 不属于 CDN 客户端，直接返回 (False, "")。
    - 若当前底层 WebSocket 回源端口有多个并发套接字，且存在其他最近活跃的 CDN 用户，坚决不断开该端口（避免打断其他用户的连接），
      返回 (False, "其他 CDN 用户在线，该用户的现有连接将在其断线重连时被 Nginx 拦截")。
    - 若 target_ip 是唯一活跃的 CDN 用户或当前套接字数 <= 1，安全执行 ss -K 断开专属会话，
      返回 (True, "已强制断开该 CDN 用户的专属 WebSocket 会话")。
    """
    if target_ip not in STATE["cdn_real_clients"]:
        return False, ""

    now_ts = time.time()
    active_cdn = [
        rip for rip, rinfo in list(STATE["cdn_real_clients"].items())
        if now_ts - rinfo.get("last_seen", 0) < 300
    ]
    other_users = [rip for rip in active_cdn if rip != target_ip]

    # 检查 WebSocket 回源端口当前建立的真实活跃套接字数
    ws_conns = 0
    try:
        raw = safe_check_output(["ss", "-tn", "state", "established", "sport", "=", f":{CDN_WS_PORT}"], timeout=5.0)
        ws_conns = len([l for l in raw.strip().splitlines() if not l.startswith("Recv-Q") and l.strip()])
    except Exception:
        ws_conns = len(other_users)

    if ws_conns > 1 and other_users:
        return False, f"其他 CDN 用户在线（{len(other_users)} 个），为免误伤，该用户的现有连接将在其断线重连时被 Nginx 拦截"

    safe_run(["ss", "-K", "dst", "127.0.0.1", "dport", "=", f":{CDN_WS_PORT}"], timeout=5.0)
    return True, "已强制断开该 CDN 用户的专属 WebSocket 会话"


def sync_cdn_rate_map():
    """
    根据 clients 表及 settings 中的限速配置，动态生成 CDN 限速映射文件（默认 /etc/nginx/conf.d/cdn-rate-map.conf），
    并平滑重载 Nginx。写入前对比内容无变化绝不 reload Nginx。
    """
    try:
        with db_session() as conn:
            settings = get_all_settings()
            def_down = safe_float(settings.get("default_ip_down_limit_mbps", 0.0))
            def_rate_str = f"{max(8, int(def_down * 125))}k" if def_down > 0 else "0"
            rows = conn.execute("SELECT ip, down_limit_mbps FROM clients ORDER BY ip").fetchall()

        lines = ["map $http_cf_connecting_ip $cdn_rate {\n", f"    default {def_rate_str};\n"]
        rates = {}
        for r in rows:
            ip = r["ip"]
            if valid_ip(ip) and not is_cloudflare_ip(ip):
                rates[ip] = safe_float(r["down_limit_mbps"])
        for ip in STATE["admin_ips"]:
            if valid_ip(ip) and not is_cloudflare_ip(ip):
                rates.setdefault(ip, 0.0)
        for ip, down_val in sorted(rates.items()):
            if down_val > 0:
                rate_k = max(8, int(down_val * 125))
                lines.append(f"    {ip} {rate_k}k;\n")
            elif def_down > 0:
                lines.append(f"    {ip} 0;\n")
        lines.append("}\n")
        conf_str = "".join(lines)

        target_path = CDN_RATE_MAP_PATH
        previous_conf = None
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as ef:
                previous_conf = ef.read()
            if previous_conf == conf_str:
                return

        target_dir = os.path.dirname(target_path) or "."
        tmp_fd, tmp_path = tempfile.mkstemp(dir=target_dir, prefix=".cdn-rate-", suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(conf_str)
            os.replace(tmp_path, target_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            raise

        try:
            t = safe_run(["nginx", "-t"], timeout=5.0)
            if t.returncode != 0:
                raise RuntimeError(f"nginx -t failed: {t.stderr}")
            reload_result = safe_run(["nginx", "-s", "reload"], timeout=5.0)
            if reload_result.returncode != 0:
                raise RuntimeError(f"nginx reload failed: {reload_result.stderr}")
        except Exception:
            if previous_conf is None:
                os.remove(target_path)
            else:
                rollback_fd, rollback_path = tempfile.mkstemp(dir=target_dir, prefix=".cdn-rate-rollback-", suffix=".tmp")
                try:
                    with os.fdopen(rollback_fd, "w", encoding="utf-8") as f:
                        f.write(previous_conf)
                    os.replace(rollback_path, target_path)
                finally:
                    if os.path.exists(rollback_path):
                        os.remove(rollback_path)
            raise
    except Exception as e:
        print(f"sync_cdn_rate_map error: {e}")
        raise


async def sync_cdn_rate_map_with_retry(changed: bool = False) -> bool:
    # Called while STATE_LOCK is held so all Nginx policy writes are serialized.
    if changed:
        STATE["cdn_rate_map_dirty"] = True
        STATE["cdn_rate_map_retry_at"] = 0.0
    if not STATE["cdn_rate_map_dirty"]:
        return True
    if time.time() < STATE["cdn_rate_map_retry_at"]:
        return False
    try:
        await asyncio.to_thread(sync_cdn_rate_map)
    except Exception:
        STATE["cdn_rate_map_retry_at"] = time.time() + 30
        logging.exception("Failed to sync CDN rate map; retrying in 30 seconds")
        return False
    else:
        STATE["cdn_rate_map_dirty"] = False
        return True


async def refresh_network_policy_after_delete() -> bool:
    # Called after the DB commit, while STATE_LOCK is held. Return whether a retry is pending.
    try:
        await asyncio.to_thread(apply_tc_limits)
    except Exception:
        STATE["tc_reload_pending"] = True
        logging.exception("Failed to refresh tc after client deletion; telemetry will retry")
    else:
        STATE["tc_reload_pending"] = False
    cdn_ok = await sync_cdn_rate_map_with_retry(changed=True)
    return STATE["tc_reload_pending"] or not cdn_ok


def query_xray_api_stats():
    """
    通过 Xray Stats API 地址原生查询 Xray 内核 StatsService 统计数据
    """
    try:
        r = subprocess.run(
            ["xray", "api", "statsquery", f"--server={XRAY_API_SERVER}"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
            inbounds = {}
            users = {}
            for item in data.get("stat", []):
                name = item.get("name", "")
                val = item.get("value", 0)
                parts = name.split(">>>")
                if len(parts) == 4:
                    cat, entity, _, direction = parts
                    if cat == "inbound":
                        inbounds.setdefault(entity, {"uplink": 0, "downlink": 0})
                        inbounds[entity][direction] = val
                    elif cat == "user":
                        users.setdefault(entity, {"uplink": 0, "downlink": 0})
                        users[entity][direction] = val
            STATE["xray_api_stats"] = {
                "inbounds": inbounds,
                "users": users,
                "updated_at": int(time.time()),
            }
    except Exception:
        pass


_last_nft_warning_at = -60.0


def warn_nft_poll(message: str):
    global _last_nft_warning_at
    now = time.monotonic()
    if now - _last_nft_warning_at >= 60.0:
        logging.warning("nft counters unavailable: %s", message.replace("\n", " ")[:200])
        _last_nft_warning_at = now


def poll_nft_counters() -> Optional[Dict[str, Dict[str, int]]]:
    r = safe_run(["nft", "-j", "list", "table", "inet", "xray_pulse"], timeout=5.0)
    res: Dict[str, Dict[str, int]] = {}
    if r.returncode != 0 or not r.stdout.strip():
        warn_nft_poll(r.stderr or "empty output")
        return None
    try:
        data = json.loads(r.stdout)
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            comment = rule.get("comment", "")
            if not comment.startswith("xp_"):
                continue
            pkts = 0
            bts = 0
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    pkts = int(expr["counter"].get("packets", 0))
                    bts = int(expr["counter"].get("bytes", 0))
                    break
            if comment.startswith("xp_up_"):
                ip = comment[len("xp_up_"):]
                res.setdefault(ip, {"up_bytes": 0, "down_bytes": 0, "drop_pkts": 0, "drop_bytes": 0})
                res[ip]["up_bytes"] += bts
            elif comment.startswith("xp_down_"):
                ip = comment[len("xp_down_"):]
                res.setdefault(ip, {"up_bytes": 0, "down_bytes": 0, "drop_pkts": 0, "drop_bytes": 0})
                res[ip]["down_bytes"] += bts
            elif comment.startswith("xp_ban_udp_"):
                ip = comment[len("xp_ban_udp_"):]
                res.setdefault(ip, {"up_bytes": 0, "down_bytes": 0, "drop_pkts": 0, "drop_bytes": 0})
                res[ip]["drop_pkts"] += pkts
                res[ip]["drop_bytes"] += bts
            elif comment.startswith("xp_ban_"):
                ip = comment[len("xp_ban_"):]
                res.setdefault(ip, {"up_bytes": 0, "down_bytes": 0, "drop_pkts": 0, "drop_bytes": 0})
                res[ip]["drop_pkts"] += pkts
                res[ip]["drop_bytes"] += bts
    except Exception as e:
        warn_nft_poll(f"invalid output: {e}")
        return None
    return res


# ==================== LINUX TC BANDWIDTH SHAPER (PORT 443 ONLY) ====================

def apply_tc_limits():
    """
    Linux TC HTB 流量整形：
    1. 无损检查：若无任何单用户/全局限速，且当前根队列已是 fq 且无 ingress，直接跳过，避免中断在途流量。
    2. IPv6 双栈支持：采用固定偏移 at 40 (sport) 与 at 42 (dport) 精确匹配 TCP 443 端口。
    """
    with db_session() as conn:
        rows = conn.execute(
            "SELECT ip, down_limit_mbps, up_limit_mbps FROM clients WHERE down_limit_mbps > 0 OR up_limit_mbps > 0"
        ).fetchall()
    clients = [r for r in rows if valid_ip(r["ip"]) and not is_cloudflare_ip(r["ip"])]
    settings = get_all_settings()
    global_down = safe_float(settings.get("global_down_limit_mbps", 0.0))
    if sum(safe_float(r["down_limit_mbps"]) > 0 for r in clients) > 65278:
        raise RuntimeError("Too many per-client download limits for tc class IDs")

    if not clients and global_down <= 0:
        qdisc_out = ""
        try:
            qdisc_out = subprocess.check_output(["tc", "qdisc", "show", "dev", IFACE], text=True, stderr=subprocess.DEVNULL, timeout=5.0)
        except Exception:
            pass
        if "qdisc ingress " in qdisc_out:
            subprocess.run(["tc", "qdisc", "del", "dev", IFACE, "ingress"], capture_output=True, timeout=5.0, check=True)
        if "qdisc htb " in qdisc_out or ("qdisc fq " not in qdisc_out and qdisc_out):
            subprocess.run(["tc", "qdisc", "replace", "dev", IFACE, "root", "fq"], capture_output=True, timeout=5.0, check=True)
        return

    try:
        current_qdisc = subprocess.check_output(
            ["tc", "qdisc", "show", "dev", IFACE], text=True,
            stderr=subprocess.DEVNULL, timeout=5.0)
    except Exception:
        current_qdisc = ""
    root_handle = "3:" if re.search(r"\bqdisc\s+\S+\s+1:\s+root\b", current_qdisc) else "1:"
    cmds = [
        f"qdisc replace dev {IFACE} root handle {root_handle} htb default 9999",
        f"class add dev {IFACE} parent {root_handle} classid {root_handle}1 htb rate 10000mbit ceil 10000mbit",
        f"class add dev {IFACE} parent {root_handle}1 classid {root_handle}9999 htb rate 10000mbit ceil 10000mbit",
        f"qdisc add dev {IFACE} parent {root_handle}9999 handle 9999: fq_codel",
    ]

    parent_443 = f"{root_handle}1"
    if global_down > 0:
        rate_kbit = max(100, int(global_down * 1024))
        cmds.append(f"class add dev {IFACE} parent {root_handle}1 classid {root_handle}2 htb rate {rate_kbit}kbit ceil {rate_kbit}kbit")
        cmds.append(f"qdisc add dev {IFACE} parent {root_handle}2 handle 2: fq_codel")
        parent_443 = f"{root_handle}2"

    class_idx = 0x100
    for row in clients:
        ip = row["ip"]
        down_mbps = safe_float(row["down_limit_mbps"])
        if down_mbps > 0:
            if class_idx == 0x9999:
                class_idx += 1  # 1:9999 is the default class.
            rate_kbit = max(64, int(down_mbps * 1024))
            cid = f"{class_idx:x}"
            class_idx += 1
            cmds.append(f"class add dev {IFACE} parent {parent_443} classid {root_handle}{cid} htb rate {rate_kbit}kbit ceil {rate_kbit}kbit")
            cmds.append(f"qdisc add dev {IFACE} parent {root_handle}{cid} handle {cid}: fq_codel")
            if is_ipv6(ip):
                cmds.append(
                    f"filter add dev {IFACE} protocol ipv6 parent {root_handle}0 prio 11 u32 match ip6 dst {ip}/128 match ip6 protocol 6 0xff match u16 0x01bb 0xffff at 40 flowid {root_handle}{cid}"
                )
            else:
                cmds.append(
                    f"filter add dev {IFACE} protocol ip parent {root_handle}0 prio 10 u32 match ip dst {ip}/32 match ip sport 443 0xffff flowid {root_handle}{cid}"
                )

    if global_down > 0:
        cmds.append(f"filter add dev {IFACE} protocol ip parent {root_handle}0 prio 20 u32 match ip sport 443 0xffff flowid {root_handle}2")
        cmds.append(f"filter add dev {IFACE} protocol ipv6 parent {root_handle}0 prio 21 u32 match ip6 protocol 6 0xff match u16 0x01bb 0xffff at 40 flowid {root_handle}2")

    try:
        subprocess.run(["tc", "-b", "-"], input="\n".join(cmds) + "\n", text=True, capture_output=True, timeout=5.0, check=True)
    except Exception:
        # A failed batch may leave a partially built HTB tree; keep traffic flowing.
        try:
            subprocess.run(["tc", "qdisc", "replace", "dev", IFACE, "root", "fq"], capture_output=True, timeout=5.0, check=True)
        except Exception:
            logging.exception("Failed to restore a forwarding root qdisc after tc batch error")
        raise

    subprocess.run(["tc", "qdisc", "del", "dev", IFACE, "ingress"], capture_output=True, timeout=5.0)
    up_clients = [r for r in clients if safe_float(r["up_limit_mbps"]) > 0]
    if up_clients:
        ing_cmds = [f"qdisc add dev {IFACE} handle ffff: ingress"]
        for row in up_clients:
            ip = row["ip"]
            up_mbps = safe_float(row["up_limit_mbps"])
            rate_kbit = max(64, int(up_mbps * 1024))
            burst_k = max(32, int(rate_kbit / 8))
            if is_ipv6(ip):
                ing_cmds.append(
                    f"filter add dev {IFACE} parent ffff: protocol ipv6 prio 11 u32 match ip6 src {ip}/128 match ip6 protocol 6 0xff match u16 0x01bb 0xffff at 42 police rate {rate_kbit}kbit burst {burst_k}k drop flowid :1"
                )
            else:
                ing_cmds.append(
                    f"filter add dev {IFACE} parent ffff: protocol ip prio 10 u32 match ip src {ip}/32 match ip dport 443 0xffff police rate {rate_kbit}kbit burst {burst_k}k drop flowid :1"
                )
        subprocess.run(["tc", "-b", "-"], input="\n".join(ing_cmds) + "\n", text=True, capture_output=True, timeout=5.0, check=True)


# ==================== GEOIP RESOLVER ====================

def queue_geo_ip(raw_ip: str):
    ip = canonical_ip(raw_ip)
    if not ip or time.time() < STATE["geo_retry_after"].get(ip, 0):
        return
    if len(STATE["geo_pending"]) < 1024:
        STATE["geo_pending"].add(ip)
    if len(STATE["geo_retry_after"]) > 4096:
        now = time.time()
        for old_ip, retry_at in list(STATE["geo_retry_after"].items()):
            if retry_at <= now:
                STATE["geo_retry_after"].pop(old_ip, None)
        for old_ip in list(STATE["geo_retry_after"])[:max(0, len(STATE["geo_retry_after"]) - 4096)]:
            STATE["geo_retry_after"].pop(old_ip, None)


async def geo_worker():
    while True:
        await asyncio.sleep(1.0)
        if not STATE["geo_pending"]:
            continue
        raw_ip = STATE["geo_pending"].pop()
        ip = canonical_ip(raw_ip)
        if not ip:
            continue
        STATE["geo_retry_after"][ip] = time.time() + 300
        with db_session() as conn:
            row = conn.execute("SELECT ip, updated_at FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
            if row and (time.time() - row["updated_at"] < 86400 * 7):
                STATE["geo_retry_after"][ip] = row["updated_at"] + 86400 * 7
                continue

        try:
            url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp,org,as"
            loop = asyncio.get_event_loop()
            def fetch():
                req = urllib.request.Request(url, headers={"User-Agent": "Xray-Pulse/1.1"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    return json.loads(resp.read().decode("utf-8", errors="ignore"))
            data = await loop.run_in_executor(None, fetch)
            if data.get("status") == "success":
                with db_session() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO geo_cache (ip, country, region, city, isp, org, asn, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ip,
                            data.get("country", ""),
                            data.get("regionName", ""),
                            data.get("city", ""),
                            data.get("isp", ""),
                            data.get("org", ""),
                            data.get("as", ""),
                            int(time.time()),
                        ),
                    )
                    conn.commit()
                STATE["geo_retry_after"][ip] = time.time() + 86400 * 7
        except Exception:
            pass


# ==================== SYSTEM & SOCKET TELEMETRY COLLECTOR ====================

_prev_cpu = (0, 0)

def read_sys_and_xray_info():
    global _prev_cpu
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
        parts = [int(x) for x in line.split()[1:]]
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
        total = sum(parts)
        prev_total, prev_idle = _prev_cpu
        _prev_cpu = (total, idle)
        cpu_pct = 0.0
        if prev_total > 0 and total > prev_total:
            cpu_pct = round(100.0 * (1.0 - (idle - prev_idle) / (total - prev_total)), 1)

        mem_total = 0
        mem_avail = 0
        with open("/proc/meminfo", "r") as f:
            for l in f:
                if l.startswith("MemTotal:"):
                    mem_total = int(l.split()[1]) // 1024
                elif l.startswith("MemAvailable:"):
                    mem_avail = int(l.split()[1]) // 1024
        mem_used = max(0, mem_total - mem_avail)
        mem_pct = round(100.0 * mem_used / mem_total, 1) if mem_total else 0.0
        with open("/proc/loadavg", "r") as f:
            load_str = " / ".join(f.read().split()[:3])

        STATE["sys_info"] = {
            "cpu_pct": cpu_pct,
            "mem_pct": mem_pct,
            "mem_used_mb": mem_used,
            "mem_total_mb": mem_total,
            "load": load_str,
        }
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["ps", "-C", "xray", "-o", "pid=,etimes=,rss=,%cpu="], text=True
        ).strip()
        if out:
            first = out.splitlines()[0].split()
            pid = int(first[0])
            etimes = int(first[1])
            rss_mb = round(int(first[2]) / 1024.0, 1)
            xcpu = float(first[3])
            days = etimes // 86400
            hours = (etimes % 86400) // 3600
            mins = (etimes % 3600) // 60
            uptime_str = f"{days}天 {hours}小时" if days > 0 else f"{hours}小时 {mins}分"
            STATE["xray_info"] = {
                "running": True,
                "pid": pid,
                "uptime": uptime_str,
                "mem_mb": rss_mb,
                "cpu_pct": xcpu,
            }
            query_xray_api_stats()
        else:
            STATE["xray_info"] = {"running": False, "pid": 0, "uptime": "已停止", "mem_mb": 0.0, "cpu_pct": 0.0}
    except Exception:
        STATE["xray_info"] = {"running": False, "pid": 0, "uptime": "已停止", "mem_mb": 0.0, "cpu_pct": 0.0}


def parse_addr_port(s: str) -> Tuple[str, int]:
    s = s.strip()
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
        if m:
            host = m.group(1)
            port = int(m.group(2))
            clean_host = canonical_ip(host) or host
            return clean_host, port
    idx = s.rfind(":")
    if idx != -1:
        ip = s[:idx]
        try:
            port = int(s[idx + 1:])
            clean_ip = canonical_ip(ip) or ip
            return clean_ip, port
        except Exception:
            pass
    clean_s = canonical_ip(s) or s
    return clean_s, 0


def collect_sockets(cdn_real_clients: Optional[Dict[str, dict]] = None,
                    cdn_socket_prev: Optional[Dict[tuple, tuple]] = None):
    if cdn_real_clients is None:
        cdn_real_clients = {ip: dict(info) for ip, info in STATE["cdn_real_clients"].items()}
    if cdn_socket_prev is None:
        cdn_socket_prev = {}
    try:
        raw = subprocess.check_output(["ss", "-tinp", "state", "established"], text=True, stderr=subprocess.DEVNULL, timeout=5.0)
    except Exception:
        return {}, 0, 0, None

    lines = raw.splitlines()
    clients_443: Dict[str, dict] = {}
    reality_conns = 0
    ws_cdn_conns = 0
    cdn_down_bytes = 0
    cdn_up_bytes = 0
    cdn_active_total_bytes = 0
    cdn_socket_now = {}

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line or line.startswith("Recv-Q"):
            i += 1
            continue
        parts = line.split()
        if len(parts) < 4:
            i += 1
            continue
        local_str = parts[2]
        peer_str = parts[3]
        proc_str = " ".join(parts[4:]) if len(parts) > 4 else ""

        tcp_info = ""
        if i + 1 < len(lines) and (lines[i + 1].startswith("\t") or lines[i + 1].startswith(" ")):
            tcp_info = lines[i + 1].strip()
            i += 2
        else:
            i += 1

        lip, lport = parse_addr_port(local_str)
        pip, pport = parse_addr_port(peer_str)

        if lip == "127.0.0.1" and lport == REALITY_PORT:
            reality_conns += 1
            continue
        if lip == "127.0.0.1" and lport == CDN_WS_PORT:
            ws_cdn_conns += 1
            m_bs = re.search(r"bytes_sent:(\d+)", tcp_info)
            m_br = re.search(r"bytes_received:(\d+)", tcp_info)
            key = (local_str, peer_str)
            sent = int(m_bs.group(1)) if m_bs else 0
            received = int(m_br.group(1)) if m_br else 0
            cdn_active_total_bytes += sent + received
            cdn_socket_now[key] = (sent, received)
            previous = cdn_socket_prev.get(key)
            if previous:
                cdn_down_bytes += max(0, sent - previous[0])
                cdn_up_bytes += max(0, received - previous[1])
            continue

        if '"xray"' in proc_str and lip != "127.0.0.1" and pip != "127.0.0.1" and lport != 443:
            continue

        if lport == 443 and valid_ip(pip):
            if is_cloudflare_ip(pip):
                # Cloudflare Anycast/反向代理节点回源连接，坚决不作为客户端显示或入库
                continue
            c = clients_443.setdefault(
                pip,
                {
                    "ip": pip,
                    "conns": 0,
                    "direct_conns": 0,
                    "rtts": [],
                    "min_rtts": [],
                    "ss_down_bytes": 0,
                    "ss_up_bytes": 0,
                },
            )
            c["conns"] += 1
            c["direct_conns"] += 1
            m_bs = re.search(r"bytes_sent:(\d+)", tcp_info)
            m_br = re.search(r"bytes_received:(\d+)", tcp_info)
            m_rtt = re.search(r"rtt:([\d\.]+)/", tcp_info)
            m_minrtt = re.search(r"minrtt:([\d\.]+)", tcp_info)
            if m_bs:
                c["ss_down_bytes"] += int(m_bs.group(1))
            if m_br:
                c["ss_up_bytes"] += int(m_br.group(1))
            if m_rtt:
                c["rtts"].append(float(m_rtt.group(1)))
            if m_minrtt:
                c["min_rtts"].append(float(m_minrtt.group(1)))

    now_ts = time.time()
    # 仅当底层 VLESS-WS CDN 节点 (31297) 有实际客户端活动连接时，才展示对应 CDN 代理用户
    if ws_cdn_conns > 0:
        active_real_cdn_ips = [
            rip for rip, rinfo in cdn_real_clients.items()
            if ((rinfo.get("open_hint", 0) > 0 and now_ts - rinfo.get("last_seen", 0) < 3600)
                or (now_ts - rinfo.get("last_seen", 0) < 180))
            and not is_cloudflare_ip(rip)
        ]
        if active_real_cdn_ips:
            # 优先挑选握手活跃或最近 180s 活跃的客户端，防止离线用户长时间平分在线速率
            active_real_cdn_ips.sort(
                key=lambda x: (
                    1 if cdn_real_clients[x].get("open_hint", 0) > 0 else 0,
                    cdn_real_clients[x].get("last_seen", 0),
                ),
                reverse=True,
            )
            active_count = min(ws_cdn_conns, len(active_real_cdn_ips))
            down_per_client = cdn_down_bytes // max(1, active_count)
            up_per_client = cdn_up_bytes // max(1, active_count)
            active_bytes_per_client = cdn_active_total_bytes // max(1, active_count)
            conns_per_client = max(1, ws_cdn_conns // max(1, active_count))

            for i in range(active_count):
                real_ip = active_real_cdn_ips[i]
                c = clients_443.setdefault(
                    real_ip,
                    {
                        "ip": real_ip,
                        "conns": 0,
                        "direct_conns": 0,
                        "rtts": [],
                        "min_rtts": [],
                        "ss_down_bytes": 0,
                        "ss_up_bytes": 0,
                        "is_cdn": True,
                    },
                )
                c["cdn_conns"] = conns_per_client
                c["conns"] = c["direct_conns"] + conns_per_client
                c["cdn_down_delta"] = down_per_client
                c["cdn_up_delta"] = up_per_client
                c["cdn_active_bytes"] = active_bytes_per_client
                c["is_cdn"] = True

    return clients_443, reality_conns, ws_cdn_conns, cdn_socket_now


async def telemetry_loop():
    tc_reload_pending = False
    tc_retry_at = 0.0
    try:
        async with STATE_LOCK:
            await asyncio.to_thread(init_nftables)
    except Exception as e:
        print("init_nftables error:", e)
    try:
        async with STATE_LOCK:
            await asyncio.to_thread(apply_tc_limits)
    except Exception as e:
        print("apply_tc_limits error:", e)
        tc_reload_pending = True
        tc_retry_at = time.time() + 30
    tick = 0
    while True:
        t0 = time.time()
        try:
            if tick % 2 == 0:
                await asyncio.to_thread(read_sys_and_xray_info)

            async with STATE_LOCK:
                sample_seq = STATE["traffic_mutation_seq"]
                cdn_snapshot = {ip: dict(info) for ip, info in STATE["cdn_real_clients"].items()}
                cdn_socket_prev = dict(STATE["cdn_socket_prev"])
            clients_443, reality_conns, ws_cdn_conns, cdn_socket_now = await asyncio.to_thread(
                collect_sockets, cdn_snapshot, cdn_socket_prev)

            settings = get_all_settings()
            def_down_limit = settings.get("default_ip_down_limit_mbps", 0.0)
            def_up_limit = settings.get("default_ip_up_limit_mbps", 0.0)
            def_quota_gb = settings.get("default_ip_quota_gb", 0.0)
            auto_ban_conns = int(settings.get("auto_ban_conn_limit", 0))

            now_int = int(t0)
            need_tc_reload = False

            nft_counts = await asyncio.to_thread(poll_nft_counters)

            async with STATE_LOCK:
                if sample_seq != STATE["traffic_mutation_seq"]:
                    cdn_snapshot = {ip: dict(info) for ip, info in STATE["cdn_real_clients"].items()}
                    clients_443, reality_conns, ws_cdn_conns, cdn_socket_now = await asyncio.to_thread(
                        collect_sockets, cdn_snapshot, cdn_socket_prev)
                    nft_counts = await asyncio.to_thread(poll_nft_counters)
                cdn_dt = max(0.2, t0 - STATE["cdn_socket_sample_ts"])
                if cdn_socket_now is not None:
                    STATE["cdn_socket_prev"] = cdn_socket_now
                    STATE["cdn_socket_sample_ts"] = t0
                STATE["inbound_stats"] = {"reality_conns": reality_conns, "ws_cdn_conns": ws_cdn_conns}
                if nft_counts is not None:
                    STATE["nft_counters"] = nft_counts
                with db_session() as conn:
                    cur = conn.cursor()

                    # 严格清理数据库与内存中可能残留的 Cloudflare Anycast/反代中继节点 IP
                    for cr in cur.execute("SELECT ip FROM clients").fetchall():
                        cip = cr["ip"]
                        if is_cloudflare_ip(cip):
                            if not await asyncio.to_thread(remove_nft_counter_rule, cip):
                                continue
                            cur.execute("DELETE FROM clients WHERE ip = ?", (cip,))
                            STATE["clients_live"].pop(cip, None)
                            STATE["prev_totals"].pop(cip, None)
                    conn.commit()

                    expired_bans = cur.execute(
                        "SELECT ip FROM blacklist WHERE expires_at > 0 AND expires_at <= ?", (now_int,)
                    ).fetchall()
                    for eb in expired_bans:
                        bip = eb["ip"]
                        if await asyncio.to_thread(remove_nft_ban_rule, bip):
                            cur.execute("DELETE FROM blacklist WHERE ip = ?", (bip,))

                    for ip in clients_443.keys():
                        sock = clients_443[ip]
                        row = cur.execute("SELECT ip FROM clients WHERE ip = ?", (ip,)).fetchone()
                        if row:
                            queue_geo_ip(ip)
                            if sock.get("direct_conns") and ip not in STATE["nft_tracked_ips"]:
                                await asyncio.to_thread(add_nft_counter_rule, ip)
                        else:
                            init_up = sock.get("ss_up_bytes", 0)
                            init_down = sock.get("ss_down_bytes", 0)
                            cdn_active = sock.get("cdn_active_bytes", 0)
                            pend = STATE["cdn_pending_traffic"].get(ip, {})
                            pend_tot = pend.get("up", 0) + pend.get("down", 0)
                            row_al = cur.execute("SELECT alias FROM client_aliases WHERE ip = ?", (ip,)).fetchone()
                            known_alias = row_al["alias"] if row_al else ""
                            # 仅当具有代理翻墙业务流量 (>50 KB，即 51200 字节) 或已有历史备注才入库持久化
                            # 彻底拦截公网端口扫描握手仅 1~2KB 的探测包，绝不污染入库
                            if not (known_alias or (init_up + init_down + cdn_active + pend_tot > MIN_PERSIST_BYTES)):
                                continue
                            queue_geo_ip(ip)
                            is_cdn_val = 1 if sock.get("is_cdn") else 0
                            if sock.get("direct_conns"):
                                await asyncio.to_thread(add_nft_counter_rule, ip)
                            if sock.get("is_cdn"):
                                init_up += pend.get("up", 0)
                                init_down += pend.get("down", 0)
                                STATE["cdn_pending_traffic"].pop(ip, None)
                            cur.execute(
                                """
                                INSERT INTO clients (
                                    ip, alias, base_up_bytes, base_down_bytes, last_nft_up, last_nft_down,
                                    down_limit_mbps, up_limit_mbps, quota_gb, first_seen, last_seen, is_cdn
                                ) VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    ip,
                                    known_alias,
                                    init_up,
                                    init_down,
                                    def_down_limit if ip not in STATE["admin_ips"] else 0,
                                    def_up_limit if ip not in STATE["admin_ips"] else 0,
                                    def_quota_gb if ip not in STATE["admin_ips"] else 0,
                                    now_int,
                                    now_int,
                                    is_cdn_val,
                                ),
                            )
                            if (def_down_limit > 0 or def_up_limit > 0) and ip not in STATE["admin_ips"]:
                                need_tc_reload = True

                    all_db_clients = cur.execute("SELECT * FROM clients").fetchall()
                    banned_rows = {r["ip"]: dict(r) for r in cur.execute("SELECT * FROM blacklist").fetchall()}
                    for bip, ban in banned_rows.items():
                        if (ban["expires_at"] and ban["expires_at"] <= now_int) or bip in STATE["nft_banned_ips"]:
                            continue
                        if t0 < STATE["nft_ban_retry_at"].get(bip, 0):
                            continue
                        if await asyncio.to_thread(add_nft_ban_rule, bip):
                            STATE["nft_ban_retry_at"].pop(bip, None)
                        else:
                            STATE["nft_ban_retry_at"][bip] = t0 + 30
                            logging.warning("nft ban rule for %s failed; retrying in 30 seconds", bip)

                    total_up_bps = 0
                    total_down_bps = 0
                    live_map = {}

                    for r in all_db_clients:
                        ip = r["ip"]
                        if not valid_ip(ip) or is_cloudflare_ip(ip):
                            continue
                        queue_geo_ip(ip)
                        base_up = int(r["base_up_bytes"])
                        base_down = int(r["base_down_bytes"])
                        last_nft_up = int(r["last_nft_up"])
                        last_nft_down = int(r["last_nft_down"])

                        if nft_counts is None:
                            # Keep the persisted counters until a real nft snapshot returns.
                            nft_up, nft_down = last_nft_up, last_nft_down
                        else:
                            nft_c = nft_counts.get(ip, {"up_bytes": 0, "down_bytes": 0})
                            nft_up = nft_c["up_bytes"]
                            nft_down = nft_c["down_bytes"]

                        if nft_up < last_nft_up:
                            base_up += last_nft_up
                            last_nft_up = 0
                        if nft_down < last_nft_down:
                            base_down += last_nft_down
                            last_nft_down = 0

                        # CDN 实时速率来自 31297 套接字的逐连接增量；累计流量由日志记录。
                        csock = clients_443.get(ip)
                        is_cdn_client = bool(csock and csock.get("is_cdn"))
                        cdn_up_bps = int(csock.get("cdn_up_delta", 0) / cdn_dt) if is_cdn_client else 0
                        cdn_down_bps = int(csock.get("cdn_down_delta", 0) / cdn_dt) if is_cdn_client else 0

                        tot_up = base_up + nft_up
                        tot_down = base_down + nft_down
                        tot_traffic = tot_up + tot_down

                        up_bps = cdn_up_bps
                        down_bps = cdn_down_bps
                        if ip in STATE["prev_totals"]:
                            pts, pup, pdown = STATE["prev_totals"][ip]
                            dt = max(0.2, t0 - pts)
                            if tot_up >= pup and tot_down >= pdown:
                                up_bps += int((tot_up - pup) / dt)
                                down_bps += int((tot_down - pdown) / dt)
                        STATE["prev_totals"][ip] = (t0, tot_up, tot_down)

                        sock = clients_443.get(ip)
                        is_online = sock is not None and sock["conns"] > 0 and (ip not in banned_rows)
                        conns = sock["conns"] if is_online else 0
                        avg_rtt = round(sum(sock["rtts"]) / len(sock["rtts"]), 1) if (sock and sock["rtts"]) else 0.0
                        min_rtt = round(min(sock["min_rtts"]), 1) if (sock and sock["min_rtts"]) else 0.0

                        peak_up = max(int(r["peak_up_bps"]), up_bps)
                        peak_down = max(int(r["peak_down_bps"]), down_bps)
                        last_seen = now_int if is_online else int(r["last_seen"])

                        cur.execute(
                            """
                            UPDATE clients
                            SET base_up_bytes = ?, base_down_bytes = ?,
                                last_nft_up = ?, last_nft_down = ?,
                                peak_up_bps = ?, peak_down_bps = ?,
                                last_seen = ?, is_cdn = ?
                            WHERE ip = ?
                            """,
                            (base_up, base_down, nft_up, nft_down, peak_up, peak_down,
                             last_seen, int(is_cdn_client or r["is_cdn"]), ip),
                        )

                        if is_online:
                            total_up_bps += up_bps
                            total_down_bps += down_bps

                        is_whitelisted = bool(r["is_whitelisted"]) or (ip in STATE["admin_ips"])
                        quota_gb = float(r["quota_gb"] or 0.0)
                        if not is_whitelisted and ip not in banned_rows:
                            if quota_gb > 0 and (tot_up + tot_down) >= int(quota_gb * (1024 ** 3)):
                                if not await asyncio.to_thread(add_nft_ban_rule, ip):
                                    STATE["nft_ban_retry_at"][ip] = t0 + 30
                                    logging.warning("nft quota ban rule for %s failed; retrying in 30 seconds", ip)
                                await asyncio.to_thread(disconnect_cdn_if_safe, ip)
                                cur.execute(
                                    "INSERT OR REPLACE INTO blacklist (ip, reason, created_at, expires_at) VALUES (?, ?, ?, 0)",
                                    (ip, f"流量达到配额上限 ({quota_gb} GB) 自动封禁", now_int),
                                )
                                banned_rows[ip] = {"ip": ip, "reason": f"流量达到配额上限 ({quota_gb} GB) 自动封禁"}
                            elif auto_ban_conns > 0 and conns > auto_ban_conns:
                                if not await asyncio.to_thread(add_nft_ban_rule, ip):
                                    STATE["nft_ban_retry_at"][ip] = t0 + 30
                                    logging.warning("nft connection ban rule for %s failed; retrying in 30 seconds", ip)
                                await asyncio.to_thread(disconnect_cdn_if_safe, ip)
                                cur.execute(
                                    "INSERT OR REPLACE INTO blacklist (ip, reason, created_at, expires_at) VALUES (?, ?, ?, ?)",
                                    (ip, f"并发连接数超限 ({conns} > {auto_ban_conns}) 自动封禁1小时", now_int, now_int + 3600),
                                )
                                banned_rows[ip] = {"ip": ip, "reason": f"并发连接数超限 ({conns})"}

                        row_is_cdn = bool(r["is_cdn"]) if "is_cdn" in r.keys() else False
                        live_map[ip] = {
                            "ip": ip,
                            "alias": r["alias"] or "",
                            "is_online": is_online,
                            "is_cdn": row_is_cdn or (ip in STATE["cdn_real_clients"] and not is_cloudflare_ip(ip)),
                            "is_whitelisted": bool(r["is_whitelisted"]),
                            "is_blacklisted": ip in banned_rows,
                            "active_conns": conns,
                            "avg_rtt_ms": avg_rtt,
                            "min_rtt_ms": min_rtt,
                            "up_speed": up_bps if is_online else 0,
                            "down_speed": down_bps if is_online else 0,
                            "peak_up_speed": peak_up,
                            "peak_down_speed": peak_down,
                            "total_up": tot_up,
                            "total_down": tot_down,
                            "total_traffic": tot_up + tot_down,
                            "down_limit_mbps": float(r["down_limit_mbps"] or 0),
                            "up_limit_mbps": float(r["up_limit_mbps"] or 0),
                            "quota_gb": quota_gb,
                            "first_seen": int(r["first_seen"]),
                            "last_seen": last_seen,
                        }

                    conn.commit()

                if need_tc_reload:
                    tc_reload_pending = True
                if STATE["tc_reload_pending"]:
                    tc_reload_pending = True
                if tc_reload_pending and t0 >= tc_retry_at:
                    try:
                        await asyncio.to_thread(apply_tc_limits)
                    except Exception:
                        tc_retry_at = time.time() + 30
                        logging.exception("Failed to apply tc limits; retrying in 30 seconds")
                    else:
                        tc_reload_pending = False
                        tc_retry_at = 0.0
                        STATE["tc_reload_pending"] = False
                STATE["clients_live"] = live_map
                await sync_cdn_rate_map_with_retry()

            online_count = sum(1 for c in live_map.values() if c["is_online"])
            active_conns_sum = sum(c["active_conns"] for c in live_map.values() if c["is_online"])

            if tick % 60 == 0:
                # 定期清理超时 24 小时的 CDN 内存缓存及超容量会话
                now_t = time.time()
                stale_cdn = [cip for cip, cdata in list(STATE["cdn_real_clients"].items()) if now_t - cdata.get("last_seen", 0) > 86400]
                for cip in stale_cdn:
                    STATE["cdn_real_clients"].pop(cip, None)
                stale_pend = [cip for cip, pdata in list(STATE["cdn_pending_traffic"].items()) if now_t - pdata.get("last_seen", 0) > 86400]
                for cip in stale_pend:
                    STATE["cdn_pending_traffic"].pop(cip, None)
                if len(STATE["session_device_map"]) > 200:
                    STATE["session_device_map"].clear()
                # 仅清理超过 15 分钟的过期失败记录，绝不全量清空导致爆破锁定重置
                for lip, t_list in list(LOGIN_FAILURES.items()):
                    v_valid = [t for t in t_list if now_int - t < 900]
                    if v_valid:
                        LOGIN_FAILURES[lip] = v_valid
                    else:
                        LOGIN_FAILURES.pop(lip, None)

            STATE["history"].append(
                {
                    "ts": now_int,
                    "time_str": time.strftime("%H:%M:%S", time.localtime(now_int)),
                    "up_bps": total_up_bps,
                    "down_bps": total_down_bps,
                    "online_ips": online_count,
                    "active_conns": active_conns_sum,
                }
            )
            if len(STATE["history"]) > 60:
                STATE["history"] = STATE["history"][-60:]

        except Exception as e:
            print("Telemetry error:", e)

        tick += 1
        elapsed = time.time() - t0
        await asyncio.sleep(max(0.2, 1.0 - elapsed))


def _consume_cdn_log_file(path: str, start_offset: int) -> Tuple[int, Dict[str, dict]]:
    """
    二进制模式流式读取 cdn-ws.log，确保 f.tell() 物理字节偏移与 os.stat(path).st_size 严格一致，
    杜绝多字节字符状态压缩导致的虚假截断与流量重复翻倍计费。
    """
    traffic: Dict[str, dict] = {}
    if not os.path.exists(path):
        return start_offset, traffic
    cur_offset = start_offset
    try:
        file_size = os.path.getsize(path)
        if start_offset > file_size:
            start_offset = 0
            cur_offset = 0
        with open(path, "rb") as f:
            f.seek(start_offset)
            while True:
                line_bytes = f.readline()
                if not line_bytes:
                    break
                if not line_bytes.endswith(b"\n"):
                    f.seek(cur_offset)
                    break
                cur_offset = f.tell()
                try:
                    line_str = line_bytes.decode("utf-8", errors="ignore").strip()
                except Exception:
                    continue
                if not line_str:
                    continue
                parts = line_str.split("|")
                if len(parts) >= 4:
                    try:
                        msec_f = float(parts[0])
                        ts_int = int(msec_f)
                        raw_ip = parts[1].strip()
                        ip = canonical_ip(raw_ip)
                        bytes_down = int(parts[2])
                        bytes_up = int(parts[3])
                        req_time = float(parts[4]) if len(parts) >= 5 else 0.0

                        if ip and not is_cloudflare_ip(ip):
                            delete_ts = STATE["client_delete_map"].get(ip, 0.0)
                            req_start = (msec_f - req_time) if req_time > 0 else msec_f
                            if delete_ts and (msec_f <= delete_ts or req_start <= delete_ts):
                                continue
                            prev = STATE["cdn_real_clients"].get(ip, {})
                            prev_seen = prev.get("last_seen", 0)
                            open_h = max(0, prev.get("open_hint", 0) - 1)
                            STATE["cdn_real_clients"][ip] = {
                                "ip": ip,
                                "last_seen": max(prev_seen, ts_int),
                                "open_hint": open_h,
                                "last_open_ts": prev.get("last_open_ts", ts_int),
                            }

                            reset_ts = STATE["traffic_reset_map"].get(ip, 0.0)
                            if msec_f <= reset_ts:
                                continue
                            if req_time > 0 and (msec_f - req_time < reset_ts < msec_f):
                                factor = max(0.0, min(1.0, (msec_f - reset_ts) / req_time))
                                bytes_down = int(bytes_down * factor)
                                bytes_up = int(bytes_up * factor)

                            if bytes_down > 0 or bytes_up > 0:
                                entry = traffic.setdefault(ip, {"down": 0, "up": 0, "ts": ts_int})
                                entry["down"] += bytes_down
                                entry["up"] += bytes_up
                                entry["ts"] = max(entry["ts"], ts_int)
                    except Exception:
                        continue
    except Exception as e:
        print(f"_consume_cdn_log_file error on {path}: {e}")
    return cur_offset, traffic


def warmup_cdn_real_clients():
    """
    服务启动时依次读取 CDN WebSocket 轮转日志与当前日志（如 cdn-ws.log.1 与 cdn-ws.log），
    预热内存中的 STATE["cdn_real_clients"]，防止重启后长连接无法归属真实来源 IP。
    丢弃首行残缺半行。
    """
    candidates = [f"{CDN_LOG_PATH}.1", CDN_LOG_PATH]
    for log_path in candidates:
        if not os.path.exists(log_path):
            continue
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                seek_pos = max(0, size - 65536)
                f.seek(seek_pos)
                if seek_pos > 0:
                    f.readline()  # 丢弃首行残缺半行
                lines = f.readlines()
                for line in lines:
                    parts = line.strip().split("|")
                    if len(parts) >= 4:
                        try:
                            ts_int = int(float(parts[0]))
                            ip = canonical_ip(parts[1])
                            if ip and not is_cloudflare_ip(ip):
                                prev = STATE["cdn_real_clients"].get(ip, {})
                                prev_seen = prev.get("last_seen", 0)
                                STATE["cdn_real_clients"][ip] = {
                                    "ip": ip,
                                    "last_seen": max(prev_seen, ts_int),
                                    "open_hint": prev.get("open_hint", 0),
                                    "last_open_ts": prev.get("last_open_ts", ts_int),
                                }
                                queue_geo_ip(ip)
                        except Exception:
                            continue
        except Exception as e:
            print(f"warmup_cdn_real_clients error on {log_path}:", e)


async def tail_cdn_ws_log():
    """
    增量读取 CDN WebSocket 日志（默认 /var/log/nginx/cdn-ws.log），精确记账每个 CDN 用户的上行与下行流量。
    平滑处理 logrotate 无损衔接、64 位 inode 与字节偏移，严格遵循 50KB 持久化入库门槛。
    """
    log_path = CDN_LOG_PATH
    rot_path = f"{CDN_LOG_PATH}.1"
    last_inode = None
    last_offset = 0

    try:
        raw_off = get_raw_setting("cdn_log_offset", "0")
        raw_ino = get_raw_setting("cdn_log_inode", "")
        last_offset = int(raw_off) if raw_off else 0
        last_inode = int(raw_ino) if raw_ino else None
    except Exception:
        last_offset = 0
        last_inode = None

    while True:
        try:
            await asyncio.sleep(1.0)
            if not os.path.exists(log_path):
                continue

            async with STATE_LOCK:
                st = os.stat(log_path)
                cur_inode = st.st_ino
                cur_size = st.st_size

                traffic_by_ip: Dict[str, dict] = {}
                next_inode = cur_inode
                read_offset = last_offset

                # 处理日志轮转 (logrotate)：若 inode 改变，先读完 cdn-ws.log.1 的剩余未入账部分
                if last_inode is not None and last_inode != cur_inode:
                    if os.path.exists(rot_path):
                        try:
                            rot_st = os.stat(rot_path)
                            if rot_st.st_ino == last_inode and rot_st.st_size > last_offset:
                                _, rot_traffic = _consume_cdn_log_file(rot_path, last_offset)
                                for ip, agg in rot_traffic.items():
                                    e = traffic_by_ip.setdefault(ip, {"down": 0, "up": 0, "ts": agg["ts"]})
                                    e["down"] += agg["down"]
                                    e["up"] += agg["up"]
                                    e["ts"] = max(e["ts"], agg["ts"])
                        except Exception as e:
                            print("logrotate handle error:", e)
                    read_offset = 0

                if cur_size < read_offset:
                    # 日志被清空或轮转截断 (copytruncate / truncate)，重置 offset 避免死锁
                    read_offset = 0

                next_offset = read_offset
                if cur_size > read_offset:
                    next_offset, new_traffic = _consume_cdn_log_file(log_path, read_offset)
                    for ip, agg in new_traffic.items():
                        e = traffic_by_ip.setdefault(ip, {"down": 0, "up": 0, "ts": agg["ts"]})
                        e["down"] += agg["down"]
                        e["up"] += agg["up"]
                        e["ts"] = max(e["ts"], agg["ts"])

                new_cdn_limits = False
                new_tc_limits = False
                committed_existing = []
                if traffic_by_ip or next_offset != last_offset or next_inode != last_inode:
                    with db_session() as conn:
                        cur = conn.cursor()
                        pending_traffic = {
                            ip: dict(value) for ip, value in STATE["cdn_pending_traffic"].items()
                        }
                        for ip, agg in traffic_by_ip.items():
                            if not valid_ip(ip) or is_cloudflare_ip(ip):
                                continue
                            row = cur.execute("SELECT ip, alias, base_up_bytes, base_down_bytes FROM clients WHERE ip = ?", (ip,)).fetchone()
                            if row:
                                cur.execute(
                                    """
                                    UPDATE clients
                                    SET base_down_bytes = base_down_bytes + ?,
                                        base_up_bytes = base_up_bytes + ?,
                                        last_seen = MAX(last_seen, ?),
                                        is_cdn = 1
                                    WHERE ip = ?
                                    """,
                                    (agg["down"], agg["up"], agg["ts"], ip),
                                )
                                committed_existing.append((ip, agg["up"], agg["down"]))
                            else:
                                pend = pending_traffic.setdefault(
                                    ip, {"up": 0, "down": 0, "first_seen": agg["ts"], "last_seen": agg["ts"]}
                                )
                                pend["up"] += agg["up"]
                                pend["down"] += agg["down"]
                                pend["last_seen"] = max(pend["last_seen"], agg["ts"])
                                tot_p = pend["up"] + pend["down"]
                                row_al = cur.execute("SELECT alias FROM client_aliases WHERE ip = ?", (ip,)).fetchone()
                                known_alias = row_al["alias"] if row_al else ""
                                if known_alias or tot_p >= MIN_PERSIST_BYTES:
                                    def_down, def_up, def_quota = default_client_limits(ip)
                                    cur.execute(
                                        """
                                        INSERT INTO clients (ip, alias, base_up_bytes, base_down_bytes,
                                            down_limit_mbps, up_limit_mbps, quota_gb, first_seen, last_seen, is_cdn)
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                                        """,
                                        (ip, known_alias, pend["up"], pend["down"], def_down, def_up,
                                         def_quota, pend["first_seen"], pend["last_seen"]),
                                    )
                                    new_cdn_limits |= def_down > 0
                                    new_tc_limits |= (def_down > 0 or def_up > 0)
                                    pending_traffic.pop(ip, None)
                        cur.execute(
                            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                            ("cdn_log_offset", str(next_offset)),
                        )
                        cur.execute(
                            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                            ("cdn_log_inode", str(next_inode)),
                        )
                        conn.commit()
                    for cip, add_up, add_down in committed_existing:
                        if cip in STATE["prev_totals"]:
                            pts, pup, pdown = STATE["prev_totals"][cip]
                            STATE["prev_totals"][cip] = (pts, pup + add_up, pdown + add_down)
                    if new_tc_limits:
                        STATE["tc_reload_pending"] = True
                    STATE["cdn_pending_traffic"] = pending_traffic
                    last_offset = next_offset
                    last_inode = next_inode
                if new_cdn_limits:
                    await sync_cdn_rate_map_with_retry(changed=True)

        except asyncio.CancelledError:
            break
        except Exception as e:
            print("tail_cdn_ws_log error:", e)
            await asyncio.sleep(2.0)


@app.on_event("startup")
async def on_startup():
    try:
        sync_cdn_rate_map()
    except Exception as e:
        print("Initial sync_cdn_rate_map error:", e)
    try:
        warmup_cdn_real_clients()
    except Exception as e:
        print("Initial warmup_cdn_real_clients error:", e)
    asyncio.create_task(telemetry_loop())
    asyncio.create_task(geo_worker())
    asyncio.create_task(tail_cdn_ws_log())


# ==================== API MODELS & ENDPOINTS ====================

class LoginReq(BaseModel):
    username: str
    password: str


class AliasReq(BaseModel):
    ip: str = Field(..., max_length=128)
    alias: str = Field(..., max_length=64)


class LimitReq(BaseModel):
    ip: str = Field(..., max_length=128)
    down_limit_mbps: float = Field(0.0, ge=0.0, le=100000.0)
    up_limit_mbps: float = Field(0.0, ge=0.0, le=100000.0)
    quota_gb: float = Field(0.0, ge=0.0, le=1000000.0)


class IpReq(BaseModel):
    ip: str = Field(..., max_length=128)


class BlacklistAddReq(BaseModel):
    ip: str = Field(..., max_length=128)
    reason: str = Field("管理员手动封禁", max_length=128)
    duration_seconds: int = Field(0, ge=0, le=315360000)


class SettingsReq(BaseModel):
    global_down_limit_mbps: float = Field(0.0, ge=0.0, le=100000.0)
    default_ip_down_limit_mbps: float = Field(0.0, ge=0.0, le=100000.0)
    default_ip_up_limit_mbps: float = Field(0.0, ge=0.0, le=100000.0)
    default_ip_quota_gb: float = Field(0.0, ge=0.0, le=1000000.0)
    auto_ban_conn_limit: int = Field(0, ge=0, le=65535)


def is_public_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        s = ip_str.strip()
        if s.startswith("::ffff:"):
            s = s[7:]
        ip = ipaddress.ip_address(s)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
        if str(ip) in SERVER_SELF_IPS:
            return False
        return True
    except Exception:
        return False


def public_non_cdn_ip(raw: str) -> str:
    ip = canonical_ip(raw)
    return ip if ip and is_public_ip(ip) and not is_cloudflare_ip(ip) else ""


def extract_viewer_ip(request: Request) -> str:
    """
    动态提取当前打开控制台的真实客户端 IP：
    1. 优先提取 Cloudflare 的 CF-Connecting-IP（支持公网 IPv4 与 IPv6）
    2. 其次提取反向代理链 X-Forwarded-For 中第一个公网 IP
    3. 再次提取 X-Real-IP（若为公网 IP）
    4. 最后提取直连套接字 host（若为公网 IP）
    绝不硬编码任何固定 IP。
    """
    cf_ip = public_non_cdn_ip(request.headers.get("cf-connecting-ip") or "")
    if cf_ip:
        return cf_ip

    xff = request.headers.get("x-forwarded-for") or ""
    if xff:
        for part in xff.split(","):
            candidate = public_non_cdn_ip(part)
            if candidate:
                return candidate

    x_real = public_non_cdn_ip(request.headers.get("x-real-ip") or "")
    if x_real:
        return x_real

    if request.client and request.client.host:
        h = public_non_cdn_ip(request.client.host)
        if h:
            return h
    return ""


@app.api_route("/internal/cdn-auth", methods=["GET", "POST"])
async def internal_cdn_auth(request: Request):
    """
    由 Nginx 在 CDN 节点 (VLESS-WS) 握手时通过 auth_request 调用：
    仅允许 127.0.0.1 / ::1 内部调用。
    """
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        return Response(content="Forbidden: internal only", status_code=403)

    raw_ip = request.headers.get("x-real-ip") or request.headers.get("cf-connecting-ip") or ""
    if not raw_ip:
        raw_ip = request.headers.get("x-forwarded-for") or ""
    first_part = raw_ip.split(",")[0].strip()
    ip = canonical_ip(first_part)
    if not ip or is_cloudflare_ip(ip):
        return Response(content="Forbidden: missing client IP", status_code=403)

    async with STATE_LOCK:
        with db_session() as conn:
            banned = conn.execute("SELECT ip FROM blacklist WHERE ip = ?", (ip,)).fetchone()
            if banned:
                return Response(content="Forbidden", status_code=403)

            now = int(time.time())
            # Bound in-memory caches to prevent memory exhaustion
            if len(STATE["cdn_real_clients"]) > 2048:
                oldest_keys = sorted(STATE["cdn_real_clients"].keys(), key=lambda k: STATE["cdn_real_clients"][k].get("last_seen", 0))[:256]
                for ok in oldest_keys:
                    STATE["cdn_real_clients"].pop(ok, None)

            prev = STATE["cdn_real_clients"].get(ip, {})
            STATE["cdn_real_clients"][ip] = {
                "ip": ip,
                "last_seen": now,
                "open_hint": min(32, prev.get("open_hint", 0) + 1),
                "last_open_ts": now,
            }
            queue_geo_ip(ip)

            row = conn.execute("SELECT ip, alias FROM clients WHERE ip = ?", (ip,)).fetchone()
            if row:
                conn.execute("UPDATE clients SET last_seen = ?, is_cdn = 1 WHERE ip = ?", (now, ip))
                conn.commit()
            else:
                row_al = conn.execute("SELECT alias FROM client_aliases WHERE ip = ?", (ip,)).fetchone()
                if row_al and row_al["alias"]:
                    def_down, def_up, def_quota = default_client_limits(ip)
                    conn.execute(
                        """
                        INSERT INTO clients (
                            ip, alias, base_up_bytes, base_down_bytes, last_nft_up, last_nft_down,
                            down_limit_mbps, up_limit_mbps, quota_gb, is_whitelisted, first_seen, last_seen, is_cdn
                        ) VALUES (?, ?, 0, 0, 0, 0, ?, ?, ?, 0, ?, ?, 1)
                        """,
                        (ip, row_al["alias"], def_down, def_up, def_quota, now, now),
                    )
                    conn.commit()
                    if def_down > 0 or def_up > 0:
                        STATE["tc_reload_pending"] = True
                else:
                    STATE["cdn_pending_traffic"].setdefault(ip, {"up": 0, "down": 0, "first_seen": now, "last_seen": now})

    return Response(content="OK", status_code=200)


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    if INDEX_HTML_PATH.exists():
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")
        resp = HTMLResponse(content)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return resp
    return HTMLResponse("<h1>Xray-Pulse Loading...</h1>")


@app.post("/api/login")
async def api_login(req: LoginReq, request: Request, response: Response):
    check_csrf(request)
    client_ip = request.client.host if request.client else "unknown"
    if client_ip in ("127.0.0.1", "::1"):
        # Nginx must overwrite X-Real-IP. A direct visitor's CF header is not trusted.
        proxy_ip = canonical_ip(request.headers.get("x-real-ip", ""))
        cf_ip = public_non_cdn_ip(request.headers.get("cf-connecting-ip", ""))
        if proxy_ip and is_cloudflare_ip(proxy_ip):
            rate_ip = cf_ip or client_ip
        else:
            rate_ip = public_non_cdn_ip(proxy_ip) or client_ip
    elif is_cloudflare_ip(client_ip):
        rate_ip = public_non_cdn_ip(request.headers.get("cf-connecting-ip", "")) or client_ip
    else:
        rate_ip = canonical_ip(client_ip) or client_ip

    now = time.time()
    fails = [t for t in LOGIN_FAILURES.get(rate_ip, []) if now - t < 900]
    if len(fails) >= 8:
        raise HTTPException(status_code=429, detail="登录失败次数过多，请 15 分钟后再试")

    expected_user = get_raw_setting("auth_username") or DEFAULT_ADMIN_USER
    expected_hash = get_raw_setting("auth_password_hash")

    if req.username.strip() == expected_user and verify_password(req.password, expected_hash):
        LOGIN_FAILURES.pop(rate_ip, None)
        token = create_session_token(expected_user)
        is_https = (
            request.headers.get("x-forwarded-proto") == "https"
            or request.url.scheme == "https"
            or "https" in (request.headers.get("cf-visitor") or "")
        )
        response.set_cookie(
            key="xp_session",
            value=token,
            httponly=True,
            secure=is_https,
            max_age=86400 * 14,
            samesite="lax",
            path="/",
        )
        return {"ok": True, "username": expected_user}

    fails.append(now)
    LOGIN_FAILURES[rate_ip] = fails
    raise HTTPException(status_code=401, detail="用户名或密码错误")


@app.post("/api/logout")
async def api_logout(request: Request, response: Response):
    require_auth(request)
    token = request.cookies.get("xp_session", "")
    parts = token.split(":")
    expires_at = int(parts[1])
    with db_session() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO revoked_sessions (token_hash, expires_at) VALUES (?, ?)",
            (hashlib.sha256(token.encode("utf-8")).hexdigest(), expires_at),
        )
        conn.execute("DELETE FROM revoked_sessions WHERE expires_at < ?", (int(time.time()),))
        conn.commit()
    token_sig = token.split(":")[-1] if token and ":" in token else ""
    if token_sig:
        STATE["session_device_map"].pop(token_sig, None)
    response.delete_cookie(key="xp_session", path="/")
    return {"ok": True}


def resolve_viewer_ip(request: Request, user: str = "") -> str:
    """
    智能识别当前打开控制台的管理端设备：
    1. 前端若探测到真实物理 IP（遍历多候选且排除 Cloudflare IP 与 mDNS）：直接采纳
    2. 直连访问（CF-Connecting-IP 非服务端自身 IP 且非 CF 节点）：直接采纳
    3. 代理访问：结合会话 Token 与终端画像精准匹配管理端
    """
    token = request.cookies.get("xp_session", "")
    token_sig = token.split(":")[-1] if token and ":" in token else ""

    # 1. 前端上报由 WebRTC STUN 探测到的真实公网 IP（支持 IPv4+IPv6 多候选逗号分隔）
    raw_real_hdr = (request.headers.get("x-client-real-ip") or request.headers.get("x-client-device-ip") or "").strip()
    if raw_real_hdr:
        real_candidates = [ip for p in raw_real_hdr.split(",") if (ip := public_non_cdn_ip(p))]
        online_hits = [
            cip for cip in real_candidates
            if STATE["clients_live"].get(cip, {}).get("is_online")
        ]
        if online_hits:
            best_hit = sorted(
                online_hits,
                key=lambda x: (
                    STATE["clients_live"][x].get("active_conns", 0),
                    STATE["clients_live"][x].get("total_traffic", 0),
                ),
                reverse=True,
            )[0]
            if token_sig:
                STATE["session_device_map"][token_sig] = best_hit
            return best_hit

    # 2. 直连访问
    direct_cf_ip = public_non_cdn_ip(request.headers.get("cf-connecting-ip") or "")
    if direct_cf_ip:
        if token_sig:
            STATE["session_device_map"][token_sig] = direct_cf_ip
        return direct_cf_ip

    direct_v = extract_viewer_ip(request)
    if direct_v and direct_v not in SERVER_SELF_IPS and not is_cloudflare_ip(direct_v):
        if token_sig:
            STATE["session_device_map"][token_sig] = direct_v
        return direct_v

    # 3. 代理访问：若当前浏览器会话已绑定且该 IP 在线，保持会话连续性
    if token_sig and token_sig in STATE["session_device_map"]:
        bound_ip = STATE["session_device_map"][token_sig]
        cinfo = STATE["clients_live"].get(bound_ip)
        if cinfo and cinfo.get("is_online"):
            return bound_ip

    # 4. 智能按终端画像匹配
    ua = request.headers.get("user-agent", "")
    platform = (request.headers.get("sec-ch-ua-platform") or "").lower()
    is_mobile = (
        "android" in platform
        or "mobile" in ua.lower()
        or "iphone" in ua.lower()
        or request.headers.get("sec-ch-ua-mobile") == "?1"
    )

    online_clients = [
        (cip, cinfo) for cip, cinfo in list(STATE["clients_live"].items())
        if cinfo.get("is_online") and not cinfo.get("is_blacklisted")
    ]
    # 严禁从任意普通在线用户中盲猜管理员！仅信任显式白名单或明确带有管理员/本机备注的节点
    whitelisted = [c for c in online_clients if c[1].get("is_whitelisted")]
    admin_named = [
        c for c in online_clients
        if any(k in (c[1].get("alias") or "").lower() for k in ("admin", "管理员", "本人", "本机", "me"))
    ]
    admin_candidates = whitelisted or admin_named
    if not admin_candidates:
        return ""

    matched_ip = ""
    if is_mobile:
        for cip, cinfo in admin_candidates:
            al = (cinfo.get("alias") or "").lower()
            if "流量" in al or "手机" in al or "mobile" in al:
                matched_ip = cip
                break
        if not matched_ip and admin_candidates:
            matched_ip = sorted(
                admin_candidates,
                key=lambda x: (
                    1 if x[1].get("is_whitelisted") else 0,
                    x[1].get("active_conns", 0),
                    x[1].get("total_traffic", 0),
                ),
                reverse=True,
            )[0][0]
    else:
        if admin_candidates:
            matched_ip = sorted(
                admin_candidates,
                key=lambda x: (
                    1 if x[1].get("is_whitelisted") else 0,
                    1 if any(k in (x[1].get("alias") or "").lower() for k in ("desktop", "pc", "workstation", "laptop", "电脑", "本机")) else 0,
                    x[1].get("active_conns", 0),
                    x[1].get("total_traffic", 0),
                ),
                reverse=True,
            )[0][0]

    if matched_ip and token_sig:
        STATE["session_device_map"][token_sig] = matched_ip

    return matched_ip


@app.get("/api/overview")
async def api_overview(request: Request):
    user = require_auth(request)
    now_ts = int(time.time())

    async with STATE_LOCK:
        viewer_ip = resolve_viewer_ip(request, user)
        previous_admin_ips = STATE["admin_ips"].copy()
        if viewer_ip and valid_ip(viewer_ip):
            STATE["admin_sessions"][viewer_ip] = now_ts
        expired_admins = [aip for aip, ts in list(STATE["admin_sessions"].items()) if now_ts - ts > 3600]
        for aip in expired_admins:
            STATE["admin_sessions"].pop(aip, None)
        STATE["admin_ips"] = set(STATE["admin_sessions"].keys())
        await sync_cdn_rate_map_with_retry(STATE["admin_ips"] != previous_admin_ips)

    with db_session() as conn:
        geo_rows = {
            r["ip"]: {
                "country": r["country"],
                "region": r["region"],
                "city": r["city"],
                "isp": r["isp"],
                "org": r["org"],
                "asn": r["asn"],
            }
            for r in conn.execute("SELECT * FROM geo_cache").fetchall()
        }
        ban_rows = conn.execute("SELECT * FROM blacklist ORDER BY created_at DESC").fetchall()

    clients_list = []
    for ip, c in list(STATE["clients_live"].items()):
        item = dict(c)
        g = geo_rows.get(ip, {})
        loc_parts = [x for x in [g.get("country", ""), g.get("region", ""), g.get("city", "")] if x]
        dedup_loc = []
        for p in loc_parts:
            if not dedup_loc or dedup_loc[-1] != p:
                dedup_loc.append(p)
        if not dedup_loc:
            item["location"] = "解析中..."
        else:
            item["location"] = " ".join(dedup_loc)
        item["isp"] = g.get("isp") or g.get("org") or ""
        item["asn"] = g.get("asn", "")
        # 实时智能自动识别：严格保证每个查看页面只将当前操作端自己标记为 is_admin
        item["is_admin"] = bool(viewer_ip and ip == viewer_ip)
        clients_list.append(item)

    clients_list.sort(
        key=lambda x: (
            0 if x["is_admin"] else 1,
            0 if x["is_online"] else 1,
            x["first_seen"],
            x["ip"],
        )
    )

    blacklist_data = []
    for b in ban_rows:
        bip = b["ip"]
        nft_c = STATE["nft_counters"].get(bip, {"drop_pkts": 0, "drop_bytes": 0})
        g = geo_rows.get(bip, {})
        loc = " ".join([x for x in [g.get("country", ""), g.get("region", ""), g.get("city", "")] if x])
        blacklist_data.append(
            {
                "ip": bip,
                "reason": b["reason"],
                "created_at": b["created_at"],
                "expires_at": b["expires_at"],
                "dropped_pkts": int(b["base_dropped_pkts"]) + nft_c.get("drop_pkts", 0),
                "dropped_bytes": int(b["base_dropped_bytes"]) + nft_c.get("drop_bytes", 0),
                "location": loc or "未知区域",
                "isp": g.get("isp", ""),
            }
        )

    total_up_all = sum(c["total_up"] for c in clients_list)
    total_down_all = sum(c["total_down"] for c in clients_list)
    cur_up_bps = STATE["history"][-1]["up_bps"] if STATE["history"] else 0
    cur_down_bps = STATE["history"][-1]["down_bps"] if STATE["history"] else 0

    return {
        "username": user,
        "viewer_ip": viewer_ip,
        "admin_ips": list(STATE["admin_ips"]),
        "xray": STATE["xray_info"],
        "xray_api_stats": STATE.get("xray_api_stats", {}),
        "system": STATE["sys_info"],
        "inbounds": STATE.get("inbound_stats", {"reality_conns": 0, "ws_cdn_conns": 0}),
        "summary": {
            "online_ips": sum(1 for c in clients_list if c["is_online"]),
            "total_known_ips": len(clients_list),
            "active_conns": sum(c["active_conns"] for c in clients_list if c["is_online"]),
            "cur_up_bps": cur_up_bps,
            "cur_down_bps": cur_down_bps,
            "total_up_bytes": total_up_all,
            "total_down_bytes": total_down_all,
            "total_traffic_bytes": total_up_all + total_down_all,
            "blacklisted_count": len(blacklist_data),
        },
        "settings": get_all_settings(),
        "clients": clients_list,
        "blacklist": blacklist_data,
        "outbounds": [],
        "history": STATE["history"],
    }


@app.post("/api/client/alias")
async def api_set_alias(req: AliasReq, request: Request):
    require_auth(request)
    ip = canonical_ip(req.ip)
    if not ip:
        raise HTTPException(status_code=400, detail="无效的 IP 地址")
    if is_cloudflare_ip(ip):
        raise HTTPException(status_code=400, detail="安全保护：该 IP 属于 Cloudflare CDN 中继网段，严禁作为客户端操作或封禁！")

    alias_clean = req.alias.strip()
    now_int = int(time.time())
    async with STATE_LOCK:
        new_limits = None
        with db_session() as conn:
            row = conn.execute("SELECT ip FROM clients WHERE ip = ?", (ip,)).fetchone()
            previous_alias = conn.execute(
                "SELECT alias, updated_at FROM client_aliases WHERE ip = ?", (ip,)
            ).fetchone()
            if row:
                conn.execute("UPDATE clients SET alias = ? WHERE ip = ?", (alias_clean, ip))
            else:
                new_limits = default_client_limits(ip)
                conn.execute(
                    """INSERT INTO clients (ip, alias, down_limit_mbps, up_limit_mbps, quota_gb,
                       first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (ip, alias_clean, *new_limits, now_int, now_int),
                )
            if alias_clean:
                conn.execute("INSERT OR REPLACE INTO client_aliases (ip, alias, updated_at) VALUES (?, ?, ?)", (ip, alias_clean, now_int))
            else:
                conn.execute("DELETE FROM client_aliases WHERE ip = ?", (ip,))
            conn.commit()
        if new_limits and any(new_limits[:2]):
            try:
                await asyncio.to_thread(apply_tc_limits)
                await asyncio.to_thread(sync_cdn_rate_map)
            except Exception:
                with db_session() as conn:
                    conn.execute("DELETE FROM clients WHERE ip = ?", (ip,))
                    if previous_alias:
                        conn.execute(
                            "INSERT OR REPLACE INTO client_aliases (ip, alias, updated_at) VALUES (?, ?, ?)",
                            (ip, previous_alias["alias"], previous_alias["updated_at"]),
                        )
                    else:
                        conn.execute("DELETE FROM client_aliases WHERE ip = ?", (ip,))
                    conn.commit()
                try:
                    await asyncio.to_thread(apply_tc_limits)
                    await asyncio.to_thread(sync_cdn_rate_map)
                except Exception:
                    logging.exception("Failed to restore policy after new alias client error")
                raise HTTPException(status_code=503, detail="默认限速下发失败，备注未保存")
        if ip in STATE["clients_live"]:
            STATE["clients_live"][ip]["alias"] = alias_clean
    return {"ok": True}


@app.post("/api/client/limit")
async def api_set_limit(req: LimitReq, request: Request):
    require_auth(request)
    ip = canonical_ip(req.ip)
    if not ip:
        raise HTTPException(status_code=400, detail="无效的 IP 地址")
    if is_cloudflare_ip(ip):
        raise HTTPException(status_code=400, detail="安全保护：该 IP 属于 Cloudflare CDN 中继网段，严禁作为客户端操作或封禁！")

    down_l = max(0.0, round(req.down_limit_mbps, 2))
    up_l = max(0.0, round(req.up_limit_mbps, 2))
    quota = max(0.0, round(req.quota_gb, 2))

    async with STATE_LOCK:
        now_int = int(time.time())
        with db_session() as conn:
            row = conn.execute(
                "SELECT down_limit_mbps, up_limit_mbps, quota_gb, is_cdn FROM clients WHERE ip = ?", (ip,)
            ).fetchone()
            previous = tuple(row)[:3] if row else None
            was_cdn = bool(row["is_cdn"]) if row else False
            if row:
                conn.execute(
                    "UPDATE clients SET down_limit_mbps = ?, up_limit_mbps = ?, quota_gb = ? WHERE ip = ?",
                    (down_l, up_l, quota, ip),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO clients (ip, down_limit_mbps, up_limit_mbps, quota_gb, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (ip, down_l, up_l, quota, now_int, now_int),
                )
            conn.commit()

        try:
            await asyncio.to_thread(apply_tc_limits)
            await asyncio.to_thread(sync_cdn_rate_map)
        except Exception:
            try:
                with db_session() as conn:
                    if previous is None:
                        conn.execute("DELETE FROM clients WHERE ip = ?", (ip,))
                    else:
                        conn.execute(
                            "UPDATE clients SET down_limit_mbps = ?, up_limit_mbps = ?, quota_gb = ? WHERE ip = ?",
                            (*previous, ip),
                        )
                    conn.commit()
                await asyncio.to_thread(apply_tc_limits)
                await asyncio.to_thread(sync_cdn_rate_map)
            except Exception:
                logging.exception("Failed to restore network limits after update error")
            raise HTTPException(status_code=503, detail="限速下发失败，原配置已尝试恢复")

        await asyncio.to_thread(add_nft_counter_rule, ip)
        if ip in STATE["clients_live"]:
            STATE["clients_live"][ip].update(
                down_limit_mbps=down_l, up_limit_mbps=up_l, quota_gb=quota)

        msg = None
        is_cdn = was_cdn or (ip in STATE["cdn_real_clients"])
        if is_cdn:
            cdn_dropped, cdn_msg = await asyncio.to_thread(disconnect_cdn_if_safe, ip)
            if up_l > 0:
                msg = "CDN 用户的限速仅下行生效"
                if cdn_msg:
                    msg += f"；{cdn_msg}"
            elif cdn_msg:
                msg = cdn_msg

    return {
        "ok": True,
        "ip": ip,
        "down_limit_mbps": down_l,
        "up_limit_mbps": up_l,
        "quota_gb": quota,
        "message": msg,
    }


@app.post("/api/admin/bind-device")
async def api_bind_device(req: IpReq, request: Request):
    require_auth(request)
    ip = canonical_ip(req.ip.strip())
    now_ts = int(time.time())
    if not ip:
        raise HTTPException(status_code=400, detail="无效的 IP 地址")
    async with STATE_LOCK:
        changed = ip not in STATE["admin_ips"]
        STATE["admin_sessions"][ip] = now_ts
        STATE["admin_ips"].add(ip)
        token = request.cookies.get("xp_session", "")
        token_sig = token.split(":")[-1] if token and ":" in token else ""
        if token_sig:
            STATE["session_device_map"][token_sig] = ip
        await sync_cdn_rate_map_with_retry(changed)
        admin_ips = sorted(STATE["admin_ips"])
    return {"ok": True, "ip": ip, "admin_ips": admin_ips}


@app.post("/api/client/kick")
async def api_kick_client(req: IpReq, request: Request):
    require_auth(request)
    ip = canonical_ip(req.ip.strip())
    if not ip:
        raise HTTPException(status_code=400, detail="无效的 IP 地址")
    async with STATE_LOCK:
        viewer_ip = resolve_viewer_ip(request)
        token = request.cookies.get("xp_session", "")
        token_sig = token.split(":")[-1] if token and ":" in token else ""
        bound_ip = STATE["session_device_map"].get(token_sig, "") if token_sig else ""
        if (viewer_ip and ip == viewer_ip) or (bound_ip and ip == bound_ip) or (ip in STATE["admin_ips"]):
            raise HTTPException(status_code=400, detail="安全保护：不能踢出当前正在操作的管理端 IP 连接！")
        await asyncio.to_thread(kill_ip_connections, ip)
        cdn_dropped, cdn_msg = await asyncio.to_thread(disconnect_cdn_if_safe, ip)
    if cdn_msg:
        return {"ok": True, "message": f"已处理：{cdn_msg}"}
    return {"ok": True, "message": f"已强制断开 {ip} 的活动连接"}


@app.post("/api/client/reset-traffic")
async def api_reset_traffic(req: IpReq, request: Request):
    require_auth(request)
    ip = "ALL" if req.ip.strip() == "ALL" else canonical_ip(req.ip)
    if not ip:
        raise HTTPException(status_code=400, detail="无效的 IP 地址")
    now_f = time.time()
    async with STATE_LOCK:
        nft_counts = await asyncio.to_thread(poll_nft_counters)
        if nft_counts is None:
            raise HTTPException(status_code=503, detail="防火墙计数暂不可用，流量未清空")
        with db_session() as conn:
            if ip == "ALL":
                all_rows = conn.execute("SELECT ip FROM clients").fetchall()
                reset_ips = set(row["ip"] for row in all_rows)
                reset_ips.update(STATE["cdn_pending_traffic"])
                for row in all_rows:
                    cip = row["ip"]
                    nc = nft_counts.get(cip, {"up_bytes": 0, "down_bytes": 0})
                    conn.execute(
                        "UPDATE clients SET base_up_bytes = ?, base_down_bytes = ?, last_nft_up = ?, last_nft_down = ?, peak_up_bps = 0, peak_down_bps = 0 WHERE ip = ?",
                        (-nc["up_bytes"], -nc["down_bytes"], nc["up_bytes"], nc["down_bytes"], cip),
                    )
            else:
                if not valid_ip(ip):
                    raise HTTPException(status_code=400, detail="无效的 IP 地址")
                nc = nft_counts.get(ip, {"up_bytes": 0, "down_bytes": 0})
                conn.execute(
                    "UPDATE clients SET base_up_bytes = ?, base_down_bytes = ?, last_nft_up = ?, last_nft_down = ?, peak_up_bps = 0, peak_down_bps = 0 WHERE ip = ?",
                    (-nc["up_bytes"], -nc["down_bytes"], nc["up_bytes"], nc["down_bytes"], ip),
                )
                reset_ips = [ip]
            conn.executemany(
                "INSERT OR REPLACE INTO traffic_resets (ip, reset_ts) VALUES (?, ?)",
                ((cip, now_f) for cip in reset_ips),
            )
            conn.commit()
        for cip in reset_ips:
            STATE["prev_totals"].pop(cip, None)
            STATE["traffic_reset_map"][cip] = now_f
            STATE["cdn_pending_traffic"].pop(cip, None)
            if cip in STATE["clients_live"]:
                STATE["clients_live"][cip].update(total_up=0, total_down=0, total_traffic=0)
        STATE["traffic_mutation_seq"] += 1
    return {"ok": True}


@app.post("/api/client/delete")
async def api_delete_client(req: IpReq, request: Request):
    require_auth(request)
    ip = "OFFLINE" if req.ip.strip() == "OFFLINE" else canonical_ip(req.ip)
    if not ip:
        raise HTTPException(status_code=400, detail="无效的 IP 地址")
    async with STATE_LOCK:
        v_ip = resolve_viewer_ip(request)
        token = request.cookies.get("xp_session", "")
        token_sig = token.split(":")[-1] if token and ":" in token else ""
        bound_ip = STATE["session_device_map"].get(token_sig, "") if token_sig else ""
        if ip == "OFFLINE":
            to_del = [
                cip for cip, info in list(STATE["clients_live"].items())
                if not info.get("is_online")
                and not info.get("is_blacklisted")
                and not info.get("is_whitelisted")
                and (info.get("alias") == "" or info.get("alias") is None)
                and cip != v_ip
                and cip != bound_ip
                and cip not in STATE["admin_ips"]
            ]
            deleted = 0
            now_f = time.time()
            deleted_ips = []
            with db_session() as conn:
                for cip in to_del:
                    if not await asyncio.to_thread(remove_nft_counter_rule, cip):
                        continue
                    conn.execute("DELETE FROM clients WHERE ip = ?", (cip,))
                    conn.execute(
                        "INSERT OR REPLACE INTO client_deletions (ip, delete_ts) VALUES (?, ?)",
                        (cip, now_f),
                    )
                    STATE["clients_live"].pop(cip, None)
                    STATE["prev_totals"].pop(cip, None)
                    STATE["cdn_pending_traffic"].pop(cip, None)
                    STATE["cdn_real_clients"].pop(cip, None)
                    deleted_ips.append(cip)
                    deleted += 1
                conn.commit()
            for cip in deleted_ips:
                STATE["client_delete_map"][cip] = now_f
            if deleted:
                STATE["traffic_mutation_seq"] += 1
            policy_pending = await refresh_network_policy_after_delete() if deleted else False
            return {"ok": True, "deleted": deleted, "failed": len(to_del) - deleted,
                    "policy_sync_pending": policy_pending}

        now_f = time.time()
        with db_session() as conn:
            if not valid_ip(ip):
                raise HTTPException(status_code=400, detail="无效的 IP 地址")

            if (v_ip and ip == v_ip) or (bound_ip and ip == bound_ip) or (ip in STATE["admin_ips"]):
                raise HTTPException(status_code=400, detail="防误操作保护：不能删除当前管理端/本机的记录！")

            if not await asyncio.to_thread(remove_nft_counter_rule, ip):
                raise HTTPException(status_code=503, detail="防火墙计数规则删除失败，客户端记录未移除")
            conn.execute("DELETE FROM clients WHERE ip = ?", (ip,))
            conn.execute(
                "INSERT OR REPLACE INTO client_deletions (ip, delete_ts) VALUES (?, ?)",
                (ip, now_f),
            )
            conn.commit()

        STATE["client_delete_map"][ip] = now_f
        await asyncio.to_thread(kill_ip_connections, ip)
        await asyncio.to_thread(disconnect_cdn_if_safe, ip)
        STATE["cdn_real_clients"].pop(ip, None)
        STATE["cdn_pending_traffic"].pop(ip, None)
        STATE["clients_live"].pop(ip, None)
        STATE["prev_totals"].pop(ip, None)
        STATE["traffic_mutation_seq"] += 1
        policy_pending = await refresh_network_policy_after_delete()
        return {"ok": True, "deleted": 1, "policy_sync_pending": policy_pending}


@app.post("/api/whitelist/toggle")
async def api_toggle_whitelist(req: IpReq, request: Request):
    require_auth(request)
    ip = canonical_ip(req.ip)
    if not ip:
        raise HTTPException(status_code=400, detail="无效的 IP 地址")
    if is_cloudflare_ip(ip):
        raise HTTPException(status_code=400, detail="安全保护：该 IP 属于 Cloudflare CDN 中继网段，严禁作为客户端操作或封禁！")
    now_int = int(time.time())
    async with STATE_LOCK:
        new_limits = None
        with db_session() as conn:
            row = conn.execute("SELECT is_whitelisted FROM clients WHERE ip = ?", (ip,)).fetchone()
            if row:
                new_val = 0 if row["is_whitelisted"] else 1
                conn.execute("UPDATE clients SET is_whitelisted = ? WHERE ip = ?", (new_val, ip))
            else:
                new_val = 1
                new_limits = default_client_limits(ip)
                conn.execute(
                    """INSERT INTO clients (ip, is_whitelisted, down_limit_mbps, up_limit_mbps,
                       quota_gb, first_seen, last_seen) VALUES (?, 1, ?, ?, ?, ?, ?)""",
                    (ip, *new_limits, now_int, now_int),
                )
            conn.commit()
        if new_limits and any(new_limits[:2]):
            try:
                await asyncio.to_thread(apply_tc_limits)
                await asyncio.to_thread(sync_cdn_rate_map)
            except Exception:
                with db_session() as conn:
                    conn.execute("DELETE FROM clients WHERE ip = ?", (ip,))
                    conn.commit()
                try:
                    await asyncio.to_thread(apply_tc_limits)
                    await asyncio.to_thread(sync_cdn_rate_map)
                except Exception:
                    logging.exception("Failed to restore policy after new whitelist client error")
                raise HTTPException(status_code=503, detail="默认限速下发失败，白名单未保存")
        if ip in STATE["clients_live"]:
            STATE["clients_live"][ip]["is_whitelisted"] = bool(new_val)
    return {"ok": True, "is_whitelisted": bool(new_val)}


@app.post("/api/blacklist/add")
async def api_blacklist_add(req: BlacklistAddReq, request: Request):
    require_auth(request)
    ip = canonical_ip(req.ip)
    if not ip:
        raise HTTPException(status_code=400, detail="请输入合法的 IP 地址（支持 IPv4 及 IPv6）")
    if is_cloudflare_ip(ip):
        raise HTTPException(status_code=400, detail="安全保护：该 IP 属于 Cloudflare CDN 中继网段，严禁作为客户端操作或封禁！")

    async with STATE_LOCK:
        viewer_ip = resolve_viewer_ip(request)
        token = request.cookies.get("xp_session", "")
        token_sig = token.split(":")[-1] if token and ":" in token else ""
        bound_ip = STATE["session_device_map"].get(token_sig, "") if token_sig else ""
        if (viewer_ip and ip == viewer_ip) or (bound_ip and ip == bound_ip) or (ip in STATE["admin_ips"]):
            raise HTTPException(status_code=400, detail="防误封保护：该 IP 是您当前的管理端/本机 IP，禁止拉黑自己！")

        with db_session() as conn:
            wrow = conn.execute("SELECT is_whitelisted FROM clients WHERE ip = ?", (ip,)).fetchone()
            if wrow and wrow["is_whitelisted"]:
                raise HTTPException(status_code=400, detail="该 IP 处于白名单保护中，请先移除白名单再拉黑")

            now_int = int(time.time())
            expires_at = (now_int + req.duration_seconds) if req.duration_seconds > 0 else 0
            conn.execute(
                "INSERT OR REPLACE INTO blacklist (ip, reason, created_at, expires_at, base_dropped_pkts, base_dropped_bytes) VALUES (?, ?, ?, ?, 0, 0)",
                (ip, req.reason.strip() or "管理员封禁", now_int, expires_at),
            )
            if not conn.execute("SELECT ip FROM clients WHERE ip = ?", (ip,)).fetchone():
                def_down, def_up, def_quota = default_client_limits(ip)
                conn.execute(
                    """INSERT INTO clients (ip, down_limit_mbps, up_limit_mbps, quota_gb,
                       first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)""",
                    (ip, def_down, def_up, def_quota, now_int, now_int),
                )
            conn.commit()

        if not await asyncio.to_thread(add_nft_ban_rule, ip):
            raise HTTPException(status_code=503, detail="封禁记录已保存，但防火墙规则未生效，请检查 nftables")
        queue_geo_ip(ip)
        cdn_dropped, cdn_msg = await asyncio.to_thread(disconnect_cdn_if_safe, ip)
        if ip in STATE["clients_live"]:
            STATE["clients_live"][ip].update(
                is_blacklisted=True, is_online=False, active_conns=0,
                up_speed=0, down_speed=0)
        msg = "已加入黑名单并阻断连接"
        if cdn_msg:
            msg = f"已加入黑名单（{cdn_msg}）"
        return {"ok": True, "ip": ip, "expires_at": expires_at, "message": msg}


@app.post("/api/blacklist/remove")
async def api_blacklist_remove(req: IpReq, request: Request):
    require_auth(request)
    ip = canonical_ip(req.ip)
    if not ip:
        raise HTTPException(status_code=400, detail="非法 IP 地址")
    async with STATE_LOCK:
        with db_session() as conn:
            row = conn.execute(
                "SELECT down_limit_mbps, up_limit_mbps FROM clients WHERE ip = ?", (ip,)
            ).fetchone()
        if row and (row["down_limit_mbps"] or row["up_limit_mbps"]):
            try:
                await asyncio.to_thread(apply_tc_limits)
                await asyncio.to_thread(sync_cdn_rate_map)
            except Exception:
                raise HTTPException(status_code=503, detail="限速规则下发失败，黑名单记录未移除")
        if not await asyncio.to_thread(remove_nft_ban_rule, ip):
            raise HTTPException(status_code=503, detail="防火墙封禁规则删除失败，黑名单记录未移除")
        with db_session() as conn:
            conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
            conn.commit()
        if ip in STATE["clients_live"]:
            STATE["clients_live"][ip]["is_blacklisted"] = False
    return {"ok": True, "ip": ip}


@app.post("/api/settings")
async def api_update_settings(req: SettingsReq, request: Request):
    require_auth(request)
    updates = {
        "global_down_limit_mbps": str(safe_float(req.global_down_limit_mbps)),
        "default_ip_down_limit_mbps": str(safe_float(req.default_ip_down_limit_mbps)),
        "default_ip_up_limit_mbps": str(safe_float(req.default_ip_up_limit_mbps)),
        "default_ip_quota_gb": str(safe_float(req.default_ip_quota_gb, max_v=1000000.0)),
        "auto_ban_conn_limit": str(max(0, min(req.auto_ban_conn_limit, 65535))),
    }
    async with STATE_LOCK:
        with db_session() as conn:
            previous = {
                key: (row["value"] if row else None)
                for key in updates
                for row in [conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()]
            }
            for key, value in updates.items():
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
        try:
            await asyncio.to_thread(apply_tc_limits)
            await asyncio.to_thread(sync_cdn_rate_map)
        except Exception:
            try:
                with db_session() as conn:
                    for key, value in previous.items():
                        if value is None:
                            conn.execute("DELETE FROM settings WHERE key = ?", (key,))
                        else:
                            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
                    conn.commit()
                await asyncio.to_thread(apply_tc_limits)
                await asyncio.to_thread(sync_cdn_rate_map)
            except Exception:
                logging.exception("Failed to restore network settings after update error")
            raise HTTPException(status_code=503, detail="设置下发失败，原配置已尝试恢复")
    return {"ok": True, "settings": get_all_settings()}
