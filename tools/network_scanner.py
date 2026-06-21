"""
tools/network_scanner.py — ポートスキャン・サービス検出

外部依存なし（stdlib socket のみ）。スレッドプールで高速スキャン。
"""

from __future__ import annotations
import socket
import ssl
import random
import time
import concurrent.futures
from core.settings import (
    COMMON_PORTS, PORT_SCAN_TIMEOUT, PORT_SCAN_THREADS,
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE,
)

SERVICE_MAP = {
    21: "FTP",    22: "SSH",     23: "Telnet",   25: "SMTP",
    53: "DNS",    80: "HTTP",    110: "POP3",    135: "RPC",
    139: "NetBIOS",143: "IMAP",  443: "HTTPS",  445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3000: "Dev/Node",
    3306: "MySQL", 3389: "RDP",   5000: "Dev/Flask",
    5432: "PostgreSQL", 6379: "Redis", 8000: "Dev/HTTP",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter/Dev",
    9200: "Elasticsearch", 27017: "MongoDB",
}

UDP_SERVICE_MAP = {
    53: "DNS",   67: "DHCP",  68: "DHCP",  69: "TFTP",  123: "NTP",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP", 162: "SNMP-Trap",
    500: "IKE",  514: "Syslog", 520: "RIP", 1900: "SSDP", 4500: "IPsec-NAT",
    5353: "mDNS",
}

# 一部UDPサービスは特定プロトプローブで応答が得やすい
_UDP_PROBES = {
    53:  b"\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b" + b"\x00" * 47,   # NTP
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
}


def _service_name(port: int) -> str:
    """ポート番号からサービス名を返す（未知なら system DB を参照）。"""
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


class NetworkScanner:
    def __init__(
        self,
        timeout: float = PORT_SCAN_TIMEOUT,
        max_threads: int = PORT_SCAN_THREADS,
        ports: list[int] | None = None,
        jitter: tuple[float, float] = (0.0, 0.0),
        randomize: bool = False,
    ):
        self.timeout     = timeout
        self.max_threads = max_threads
        self.ports       = ports or COMMON_PORTS
        self.jitter      = jitter      # 各接続前のランダム遅延 (min, max) 秒
        self.randomize   = randomize   # ポート走査順をシャッフルするか

    @classmethod
    def from_profile(cls, name: str, ports: list[int] | None = None) -> "NetworkScanner":
        """settings.SCAN_PROFILES からステルスプロファイルを適用して生成する。"""
        prof = SCAN_PROFILES.get(name, SCAN_PROFILES[DEFAULT_SCAN_PROFILE])
        return cls(
            timeout=prof["timeout"],
            max_threads=prof["threads"],
            ports=ports,
            jitter=prof["jitter"],
            randomize=prof["randomize"],
        )

    # ── ホスト解決 ─────────────────────────────────────────
    def resolve(self, target: str) -> tuple[str, str | None]:
        """
        URL/ホスト名/IPを正規化し、(ホスト名, IPアドレス) を返す。
        解決失敗時は (target, None)。
        """
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        try:
            ip = socket.gethostbyname(host)
            return host, ip
        except socket.gaierror:
            return host, None

    # ── ポートスキャン ─────────────────────────────────────
    def scan(self, host: str) -> list[dict]:
        """
        指定ホストの COMMON_PORTS をスキャンし、開放ポートのリストを返す。
        [{port, service, banner}, ...]
        """
        open_ports = []
        # ステルス時はポート順をシャッフル（順次走査はIDS検知の典型パターン）
        ports = list(self.ports)
        if self.randomize:
            random.shuffle(ports)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(self._check_port, host, p): p for p in ports}
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports, key=lambda x: x["port"])

    def _check_port(self, host: str, port: int) -> dict | None:
        # レート検知を回避するため接続前にランダム遅延を挿入
        lo, hi = self.jitter
        if hi > 0:
            time.sleep(random.uniform(lo, hi))
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                banner = self._grab_banner(s, host, port)
                return {
                    "port":    port,
                    "service": _service_name(port),
                    "banner":  banner,
                }
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    # ── UDPスキャン（参考情報・open|filtered の曖昧さあり） ──
    def scan_udp(self, host: str, ports: list[int]) -> list[dict]:
        """指定UDPポートを走査する。応答ありは open、無応答は open|filtered。

        UDPは無応答だと open/filtered の区別が付かないため検出は参考扱い。
        ICMP port unreachable（接続リセット）を受けたポートは closed として除外する。
        """
        results: list[dict] = []
        plist = list(ports)
        if self.randomize:
            random.shuffle(plist)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(self._check_udp_port, host, p): p for p in plist}
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    results.append(result)
        return sorted(results, key=lambda x: x["port"])

    def _check_udp_port(self, host: str, port: int) -> dict | None:
        lo, hi = self.jitter
        if hi > 0:
            time.sleep(random.uniform(lo, hi))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            s.sendto(_UDP_PROBES.get(port, b"\x00"), (host, port))
            try:
                data, _ = s.recvfrom(1024)
                status = "open"
            except socket.timeout:
                status = "open|filtered"   # 無応答（区別不能）
                data = b""
            return {
                "port":    port,
                "service": UDP_SERVICE_MAP.get(port, "unknown") + "/udp",
                "banner":  status + (f" ({len(data)}B resp)" if data else ""),
            }
        except (ConnectionResetError, ConnectionRefusedError):
            return None   # ICMP port unreachable → closed
        except OSError:
            return None
        finally:
            s.close()

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        """バナーを取得する（失敗時は空文字）。"""
        try:
            sock.settimeout(2.0)
            if port == 443:
                return self._ssl_info(host)
            if port in (80, 8080, 8000, 8443, 3000, 5000, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").split("\n")[0].strip()[:120]
        except Exception:
            return ""

    def _ssl_info(self, host: str) -> str:
        """HTTPS ポートのSSL証明書情報を取得する。"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3.0)
                s.connect((host, 443))
                cert = s.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                return (
                    f"SSL: CN={subject.get('commonName','')} "
                    f"Issuer={issuer.get('organizationName','')} "
                    f"Expires={cert.get('notAfter','')}"
                )
        except Exception as e:
            return f"SSL probe failed: {e}"


# ── 受動OSフィンガープリント ────────────────────────────────
# バナー／HTTPヘッダーから受動的にOSを推定する。追加パケットを送らない
# ため完全にステルス（nmap -O のようなアクティブ探査とは異なる）。
_OS_HINTS = [
    ("Linux (Ubuntu)",        ("ubuntu",)),
    ("Linux (Debian)",        ("debian",)),
    ("Linux (RHEL/CentOS)",   ("centos", "red hat", "rhel", "rocky", "almalinux")),
    ("Linux (Alpine)",        ("alpine",)),
    ("Windows",               ("win32", "win64", "microsoft-iis", "microsoft-httpapi", " windows")),
    ("FreeBSD",               ("freebsd",)),
    ("macOS",                 ("darwin", "mac os")),
]


def passive_os_fingerprint(
    open_ports: list[dict],
    web_headers: dict | None = None,
) -> str | None:
    """
    収集済みバナー・ヘッダーからOSを推定する（追加通信なし）。
    判定できなければ None を返す。
    """
    parts = [p.get("banner", "") for p in open_ports]
    if web_headers:
        parts += [f"{k}: {v}" for k, v in web_headers.items()]
    text = " ".join(parts).lower()
    if not text.strip():
        return None
    for label, needles in _OS_HINTS:
        if any(n in text for n in needles):
            return label
    # 直接の手掛かりがない場合のフォールバック（OpenSSHはUnix系の強い示唆）
    if "openssh" in text:
        return "Linux/Unix (推定: OpenSSH)"
    if "nginx" in text or "apache" in text:
        return "Linux/Unix (推定: Webサーバ)"
    return None
