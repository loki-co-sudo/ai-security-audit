"""
tools/network_scanner.py — ポートスキャン・サービス検出

外部依存なし（stdlib socket のみ）。スレッドプールで高速スキャン。
"""

from __future__ import annotations
import socket
import ssl
import concurrent.futures
from core.settings import COMMON_PORTS, PORT_SCAN_TIMEOUT, PORT_SCAN_THREADS

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


class NetworkScanner:
    def __init__(
        self,
        timeout: float = PORT_SCAN_TIMEOUT,
        max_threads: int = PORT_SCAN_THREADS,
        ports: list[int] | None = None,
    ):
        self.timeout     = timeout
        self.max_threads = max_threads
        self.ports       = ports or COMMON_PORTS

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
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(self._check_port, host, p): p for p in self.ports}
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports, key=lambda x: x["port"])

    def _check_port(self, host: str, port: int) -> dict | None:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                banner = self._grab_banner(s, host, port)
                return {
                    "port":    port,
                    "service": SERVICE_MAP.get(port, "unknown"),
                    "banner":  banner,
                }
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

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
