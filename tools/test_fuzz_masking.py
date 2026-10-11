"""WEB FUZZの表示・LLM送信・保存前マスキング(P1.2)を、ローカルサーバ＋モックLLMで実走して検証する。"""
import http.server
import json
import os
import re
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from agents.fuzz_agent import FuzzAgent
from core.event_bus import EventBus

URL_SECRET = "URLTOKEN_Zk93mQ"
COOKIE = "session=cookiesecret_0123456789; theme=darkdarkdark"


class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        body = "<html><body>"
        if u.path == "/":
            body += f'<a href="/s?q=1&token={URL_SECRET}">s</a>'
        elif u.path == "/s":
            body += f"result: {q.get('q', [''])[0]} cookie={self.headers.get('Cookie', '')}"  # 反射(未エスケープ)
        body += "</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class _FakeLLM:
    model = "fake-model"

    def __init__(self):
        self.received = []

    @staticmethod
    def system(c):
        return {"role": "system", "content": c}

    @staticmethod
    def user(c):
        return {"role": "user", "content": c}

    def stream(self, messages, on_chunk=None, on_error=None):
        self.received.append(messages)
        return ""

    def complete(self, messages):
        self.received.append(messages)
        return "{}"


def _all_text(root):
    return "".join(p.read_text(encoding="utf-8", errors="replace")
                   for p in Path(root).rglob("*") if p.is_file())


class FuzzMaskingTest(unittest.TestCase):
    def test_secrets_do_not_reach_display_llm_or_files(self):
        srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}/"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cwd = os.getcwd()
                os.chdir(tmp)
                try:
                    llm = _FakeLLM()
                    bus = EventBus()
                    agent = FuzzAgent(bus, llm)
                    agent._fast_client = lambda: llm  # モックを高速モデル役にも使う
                    agent.run(base, profile="aggressive", max_requests=300,
                              auth={"cookie": COOKIE})
                    events = []
                    while True:
                        b = bus.drain()
                        if not b:
                            break
                        events.extend(b)
                finally:
                    os.chdir(cwd)
                shown = json.dumps([e.payload for e in events], ensure_ascii=False, default=str)
                sent = json.dumps(llm.received, ensure_ascii=False)
                files = _all_text(tmp)
                result = agent._last_scan_result
                # 前提: 異常が観測され、表示・LLMに到達している（空振りで通らない）
                self.assertIn("ANOMALIES OBSERVED", sent)
                self.assertRegex(shown, r"\[XSS\]|\[SSTI\]|\[SQLI\]|\[TRAVERSAL\]")
                for leak in (URL_SECRET, "cookiesecret_0123456789", "darkdarkdark"):
                    for name, blob in (("表示", shown), ("LLM", sent), ("保存物", files)):
                        self.assertNotIn(leak, blob, f"{name}に{leak}が残っている")
                self.assertIn("REDACTED", shown + sent)
                self.assertTrue(result is not None)
        finally:
            srv.shutdown()

    def test_known_secrets_split_cookie_pairs(self):
        s = FuzzAgent._known_secrets({"cookie": COOKIE}, None)
        self.assertIn(COOKIE, s)
        self.assertIn("session=cookiesecret_0123456789", s)
        self.assertIn("cookiesecret_0123456789", s)  # 8文字以上の値は単独でも登録
        short = FuzzAgent._known_secrets({"cookie": "a=1; b=22"}, None)
        self.assertNotIn("1", short)  # 短い値は誤マスク防止のため単独登録しない
        self.assertNotIn("22", short)


if __name__ == "__main__":
    unittest.main()
