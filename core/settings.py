"""
core/settings.py — アプリ全体の設定定数
"""

# ============================================================
#  LLM バックエンド接続設定 — ここを変えるだけで切り替え可能
# ============================================================
LLM_BASE_URL = "http://localhost:11434/v1"   # Ollama ローカル
# LLM_BASE_URL = "https://api.openai.com/v1" # OpenAI クラウド
LLM_API_KEY  = "ollama"                       # クラウドなら実APIキー
LLM_MODEL    = "qwen2.5-coder:14b"
LLM_TIMEOUT  = 180
# ============================================================

APP_TITLE   = "AI Security Audit System  ·  Autonomous Penetration Testing & Defense v2.3"
APP_VERSION = "2.3.0"

# ─── カラーテーマ ───────────────────────────────────────────
BG_ROOT    = "#070C14"
BG_PANEL   = "#0B1220"
BG_WIDGET  = "#0E1828"
BG_INPUT   = "#111F30"

CYAN       = "#00D4FF"
GREEN      = "#00FF88"
RED_C      = "#FF3B3B"
ORANGE_H   = "#FF7A3B"
YELLOW_M   = "#FFD700"
GREEN_L    = "#39FF75"
PURPLE     = "#BF7FFF"
AMBER      = "#FFA500"

TEXT_PRI   = "#D8E8F4"
TEXT_DIM   = "#4A6A8A"
TEXT_MID   = "#7A9ABE"
BORDER     = "#1A3050"

SEV_COLORS = {
    "CRITICAL": RED_C,
    "HIGH":     ORANGE_H,
    "MEDIUM":   YELLOW_M,
    "LOW":      GREEN_L,
}

# タブカラー
TAB_AUDIT   = CYAN
TAB_ATTACK  = RED_C
TAB_DEFENSE = GREEN

# ─── フォント ────────────────────────────────────────────────
FONT_UI    = ("Segoe UI", 11)
FONT_TITLE = ("Segoe UI", 19, "bold")
FONT_MONO  = ("Consolas", 11)
FONT_MONO_SM = ("Consolas", 10)

# ─── ネットワークスキャン設定 ──────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 1433, 1521, 3000, 3306, 3389, 5000,
    5432, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
]
PORT_SCAN_TIMEOUT  = 1.5   # 秒
PORT_SCAN_THREADS  = 50
WEB_REQUEST_TIMEOUT = 10   # 秒

# ─── スキャンプロファイル（ステルス制御） ──────────────────
# ATTACK MODE のフットプリント（検知されやすさ）と速度のトレードオフ。
# stealth が最も静か、aggressive が最速。authorized な診断専用。
#   timeout      : 1接続あたりの待機秒
#   threads      : ポートスキャン同時接続数（少ないほど静か）
#   jitter       : 各接続前のランダム遅延 (min, max) 秒 — レート検知を回避
#   randomize    : ポート走査順をシャッフルするか（順次走査はIDS検知の典型）
#   path_threads : Webパス探索の同時接続数
#   path_jitter  : Webパス探索のランダム遅延 (min, max) 秒
#   max_paths    : センシティブパス探索数の上限（None=全件）
SCAN_PROFILES = {
    "stealth": {
        "timeout": 2.0, "threads": 4,  "jitter": (0.15, 0.6),
        "randomize": True,  "path_threads": 2,  "path_jitter": (0.2, 0.8),
        "max_paths": 12,
    },
    "passive": {
        "timeout": 1.5, "threads": 10, "jitter": (0.05, 0.25),
        "randomize": True,  "path_threads": 4,  "path_jitter": (0.05, 0.3),
        "max_paths": None,
    },
    "moderate": {
        "timeout": 1.0, "threads": 30, "jitter": (0.0, 0.05),
        "randomize": True,  "path_threads": 8,  "path_jitter": (0.0, 0.05),
        "max_paths": None,
    },
    "aggressive": {
        "timeout": 0.5, "threads": 80, "jitter": (0.0, 0.0),
        "randomize": False, "path_threads": 16, "path_jitter": (0.0, 0.0),
        "max_paths": None,
    },
}
DEFAULT_SCAN_PROFILE = "stealth"

# 実在ブラウザを模した User-Agent プール（ステルス時にローテーション）。
# 自己申告型UA（"Security Audit Tool"）は検知を誘発するため使用しない。
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# センシティブパスリスト（Webスキャン用）
SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD",
    "/.env", "/.env.production", "/.env.local",
    "/admin", "/admin/", "/administrator",
    "/wp-admin", "/wp-login.php",
    "/phpinfo.php", "/info.php",
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/api", "/api/v1", "/api/docs", "/swagger",
    "/swagger-ui.html", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.htaccess", "/web.config",
    "/server-status", "/server-info",
]

# セキュリティヘッダー（存在すべきもの）
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ─── ログ解析設定 ──────────────────────────────────────────
LOG_WATCH_INTERVAL = 1.0   # 秒
LOG_BATCH_SIZE     = 50    # AI送信バッチ行数
LOG_MAX_CONTEXT    = 100   # AI送信最大行数

# 攻撃シグネチャパターン（正規表現）
ATTACK_PATTERNS = {
    "SQL_INJECTION":    r"(?i)(union\s+select|or\s+1=1|'\s*or\s+'|--\s*$|;\s*drop\s+table|xp_cmdshell)",
    "XSS":              r"(?i)(<script|javascript:|onerror=|onload=|alert\s*\(|document\.cookie)",
    "LFI_RFI":          r"(?i)(\.\.\/|\.\.\\\\|%2e%2e%2f|file://|php://|expect://|data://)",
    "CMD_INJECTION":    r"(?i)(;\s*(ls|cat|id|whoami|pwd|wget|curl)\b|`[^`]+`|\$\([^)]+\))",
    "BRUTE_FORCE":      r"(failed login|authentication failure|invalid (password|credentials))",
    "SCANNER":          r"(?i)(nikto|sqlmap|nmap|masscan|nessus|openvas|burpsuite|zap)",
    "PATH_TRAVERSAL":   r"(?i)(\.\./|\.\.\\\\|%252e%252e|%c0%ae|%c1%9c)",
    "SSRF":             r"(?i)(http://localhost|http://127\.|http://169\.254|file://|dict://|gopher://)",
}
