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

APP_TITLE   = "AI Security Audit System  ·  Autonomous Penetration Testing & Defense v2.0"
APP_VERSION = "2.0.0"

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
