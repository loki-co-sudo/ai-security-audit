"""
tools/pdf_writer.py — 日本語対応 PDF レポートレンダラー（依存: Pillow のみ）

PDF 標準14フォントは日本語(CJK)を描画できず、TrueType フォント埋め込みは
サブセット化が複雑で巨大になる。そのため本モジュールは Pillow で各ページを
高解像度画像として描画し、Pillow の PDF 保存機能で多ページ PDF にまとめる。
ラスタライズされるが、日本語を確実に表示でき、HTMLレポートと同じ配色で
統一感のある体裁を保てる。Pillow が無い環境では render() が None を返す。
"""

from __future__ import annotations
import io
import os

# ── ページ寸法（A4 縦 / 150 DPI） ───────────────────────────
PAGE_W, PAGE_H = 1240, 1754
MARGIN         = 84
CONTENT_W      = PAGE_W - MARGIN * 2

# ── 配色（settings のテーマと一致） ─────────────────────────
C_BG      = (7,   12,  20)    # #070C14
C_PANEL   = (11,  18,  32)    # #0B1220
C_WIDGET  = (14,  24,  40)    # #0E1828
C_BORDER  = (26,  48,  80)    # #1A3050
C_CYAN    = (0,   212, 255)   # #00D4FF
C_GREEN   = (0,   255, 136)   # #00FF88
C_RED     = (255, 59,  59)    # #FF3B3B
C_ORANGE  = (255, 122, 59)    # #FF7A3B
C_YELLOW  = (255, 215, 0)     # #FFD700
C_TEXT    = (216, 232, 244)   # #D8E8F4
C_DIM     = (74,  106, 138)   # #4A6A8A
C_MID     = (122, 154, 190)   # #7A9ABE

_SEV_COLOR = {
    "CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW, "LOW": C_GREEN,
}

# labels が渡されない場合のフォールバック（日本語）
_DEFAULT_LABELS = {
    "doc_title": "セキュリティ診断レポート",
    "scan_mode": "スキャンモード", "target": "対象", "engine": "AI エンジン",
    "date": "診断日時", "summary": "エグゼクティブサマリ — 深刻度分布",
    "findings": "検出項目の詳細", "raw": "スキャン出力（全文）",
    "vuln_code": "該当箇所 / コード", "attack": "攻撃 / 分析", "fix": "推奨対策",
    "ref": "参照", "location": "箇所", "no_output": "(出力なし)",
    "footer": ("本レポートは AI Security Audit System により自動生成されました。"
               "内容は参考情報です。本ツールは教育・研究・許可された診断のみを目的としています。"),
}

# ── フォント候補（Windows優先、Linuxフォールバック付き） ────
_JP_FONTS = [
    (r"C:\Windows\Fonts\YuGothM.ttc", 0), (r"C:\Windows\Fonts\YuGothR.ttc", 0),
    (r"C:\Windows\Fonts\meiryo.ttc", 0),  (r"C:\Windows\Fonts\msgothic.ttc", 0),
    (r"C:\Windows\Fonts\BIZ-UDGothicR.ttc", 0),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
    ("/usr/share/fonts/truetype/fonts-japanese-gothic.ttf", 0),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0),  # 最終手段(日本語不可)
]
# 等幅かつ日本語対応（コード/生ログ用）
_MONO_FONTS = [
    (r"C:\Windows\Fonts\msgothic.ttc", 0),   # MS ゴシックは ASCII/CJK とも等幅
    (r"C:\Windows\Fonts\consola.ttf", 0),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
]


def _load_font(candidates, size):
    from PIL import ImageFont
    for path, idx in candidates:
        try:
            if os.path.exists(path):
                return ImageFont.truetype(path, size, index=idx)
        except Exception:
            continue
    return ImageFont.load_default()


class _Renderer:
    """ページを順に描画していくシンプルなフローレイアウトエンジン。"""

    def __init__(self, labels: dict | None = None):
        from PIL import ImageDraw  # noqa: F401  (存在確認)
        self.lbl    = labels or _DEFAULT_LABELS
        self.f_h1   = _load_font(_JP_FONTS, 40)
        self.f_h2   = _load_font(_JP_FONTS, 22)
        self.f_body = _load_font(_JP_FONTS, 21)
        self.f_bold = _load_font(_JP_FONTS, 21)
        self.f_small= _load_font(_JP_FONTS, 17)
        self.f_mono = _load_font(_MONO_FONTS, 18)
        self.f_badge= _load_font(_JP_FONTS, 18)
        self.f_big  = _load_font(_JP_FONTS, 54)
        self.pages  = []
        self.img    = None
        self.draw   = None
        self.y      = 0
        self._new_page()

    # ── ページ管理 ─────────────────────────────────────────
    def _new_page(self):
        from PIL import Image, ImageDraw
        self.img  = Image.new("RGB", (PAGE_W, PAGE_H), C_BG)
        self.draw = ImageDraw.Draw(self.img)
        self.pages.append(self.img)
        self.y = MARGIN

    def _ensure(self, height: int):
        """残り高さが足りなければ改ページする。"""
        if self.y + height > PAGE_H - MARGIN:
            self._new_page()

    # ── テキスト計測・折返し ───────────────────────────────
    def _text_w(self, s: str, font) -> float:
        return self.draw.textlength(s, font=font)

    def _wrap(self, text: str, font, max_w: int) -> list[str]:
        lines = []
        for raw in text.split("\n"):
            if raw == "":
                lines.append("")
                continue
            cur = ""
            for ch in raw:
                if self._text_w(cur + ch, font) <= max_w:
                    cur += ch
                else:
                    lines.append(cur)
                    cur = ch
            lines.append(cur)
        return lines

    # ── 描画プリミティブ ───────────────────────────────────
    def _rect(self, x, y, w, h, fill=None, outline=None, width=1, radius=8):
        self.draw.rounded_rectangle(
            [x, y, x + w, y + h], radius=radius,
            fill=fill, outline=outline, width=width,
        )

    def _line_block(self, lines, font, color, x, lh, indent=0):
        for ln in lines:
            self._ensure(lh)
            self.draw.text((x + indent, self.y), ln, font=font, fill=color)
            self.y += lh

    # ── 高レベル要素 ───────────────────────────────────────
    def header(self, mode, target, model, timestamp, version):
        h = 196
        self._rect(MARGIN, self.y, CONTENT_W, h, fill=C_PANEL,
                   outline=C_BORDER, width=2, radius=12)
        ix = MARGIN + 28
        iy = self.y + 24
        self.draw.text((ix, iy), self.lbl["doc_title"],
                       font=self.f_h1, fill=C_CYAN)
        iy += 64
        for label, val in [
            (self.lbl["scan_mode"], mode), (self.lbl["target"], target or "—"),
            (self.lbl["engine"], model), (self.lbl["date"], timestamp),
        ]:
            self.draw.text((ix, iy), f"{label}:", font=self.f_small, fill=C_MID)
            self.draw.text((ix + 180, iy), str(val), font=self.f_small, fill=C_TEXT)
            iy += 28
        self.draw.text((PAGE_W - MARGIN - 220, self.y + 24),
                       f"v{version}", font=self.f_small, fill=C_DIM)
        self.y += h + 30

    def heading(self, text):
        self._ensure(56)
        self.draw.text((MARGIN, self.y), text.upper(), font=self.f_h2, fill=C_CYAN)
        self.y += 34
        self.draw.line([MARGIN, self.y, PAGE_W - MARGIN, self.y],
                       fill=C_BORDER, width=2)
        self.y += 22

    def severity_summary(self, counts: dict):
        gap   = 18
        bw    = (CONTENT_W - gap * 3) // 4
        bh    = 130
        self._ensure(bh + 10)
        x = MARGIN
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            col = _SEV_COLOR[sev]
            self._rect(x, self.y, bw, bh, fill=C_PANEL, outline=C_BORDER, width=2)
            n = str(counts.get(sev, 0))
            self.draw.text((x + 22, self.y + 20), sev, font=self.f_small, fill=col)
            nw = self._text_w(n, self.f_big)
            self.draw.text((x + (bw - nw) / 2, self.y + 48), n,
                           font=self.f_big, fill=col)
            x += bw + gap
        self.y += bh + 30

    def finding(self, f: dict):
        sev  = (f.get("severity") or "LOW").upper()
        col  = _SEV_COLOR.get(sev, C_GREEN)
        name = f.get("name") or "Unknown"

        # カード上端の見積りで改ページ（最低でもヘッダ分は同一ページに）
        self._ensure(120)
        start_page = len(self.pages)   # ページ跨ぎ検出用
        card_top = self.y
        x0 = MARGIN + 22
        inner_w = CONTENT_W - 44
        self.y += 22

        # 重大度バッジ + タイトル
        badge_w = self._text_w(sev, self.f_badge) + 28
        self._rect(x0, self.y, badge_w, 30, fill=col, radius=6)
        self.draw.text((x0 + 14, self.y + 4), sev, font=self.f_badge, fill=C_BG)
        for ln in self._wrap(name, self.f_bold, inner_w - badge_w - 20):
            self.draw.text((x0 + badge_w + 16, self.y + 2), ln, font=self.f_bold, fill=C_TEXT)
            break  # タイトルは1行に丸める（バッジ右）
        self.y += 44

        # メタ（REF / LOCATION）
        meta = " | ".join(
            f"{k}: {v}" for k, v in
            [(self.lbl["ref"], f.get("ref", "")), (self.lbl["location"], f.get("lines", ""))] if v
        )
        if meta:
            self._line_block(self._wrap(meta, self.f_small, inner_w), self.f_small,
                             C_MID, x0, 24)
            self.y += 4

        # メタ（REF / LOCATION）のラベルもローカライズ済み（下記 meta で使用）

        # セクション（脆弱コード / 攻撃・分析 / 修正）
        for label, key, mono in [
            (self.lbl["vuln_code"], "snippet", True),
            (self.lbl["attack"], "attack", False),
            (self.lbl["fix"], "fix", True),
        ]:
            val = f.get(key)
            if not val:
                continue
            self._ensure(40)
            self.draw.text((x0, self.y), label, font=self.f_small, fill=C_CYAN)
            self.y += 26
            font = self.f_mono if mono else self.f_body
            lh   = 24 if mono else 28
            block_lines = self._wrap(val, font, inner_w - 24)
            # コード/修正は薄パネル背景
            if mono:
                bh = lh * len(block_lines) + 16
                self._ensure(bh)
                self._rect(x0, self.y, inner_w, bh, fill=C_WIDGET,
                           outline=C_BORDER, width=1, radius=6)
                self.y += 8
                self._line_block(block_lines, font, C_TEXT, x0 + 12, lh)
                self.y += 8
            else:
                self._line_block(block_lines, font, C_MID, x0, lh)
            self.y += 6

        # カードを囲む枠（左アクセントバー付き）。
        # ページを跨いだ場合は card_top が別ページの座標になり矩形が破綻するため枠を省略する。
        card_bottom = self.y + 10
        if len(self.pages) == start_page and card_bottom > card_top:
            self.draw.rectangle([MARGIN, card_top, MARGIN + 6, card_bottom], fill=col)
            self.draw.rounded_rectangle(
                [MARGIN, card_top, PAGE_W - MARGIN, card_bottom],
                radius=10, outline=C_BORDER, width=2,
            )
        self.y = card_bottom + 22

    def raw_block(self, text: str):
        self.heading(self.lbl["raw"])
        lines = self._wrap(text.strip() or self.lbl["no_output"], self.f_mono, CONTENT_W - 28)
        self._line_block(lines, self.f_mono, C_MID, MARGIN + 14, 22)
        self.y += 10

    def footer_all(self):
        note = self.lbl["footer"]
        for i, page in enumerate(self.pages, 1):
            from PIL import ImageDraw
            d = ImageDraw.Draw(page)
            d.line([MARGIN, PAGE_H - 64, PAGE_W - MARGIN, PAGE_H - 64],
                   fill=C_BORDER, width=1)
            d.text((MARGIN, PAGE_H - 52), note[:74], font=self.f_small, fill=C_DIM)
            pg = f"{i} / {len(self.pages)}"
            d.text((PAGE_W - MARGIN - d.textlength(pg, font=self.f_small),
                    PAGE_H - 52), pg, font=self.f_small, fill=C_DIM)

    def to_pdf_bytes(self) -> bytes:
        self.footer_all()
        buf = io.BytesIO()
        first, rest = self.pages[0], self.pages[1:]
        first.save(buf, format="PDF", resolution=150.0,
                   save_all=True, append_images=rest)
        return buf.getvalue()


def render(meta: dict, counts: dict, findings: list[dict], raw_text: str,
           labels: dict | None = None) -> bytes | None:
    """レポートPDFをバイト列で返す。Pillow が無ければ None。"""
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        return None

    lbl = labels or _DEFAULT_LABELS
    r = _Renderer(lbl)
    r.header(
        mode=meta.get("mode", ""), target=meta.get("target", ""),
        model=meta.get("model", ""), timestamp=meta.get("timestamp", ""),
        version=meta.get("version", ""),
    )
    r.heading(lbl["summary"])
    r.severity_summary(counts)
    if findings:
        r.heading(f'{lbl["findings"]} ({len(findings)})')
        for f in findings:
            r.finding(f)
    r.raw_block(raw_text)
    return r.to_pdf_bytes()
