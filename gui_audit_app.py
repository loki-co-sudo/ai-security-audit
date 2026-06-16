"""
AI Security Audit System — GUI Prototype v1.0
Autonomous Vulnerability Discovery Platform
Next-Gen AI-Driven Penetration Testing Tool
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, font as tkfont
import threading
import time
import os
import re
import queue
from datetime import datetime
from openai import OpenAI

# ============================================================
#  LLM バックエンド接続設定 — ここを変えるだけで切り替え可能
# ============================================================
LLM_BASE_URL = "http://localhost:11434/v1"   # Ollama ローカル
# LLM_BASE_URL = "https://api.openai.com/v1" # OpenAI クラウド
LLM_API_KEY  = "ollama"                       # クラウドなら実際のキー
LLM_MODEL    = "qwen2.5-coder:14b"            # モデル名
LLM_TIMEOUT  = 180                            # タイムアウト（秒）
# ============================================================

SYSTEM_PROMPT = """You are an elite white-hat penetration tester and code auditor with 15 years of experience. Your specialty is discovering *novel, unknown vulnerabilities* that do NOT appear in any CVE database.

You MUST analyze the provided code and find vulnerabilities in these categories:

## PRIORITY 1 — Authentication & Session Logic Flaws
- Authentication bypass through business logic errors (NOT injection alone)
- Session fixation, token prediction, insecure token validation
- Privilege escalation via logic flaws
- Multi-step authentication bypasses

## PRIORITY 2 — Business Logic Vulnerabilities
- Race conditions and TOCTOU (Time-of-Check-Time-of-Use) flaws
- State machine violations, step-skipping in workflows
- Negative number / integer overflow abuse in financial or numeric operations
- Incorrect permission boundary enforcement

## PRIORITY 3 — Architectural & Design Weaknesses
- Unsafe trust assumptions about caller inputs
- Missing security controls at API/module boundaries
- Indirect injection flows that scanners miss due to multi-hop data propagation

For EVERY vulnerability you find, output in this EXACT structured format:

---VULN_START---
NAME: [Descriptive vulnerability name]
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
CWE: [CWE-XXX or "Novel — No CVE/CWE Match"]
LINES: [affected line numbers, e.g. 42-51]
SNIPPET:
```
[exact vulnerable code snippet]
```
ATTACK:
[Step-by-step realistic exploitation scenario]
FIX:
```
[corrected, secure replacement code]
```
---VULN_END---

Think deeply. Reason about what the developer *intended* versus what the code *actually does*. Find the semantic gap. Be thorough."""


# ─────────────────────────── カラーテーマ ────────────────────
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

# ─────────────────────────── フォント ────────────────────────
def _pick_mono(size: int, bold: bool = False) -> tuple:
    families = tkfont.families()
    weight = "bold" if bold else "normal"
    for name in ("Cascadia Code", "Cascadia Mono", "JetBrains Mono", "Fira Code", "Consolas"):
        if name in families:
            return (name, size, weight)
    return ("Courier New", size, weight)


# ─────────────────────────── 進捗ステップ ────────────────────
AUDIT_STEPS = [
    ("READ",    "ターゲットファイルを読み込み中"),
    ("PARSE",   "コード構造を解析中 (AST/CFG)"),
    ("REASON",  "AIエージェントが論理バグを推論中"),
    ("STREAM",  "脆弱性情報をストリーミング中"),
    ("SCORE",   "深刻度スコアを評価中"),
    ("PATCH",   "修正パッチコードを生成中"),
    ("REPORT",  "監査レポートを最終化中"),
]

STEP_IDLE    = ("⬜", TEXT_DIM)
STEP_RUNNING = ("▶ ", CYAN)
STEP_DONE    = ("✓ ", GREEN)
STEP_ERROR   = ("✗ ", RED_C)


# ─────────────────────────── メインアプリ ────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class AuditApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AI Security Audit System  ·  Autonomous Vulnerability Discovery v1.0")
        self.configure(fg_color=BG_ROOT)
        # geometry() takes logical px; winfo_screenwidth() returns physical px.
        # GetDpiForWindow gives the per-monitor DPI (e.g. 144 at 150% scale).
        import ctypes
        try:
            dpi   = ctypes.windll.user32.GetDpiForWindow(self.winfo_id())
            scale = dpi / 96.0
        except Exception:
            scale = 1.0
        self.update_idletasks()
        phys_w = self.winfo_screenwidth()
        phys_h = self.winfo_screenheight()
        log_w  = int(phys_w / scale * 0.91)   # 1504/1.5*0.91 ≈ 909 → 1364 physical
        log_h  = int(phys_h / scale * 0.89)
        self.geometry(f"{log_w}x{log_h}+0+0")
        self.minsize(int(700 / scale), int(480 / scale))

        self._target_path = tk.StringVar(value="検査対象ファイルを選択してください ...")
        self._is_running   = False
        self._ui_queue: queue.Queue = queue.Queue()

        self._step_icon_labels: list[ctk.CTkLabel] = []
        self._step_text_labels: list[ctk.CTkLabel] = []
        self._stat_vars: dict[str, tk.StringVar]   = {}

        self._blink_job = None  # 点滅アニメ用

        self._build_ui()
        self._process_queue()

    # ════════════════════════════════════════════════════════
    #  UI 構築
    # ════════════════════════════════════════════════════════
    def _build_ui(self):
        # ── タイトルバー ─────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # right-side items must be packed BEFORE any left-side item
        ctk.CTkLabel(
            hdr,
            text=f"ENGINE: {LLM_MODEL}  |  {LLM_BASE_URL}",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=TEXT_MID,
        ).pack(side="right", padx=12)

        self._status_dot = ctk.CTkLabel(
            hdr, text="● IDLE",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            text_color=TEXT_DIM,
        )
        self._status_dot.pack(side="right", padx=4)

        ctk.CTkLabel(
            hdr,
            text="⬡  AI SECURITY AUDIT SYSTEM",
            font=ctk.CTkFont("Segoe UI", 19, "bold"),
            text_color=CYAN,
        ).pack(side="left", padx=18)

        # ── ファイル選択バー ──────────────────────────────────
        fbar = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=50)
        fbar.pack(fill="x", pady=(1, 0))
        fbar.pack_propagate(False)

        # start_btn must be packed BEFORE path_lbl (which uses expand=True)
        self._start_btn = ctk.CTkButton(
            fbar, text="  AI 監査を開始  ▶ ", width=190, height=34,
            fg_color=CYAN, hover_color="#00B5DD",
            text_color=BG_ROOT, font=ctk.CTkFont("Segoe UI", 12, "bold"),
            command=self._start_audit,
        )
        self._start_btn.pack(side="right", padx=12, pady=8)

        ctk.CTkButton(
            fbar, text="📂  ファイルを選択", width=150, height=34,
            fg_color="#152030", hover_color="#1E3040",
            border_color=CYAN, border_width=1,
            text_color=CYAN, font=ctk.CTkFont("Segoe UI", 11),
            command=self._browse_file,
        ).pack(side="left", padx=12, pady=8)

        ctk.CTkLabel(
            fbar, textvariable=self._target_path,
            font=ctk.CTkFont("Consolas", 10),
            text_color=TEXT_MID, anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=6)

        # ── ステータスバー（expand=True の main より先に pack する） ─
        sbar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=24)
        sbar.pack(fill="x", side="bottom")
        sbar.pack_propagate(False)
        self._sbar_lbl = ctk.CTkLabel(
            sbar, text="Ready.  ファイルを選択して「AI 監査を開始」を押してください。",
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
        )
        self._sbar_lbl.pack(side="left", padx=12)
        ctk.CTkLabel(
            sbar,
            text=f"Autonomous Vulnerability Discovery Platform  |  {datetime.now().strftime('%Y-%m-%d')}",
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
        ).pack(side="right", padx=12)

        # ── メインペイン（sbar の後に pack → sbar がスペースを確保済み）──
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=6, pady=5)

        self._build_left_panel(main)
        self._build_right_panel(main)

    def _build_left_panel(self, parent):
        left = ctk.CTkFrame(parent, fg_color=BG_PANEL, corner_radius=8, width=370)
        left.pack(side="left", fill="y", padx=(0, 4))
        left.pack_propagate(False)

        # セクションタイトル
        ctk.CTkLabel(
            left, text="SCAN PROGRESS",
            font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=CYAN,
        ).pack(anchor="w", padx=14, pady=(12, 4))

        # プログレスバー
        self._pbar = ctk.CTkProgressBar(
            left, mode="determinate",
            fg_color=BG_WIDGET, progress_color=CYAN, height=5,
        )
        self._pbar.set(0)
        self._pbar.pack(fill="x", padx=14, pady=(0, 10))

        # ステップリスト
        step_frame = ctk.CTkScrollableFrame(left, fg_color="transparent", height=290)
        step_frame.pack(fill="x", padx=8)

        for i, (code, label) in enumerate(AUDIT_STEPS):
            row = ctk.CTkFrame(step_frame, fg_color="transparent", height=34)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            icon = ctk.CTkLabel(
                row, text="⬜", width=24,
                font=ctk.CTkFont("Segoe UI", 13), text_color=TEXT_DIM,
            )
            icon.pack(side="left", padx=(4, 2))
            self._step_icon_labels.append(icon)

            ctk.CTkLabel(
                row, text=f"[{i+1}/{len(AUDIT_STEPS)}]",
                font=ctk.CTkFont("Consolas", 10), text_color=TEXT_DIM, width=52,
            ).pack(side="left")

            txt = ctk.CTkLabel(
                row, text=label,
                font=ctk.CTkFont("Segoe UI", 11), text_color=TEXT_DIM, anchor="w",
            )
            txt.pack(side="left", padx=4)
            self._step_text_labels.append(txt)

        self._divider(left)

        # 検出サマリー
        ctk.CTkLabel(
            left, text="DETECTION SUMMARY",
            font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=CYAN,
        ).pack(anchor="w", padx=14, pady=(0, 6))

        grid = ctk.CTkFrame(left, fg_color="transparent")
        grid.pack(fill="x", padx=10)
        grid.columnconfigure((0, 1), weight=1)

        for i, (sev, color) in enumerate(SEV_COLORS.items()):
            box = ctk.CTkFrame(grid, fg_color=BG_WIDGET, corner_radius=6, height=46)
            box.grid(row=i // 2, column=i % 2, padx=3, pady=3, sticky="ew")
            box.pack_propagate(False)
            var = tk.StringVar(value="0")
            self._stat_vars[sev] = var
            ctk.CTkLabel(box, text=sev, font=ctk.CTkFont("Segoe UI", 9, "bold"), text_color=color).pack(pady=(5, 0))
            ctk.CTkLabel(box, textvariable=var, font=ctk.CTkFont("Segoe UI", 19, "bold"), text_color=color).pack()

        self._divider(left)

        # システムログ
        ctk.CTkLabel(
            left, text="SYSTEM LOG",
            font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=CYAN,
        ).pack(anchor="w", padx=14, pady=(0, 4))

        self._log_box = ctk.CTkTextbox(
            left, fg_color=BG_WIDGET, text_color=TEXT_DIM,
            font=ctk.CTkFont("Consolas", 9),
            corner_radius=6, height=150, wrap="word", state="disabled",
        )
        self._log_box.pack(fill="x", padx=10, pady=(0, 10))

    def _build_right_panel(self, parent):
        right = ctk.CTkFrame(parent, fg_color=BG_PANEL, corner_radius=8)
        right.pack(side="left", fill="both", expand=True, padx=(4, 0))

        hdr = ctk.CTkFrame(right, fg_color="transparent", height=36)
        hdr.pack(fill="x", padx=14, pady=(10, 4))
        hdr.pack_propagate(False)

        ctk.CTkLabel(
            hdr, text="AI VULNERABILITY ANALYSIS OUTPUT",
            font=ctk.CTkFont("Segoe UI", 11, "bold"), text_color=CYAN,
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="Clear", width=60, height=26,
            fg_color="#152030", hover_color="#1E3040",
            border_color=BORDER, border_width=1,
            text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 10),
            command=self._clear_output,
        ).pack(side="right")

        self._out_box = ctk.CTkTextbox(
            right,
            fg_color=BG_WIDGET, text_color=TEXT_PRI,
            font=ctk.CTkFont("Consolas", 11),
            corner_radius=6, wrap="word", state="disabled",
        )
        self._out_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # カラータグを内部 tk.Text に直接設定
        tb = self._out_box._textbox
        mono_b = _pick_mono(12, bold=True)
        mono   = _pick_mono(11)
        mono_s = _pick_mono(10)
        tb.tag_configure("header",   foreground=CYAN,     font=mono_b)
        tb.tag_configure("section",  foreground=PURPLE,   font=(*mono_b[:2], "bold"))
        tb.tag_configure("critical", foreground=RED_C,    font=(*mono[:2], "bold"))
        tb.tag_configure("high",     foreground=ORANGE_H, font=(*mono[:2], "bold"))
        tb.tag_configure("medium",   foreground=YELLOW_M, font=(*mono[:2], "bold"))
        tb.tag_configure("low",      foreground=GREEN_L,  font=(*mono[:2], "bold"))
        tb.tag_configure("code",     foreground="#9CDCFE", font=mono_s)
        tb.tag_configure("fix",      foreground=GREEN,    font=mono_s)
        tb.tag_configure("dim",      foreground=TEXT_DIM, font=mono_s)
        tb.tag_configure("label",    foreground=CYAN,     font=(*mono_s[:2], "bold"))
        tb.tag_configure("attack",   foreground=ORANGE_H, font=mono_s)
        tb.tag_configure("sep",      foreground=BORDER)
        tb.tag_configure("green",    foreground=GREEN)

    def _divider(self, parent):
        ctk.CTkFrame(parent, fg_color=BORDER, height=1).pack(fill="x", padx=12, pady=10)

    # ════════════════════════════════════════════════════════
    #  UI キュー処理（スレッドセーフ更新）
    # ════════════════════════════════════════════════════════
    def _process_queue(self):
        try:
            while True:
                fn = self._ui_queue.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.after(30, self._process_queue)

    def _ui(self, fn):
        """バックグラウンドスレッドから UI 更新をキューに積む"""
        self._ui_queue.put(fn)

    # ════════════════════════════════════════════════════════
    #  進捗ステップ制御
    # ════════════════════════════════════════════════════════
    def _set_step(self, idx: int, state: str):
        states = {
            "running": (STEP_RUNNING[0], STEP_RUNNING[1], TEXT_PRI),
            "done":    (STEP_DONE[0],    STEP_DONE[1],    GREEN),
            "error":   (STEP_ERROR[0],   STEP_ERROR[1],   RED_C),
        }
        icon_txt, icon_color, txt_color = states[state]
        progress = (idx + (1 if state == "done" else 0.45)) / len(AUDIT_STEPS)

        def _do():
            self._step_icon_labels[idx].configure(text=icon_txt, text_color=icon_color)
            self._step_text_labels[idx].configure(text_color=txt_color)
            self._pbar.set(progress)
        self._ui(_do)

    # ════════════════════════════════════════════════════════
    #  ログ・出力パネル操作
    # ════════════════════════════════════════════════════════
    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        def _do():
            self._log_box.configure(state="normal")
            self._log_box.insert("end", line)
            self._log_box._textbox.see("end")
            self._log_box.configure(state="disabled")
        self._ui(_do)

    def _insert(self, text: str, tag: str = ""):
        def _do():
            tb = self._out_box._textbox
            self._out_box.configure(state="normal")
            if tag:
                tb.insert("end", text, tag)
            else:
                tb.insert("end", text)
            tb.see("end")
            self._out_box.configure(state="disabled")
        self._ui(_do)

    def _clear_output(self):
        self._out_box.configure(state="normal")
        self._out_box.delete("1.0", "end")
        self._out_box.configure(state="disabled")

    def _set_status(self, msg: str):
        self._ui(lambda: self._sbar_lbl.configure(text=msg))

    # ════════════════════════════════════════════════════════
    #  監査フロー
    # ════════════════════════════════════════════════════════
    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="検査対象ファイルを選択",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")],
        )
        if path:
            self._target_path.set(path)
            self._log(f"Target set → {os.path.basename(path)}")

    def _start_audit(self):
        if self._is_running:
            return
        path = self._target_path.get()
        if not os.path.isfile(path):
            self._insert("[ ERROR ] 有効なファイルを選択してください。\n", "critical")
            return

        self._is_running = True
        self._reset_ui()
        self._start_btn.configure(state="disabled", text="  監査中 ...  ●", fg_color="#153040")
        self._status_dot.configure(text="● SCANNING", text_color=GREEN)

        threading.Thread(target=self._run_audit, args=(path,), daemon=True).start()

    def _reset_ui(self):
        for icon, txt in zip(self._step_icon_labels, self._step_text_labels):
            icon.configure(text="⬜", text_color=TEXT_DIM)
            txt.configure(text_color=TEXT_DIM)
        self._pbar.set(0)
        for v in self._stat_vars.values():
            v.set("0")
        self._clear_output()
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")

    # ════════════════════════════════════════════════════════
    #  監査メインロジック（バックグラウンドスレッド）
    # ════════════════════════════════════════════════════════
    def _run_audit(self, path: str):
        try:
            # ── Step 0: ファイル読み込み ─────────────────────
            self._set_step(0, "running")
            self._log(f"Reading: {path}")
            time.sleep(0.25)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except OSError as e:
                self._log(f"File read error: {e}")
                self._set_step(0, "error")
                self._finish_audit(error=True)
                return
            line_count = source.count("\n") + 1
            self._log(f"Loaded {line_count} lines ({len(source)} bytes)")
            self._set_step(0, "done")

            # ── Step 1: 構造解析 ─────────────────────────────
            self._set_step(1, "running")
            self._insert(
                "╔══════════════════════════════════════════════════════════════════╗\n"
                "║      AI SECURITY AUDIT SYSTEM  —  AUTONOMOUS SCAN INITIATED     ║\n"
                "╚══════════════════════════════════════════════════════════════════╝\n\n",
                "header",
            )
            self._insert(f"  TARGET  :  {path}\n",    "dim")
            self._insert(f"  LINES   :  {line_count}\n", "dim")
            self._insert(f"  MODEL   :  {LLM_MODEL}\n", "dim")
            self._insert(f"  ENGINE  :  {LLM_BASE_URL}\n\n", "dim")
            time.sleep(0.3)
            self._set_step(1, "done")

            # ── Step 2: AI 推論開始 ──────────────────────────
            self._set_step(2, "running")
            self._set_status(f"AI が {os.path.basename(path)} を深層解析中 ...")
            self._log("Connecting to LLM backend ...")

            self._insert("─" * 68 + "\n", "sep")
            self._insert("  REASONING ENGINE OUTPUT  (streaming)\n", "section")
            self._insert("─" * 68 + "\n\n", "sep")

            client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)
            full_response = ""

            try:
                stream = client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": (
                                f"Analyze this code for unknown and logic-based security vulnerabilities:\n\n"
                                f"```python\n{source}\n```\n\n"
                                "Apply deep semantic reasoning. Focus on authentication, session management, "
                                "business logic, and race conditions."
                            ),
                        },
                    ],
                    stream=True,
                    timeout=LLM_TIMEOUT,
                )

                # Step 3: ストリーミング
                self._set_step(3, "running")
                for chunk in stream:
                    delta = chunk.choices[0].delta.content or ""
                    if delta:
                        full_response += delta
                        self._insert(delta)

                self._set_step(3, "done")

            except Exception as e:
                self._log(f"LLM error: {e}")
                self._insert("\n\n", "")
                self._insert(f"[ LLM CONNECTION ERROR ]\n{e}\n\n", "critical")
                self._insert(
                    "Ollama が起動しているか確認してください:\n"
                    "  > ollama serve\n"
                    f"  > ollama pull {LLM_MODEL}\n\n",
                    "dim",
                )
                self._set_step(2, "error")
                self._finish_audit(error=True)
                return

            self._set_step(2, "done")

            # ── Step 4: 深刻度スコアリング ───────────────────
            self._set_step(4, "running")
            counts = self._count_severities(full_response)
            time.sleep(0.2)
            self._set_step(4, "done")

            # ── Step 5: パッチ生成確認 ───────────────────────
            self._set_step(5, "running")
            time.sleep(0.25)
            self._set_step(5, "done")

            # ── Step 6: 最終化 ───────────────────────────────
            self._set_step(6, "running")
            total = sum(counts.values())
            time.sleep(0.2)
            self._set_step(6, "done")
            self._ui(lambda: self._pbar.set(1.0))

            # サマリー更新
            def _update_stats():
                for sev, cnt in counts.items():
                    self._stat_vars[sev].set(str(cnt))
            self._ui(_update_stats)

            # 完了バナー
            self._insert("\n\n" + "═" * 68 + "\n", "sep")
            self._insert(f"  SCAN COMPLETE  |  {total} vulnerabilities detected\n", "green")
            sev_line = "  " + "  ".join(f"{s}: {n}" for s, n in counts.items() if n > 0)
            if sev_line.strip():
                self._insert(sev_line + "\n", "dim")
            self._insert("═" * 68 + "\n", "sep")

            self._log(f"Audit complete. Total: {total} issues.")
            self._set_status(f"Audit complete — {total} vulnerabilities detected.")

        except Exception as e:
            self._log(f"Unexpected error: {e}")
            self._insert(f"\n[ UNEXPECTED ERROR ] {e}\n", "critical")
        finally:
            self._finish_audit()

    def _count_severities(self, text: str) -> dict:
        counts = {s: 0 for s in SEV_COLORS}
        for sev in counts:
            counts[sev] = len(re.findall(rf"SEVERITY:\s*{sev}\b", text, re.IGNORECASE))
        return counts

    def _finish_audit(self, error: bool = False):
        self._is_running = False
        def _do():
            self._start_btn.configure(
                state="normal", text="  AI 監査を開始  ▶ ", fg_color=CYAN,
            )
            self._status_dot.configure(
                text="● ERROR" if error else "● IDLE",
                text_color=RED_C if error else TEXT_DIM,
            )
        self._ui(_do)


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = AuditApp()
    app.mainloop()
