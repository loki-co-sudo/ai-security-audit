"""
gui/dialogs/settings_dialog.py — LLM接続設定ダイアログ
"""

from __future__ import annotations
import threading
import tkinter as tk
import customtkinter as ctk

from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, GREEN, RED_C, AMBER, PURPLE,
    TEXT_PRI, TEXT_DIM, TEXT_MID, BORDER, EFFORT_PRESETS,
)
import core.config as config
from core.llm_client import LLMClient, cost_tier, sort_models
from gui.dialogs.base import RobustToplevel
from gui.dialogs.help_dialog import HelpDialog

# 厳選デフォルトのモデル候補（オフライン時／初期表示用のフォールバック）。
# 実際に使えるモデルは「↻ 取得」ボタンで接続先から動的に取得・更新でき、
# その結果が config.json にキャッシュされてここに加わる。MODEL 欄は自由入力なので
# ここに無いスラッグも直接入力可能。スラッグは接続先（特に OpenRouter）の表記に従う。
_PRESET_MODELS = [
    # ── ローカル（Ollama） ──
    "qwen3:30b-a3b",
    "llama4:scout",
    "qwen2.5-coder:14b",
    # ── Claude（OpenRouter 経由） ──
    "anthropic/claude-opus-4.8",
    "anthropic/claude-sonnet-4.6",
    "anthropic/claude-fable-5",
    # ── その他クラウド（OpenRouter 経由） ──
    "openai/gpt-5.5",
    "meta-llama/llama-4-scout",
    "qwen/qwen3-max",
    "qwen/qwen3-30b-a3b",
]

_PRESET_URLS = [
    ("Ollama (ローカル)",  "http://localhost:11434/v1"),
    ("OpenRouter",        "https://openrouter.ai/api/v1"),
    ("OpenAI",            "https://api.openai.com/v1"),
    ("LM Studio",         "http://localhost:1234/v1"),
]


class SettingsDialog(RobustToplevel):

    def __init__(self, master, llm: LLMClient, on_save: callable):
        super().__init__(master)
        self._llm     = llm
        self._on_save = on_save

        self.title("LLM 接続設定")
        self.configure(fg_color=BG_PANEL)
        self.geometry("660x820")
        # minsize のみ設定（maxsize を固定すると最大化できなくなるため設定しない）。
        self.minsize(660, 720)

        # master=self を明示し、tkinter のデフォルトルートに依存させない
        # （スプラッシュ用ルート破棄で default root が None でも安全）。
        self._url_var     = tk.StringVar(self, value=config.get("llm_base_url"))
        self._key_var     = tk.StringVar(self, value=config.get("llm_api_key"))
        self._model_var   = tk.StringVar(self, value=config.get("llm_model"))
        self._timeout_var = tk.StringVar(self, value=str(config.get("llm_timeout")))
        self._search_var  = tk.StringVar(self)
        self._search_job  = None  # 検索の debounce 用 after ID
        # モデル一覧（検索・絞り込み・クリック選択）はMODEL/FASTで共有する。
        # どちらの欄へ反映するかは _pick_target_var で切り替える（lokicode の
        # ModelPicker.tsx はフィールドごとに独立したピッカーだが、本ツールはダイアログの
        # 縦幅を抑えるため一覧を1つに共通化し、適用先セレクタで切り替える設計にしている）。
        self._pick_target_var = tk.StringVar(self, value="MODEL")
        self._cost_filter: set[str] = set()      # 選択中のコスト階級フィルタ（空=絞り込みなし）
        self._provider_filter: set[str] = set()  # 選択中のプロバイダフィルタ（空=絞り込みなし）
        # 並び順（表示は「ID順」「知能指数順」、内部キーへは _sort_key() で変換）。
        # lokicodeには無い独自追加。
        self._sort_display_var = tk.StringVar(self, value="ID順")
        # レポート言語（事前選択）。表示は「日本語/English」、保存値は ja/en。
        self._lang_var    = tk.StringVar(
            self, value="日本語" if config.get("report_lang", "ja") == "ja" else "English")
        # FAST（廉価）モデルとその任意接続。空=ルーティング無効（STRONG共用）。
        self._fast_model_var = tk.StringVar(self, value=config.get("llm_fast_model", ""))
        self._fast_url_var   = tk.StringVar(self, value=config.get("llm_fast_base_url", ""))
        self._fast_key_var   = tk.StringVar(self, value=config.get("llm_fast_api_key", ""))
        # 推論エフォート（速度/バランス/品質）。表示ラベルは EFFORT_PRESETS の label。
        _eff = config.get("effort", "balanced")
        self._effort_var = tk.StringVar(
            self, value=EFFORT_PRESETS.get(_eff, EFFORT_PRESETS["balanced"])["label"])

        # withdraw を伴わないので、メインウィンドウ同様その場で構築して問題ない。
        self._build()
        self._apply_dark_titlebar()
        self.after(80, lambda: self._bring_to_front(grab=True))

    def _open_help(self) -> None:
        # ヘルプを開いている間は設定ダイアログのモーダルを解除し、閉じたら復帰する。
        try:
            self.grab_release()
        except tk.TclError:
            pass
        HelpDialog(self, on_close=self._after_help_close)

    def _after_help_close(self) -> None:
        if self.winfo_exists():
            try:
                self.grab_set()
            except tk.TclError:
                pass

    def _build(self) -> None:
        # タイトル
        hdr = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="⚙  LLM 接続設定",
            font=ctk.CTkFont("Segoe UI", 14, "bold"), text_color=CYAN,
        ).pack(side="left", padx=16, pady=12)

        # ヘルプ呼び出しボタン（AI/設定が初めての人向けの案内を開く）
        ctk.CTkButton(
            hdr, text="❓ ヘルプ", width=84, height=30,
            fg_color=BG_PANEL, hover_color="#152030",
            border_color=CYAN, border_width=1,
            text_color=CYAN, font=ctk.CTkFont("Segoe UI", 11),
            command=self._open_help,
        ).pack(side="right", padx=16, pady=10)

        # モデルピッカー追加でコンテンツがダイアログ固定高（660x820）を超えるようになった
        # ため、body自体をスクロール可能にする（さもないとSCOPE欄より下＝モデルピッカーの
        # 検索・フィルタ・一覧が画面外に隠れて操作不能になる。実機スクリーンショットで発覚）。
        body = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=TEXT_DIM,
        )
        body.pack(fill="both", expand=True, padx=20, pady=12)

        # プリセットボタン
        ctk.CTkLabel(body, text="PRESET", font=ctk.CTkFont("Segoe UI", 10, "bold"),
                     text_color=TEXT_DIM).pack(anchor="w", pady=(0, 4))
        preset_row = ctk.CTkFrame(body, fg_color="transparent")
        preset_row.pack(fill="x", pady=(0, 14))
        for label, url in _PRESET_URLS:
            ctk.CTkButton(
                preset_row, text=label, height=28,
                fg_color=BG_WIDGET, hover_color="#152030",
                border_color=BORDER, border_width=1,
                text_color=TEXT_MID, font=ctk.CTkFont("Segoe UI", 10),
                command=lambda u=url: self._url_var.set(u),
            ).pack(side="left", padx=(0, 6))

        # フォームフィールド（BASE URL / API KEY はテキスト入力）
        self._add_entry(body, "BASE URL", self._url_var, False, "http://localhost:11434/v1")
        self._add_entry(body, "API KEY",  self._key_var, True,  "ollama  または  sk-...")

        # MODEL は選択中モデルを表示・編集する欄（手入力も可）＋「↻ 取得」ボタン。
        model_row = ctk.CTkFrame(body, fg_color="transparent")
        model_row.pack(fill="x", pady=5)
        ctk.CTkLabel(model_row, text="MODEL", width=80,
                     font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                     anchor="w").pack(side="left")
        ctk.CTkEntry(
            model_row, textvariable=self._model_var,
            placeholder_text="qwen3:30b-a3b",
            font=ctk.CTkFont("Consolas", 11),
            fg_color=BG_INPUT, border_color=BORDER, border_width=1,
            text_color=TEXT_PRI, height=32,
        ).pack(side="left", fill="x", expand=True)
        self._fetch_btn = ctk.CTkButton(
            model_row, text="↻ 取得", width=76, height=32,
            fg_color=BG_WIDGET, hover_color="#152030",
            border_color=CYAN, border_width=1,
            text_color=CYAN, font=ctk.CTkFont("Segoe UI", 10),
            command=self._start_fetch_models,
        )
        self._fetch_btn.pack(side="left", padx=(6, 0))

        # TIMEOUT
        self._add_entry(body, "TIMEOUT", self._timeout_var, False, "180")

        # レポート言語（事前選択）。スキャン時のAI出力言語とレポート表記に反映される。
        lang_row = ctk.CTkFrame(body, fg_color="transparent")
        lang_row.pack(fill="x", pady=5)
        ctk.CTkLabel(lang_row, text="REPORT", width=80,
                     font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                     anchor="w").pack(side="left")
        ctk.CTkSegmentedButton(
            lang_row, values=["日本語", "English"], variable=self._lang_var,
            font=ctk.CTkFont("Segoe UI", 11),
            fg_color=BG_INPUT, selected_color=CYAN, selected_hover_color="#00B5DD",
            unselected_color=BG_WIDGET, unselected_hover_color="#152030",
            text_color=TEXT_PRI, height=30,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(lang_row, text="レポートの生成言語（AI出力もこの言語になります）",
                     font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM,
                     anchor="w").pack(side="left")

        # ── 推論エフォート（速度 / バランス / 品質） ──────────
        eff_row = ctk.CTkFrame(body, fg_color="transparent")
        eff_row.pack(fill="x", pady=5)
        ctk.CTkLabel(eff_row, text="EFFORT", width=80,
                     font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                     anchor="w").pack(side="left")
        ctk.CTkSegmentedButton(
            eff_row, values=[EFFORT_PRESETS[k]["label"] for k in ("speed", "balanced", "quality")],
            variable=self._effort_var, command=lambda _v: self._update_effort_hint(),
            font=ctk.CTkFont("Segoe UI", 11),
            fg_color=BG_INPUT, selected_color=PURPLE, selected_hover_color="#A96FE0",
            unselected_color=BG_WIDGET, unselected_hover_color="#152030",
            text_color=TEXT_PRI, height=30,
        ).pack(side="left", padx=(0, 8))
        self._effort_hint = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont("Segoe UI", 9),
            text_color=TEXT_DIM, anchor="w", justify="left")
        self._effort_hint.pack(fill="x", padx=(84, 0))
        self._update_effort_hint()

        # ── FAST（廉価）モデル — コスト最適化・任意 ────────────
        ctk.CTkLabel(
            body, text="⚡ FAST モデル（廉価・機械的処理用 — 任意）",
            font=ctk.CTkFont("Segoe UI", 10, "bold"), text_color=AMBER,
        ).pack(anchor="w", pady=(10, 0))
        ctk.CTkLabel(
            body,
            text="設定すると、検出プローブ生成など量の出る処理を安価なモデルに振り分け、"
                 "最終推論のみ主モデルを使います（コスト削減）。空欄＝主モデルを共用。",
            font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM,
            anchor="w", justify="left", wraplength=580,
        ).pack(anchor="w", pady=(0, 2))
        self._add_entry(body, "FAST", self._fast_model_var, False,
                        "例: mistralai/mistral-small-24b-instruct-2501（空欄=無効）")
        self._add_entry(body, "FAST URL", self._fast_url_var, False,
                        "任意: 別エンドポイント時のみ（空欄=主モデルと同じ接続）")
        self._add_entry(body, "FAST KEY", self._fast_key_var, True,
                        "任意: FAST URL を別にした場合のAPIキー")

        # ── SCOPE（バグバウンティ対応・対象範囲ガード — 任意） ─────
        # BOUNTY_ROADMAP.md Phase A。advisorレビュー指摘（2026-08-16）:
        # allowed_targets が空だと無効（既存インストールとの後方互換）のため、
        # 初学者が設定を忘れて無防備なまま使ってしまう false sense of security
        # を防ぐ常時警告をここに表示する。
        ctk.CTkLabel(
            body, text="🎯 SCOPE（対象範囲・バグバウンティ対応 — 任意）",
            font=ctk.CTkFont("Segoe UI", 10, "bold"), text_color=AMBER,
        ).pack(anchor="w", pady=(10, 0))
        self._scope_warn = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont("Segoe UI", 9), text_color=AMBER,
            anchor="w", justify="left", wraplength=580,
        )
        self._scope_warn.pack(anchor="w", pady=(0, 2))

        scope_row = ctk.CTkFrame(body, fg_color="transparent")
        scope_row.pack(fill="x", pady=5)
        ctk.CTkLabel(scope_row, text="ALLOWED", width=80,
                     font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                     anchor="w").pack(side="left", anchor="n")
        self._scope_text = ctk.CTkTextbox(
            scope_row, height=70,
            font=ctk.CTkFont("Consolas", 10),
            fg_color=BG_INPUT, border_color=BORDER, border_width=1,
            text_color=TEXT_PRI,
        )
        self._scope_text.insert("1.0", "\n".join(config.get("allowed_targets") or []))
        self._scope_text.pack(side="left", fill="x", expand=True)
        self._scope_text.bind("<KeyRelease>", lambda _e: self._update_scope_hint())

        mode_row = ctk.CTkFrame(body, fg_color="transparent")
        mode_row.pack(fill="x", pady=5)
        ctk.CTkLabel(mode_row, text="MODE", width=80,
                     font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                     anchor="w").pack(side="left")
        self._scope_mode_var = tk.StringVar(self, value=config.get("scope_mode", "warn"))
        ctk.CTkSegmentedButton(
            mode_row, values=["warn", "block"], variable=self._scope_mode_var,
            font=ctk.CTkFont("Segoe UI", 11),
            fg_color=BG_INPUT, selected_color=AMBER, selected_hover_color="#CC8400",
            unselected_color=BG_WIDGET, unselected_hover_color="#152030",
            text_color=TEXT_PRI, height=30,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(
            mode_row,
            text="1行1ルール（例: example.com / *.example.com / 203.0.113.0/24）。"
                 "範囲外を warn=警告のみ続行 / block=実行ブロック。空欄=制限なし（既存動作）",
            font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM,
            anchor="w", justify="left", wraplength=440,
        ).pack(side="left")
        self._update_scope_hint()

        # ── TLS（WEB FUZZ証明書検証 — 任意・P0.2） ─────────
        ctk.CTkLabel(
            body, text="🔒 TLS（WEB FUZZ証明書検証 — 任意）",
            font=ctk.CTkFont("Segoe UI", 10, "bold"), text_color=AMBER,
        ).pack(anchor="w", pady=(10, 0))
        ctk.CTkLabel(
            body, text="既定は無効（自己署名証明書のラボ環境が多いため・既存動作を維持）。"
                       "実サービスを対象にする案件では有効化を推奨します。",
            font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM,
            anchor="w", justify="left", wraplength=580,
        ).pack(anchor="w", pady=(0, 2))
        tls_row = ctk.CTkFrame(body, fg_color="transparent")
        tls_row.pack(fill="x", pady=5)
        self._tls_verify_var = tk.BooleanVar(self, value=bool(config.get("tls_verify", False)))
        ctk.CTkCheckBox(
            tls_row, text="証明書を検証する(tls_verify)", variable=self._tls_verify_var,
            font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_PRI,
            fg_color=AMBER, hover_color="#CC8400", checkbox_width=16, checkbox_height=16,
        ).pack(side="left", padx=(0, 12))
        self._tls_ca_var = tk.StringVar(self, value=config.get("tls_ca_bundle", "") or "")
        ctk.CTkEntry(
            tls_row, textvariable=self._tls_ca_var,
            placeholder_text="独自CA証明書のパス(任意・空欄=標準ストア)",
            font=ctk.CTkFont("Consolas", 10),
            fg_color=BG_INPUT, border_color=BORDER, border_width=1,
            text_color=TEXT_PRI, height=28,
        ).pack(side="left", fill="x", expand=True)

        # モデル要件ゲート（ヒューリスティック警告・ブロックしない） — AGENT_ARCHITECTURE.md §5.2
        self._readiness_label = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont("Segoe UI", 9),
            text_color=AMBER, anchor="w", justify="left", wraplength=580,
        )
        self._readiness_label.pack(anchor="w", pady=(2, 0))
        self._model_var.trace_add("write", lambda *_a: self._update_readiness_hint())
        self._fast_model_var.trace_add("write", lambda *_a: self._update_readiness_hint())
        self._update_readiness_hint()

        # モデル別コスト×精度台帳の助言（記録の活用・自動切り替えはしない） — AGENT_ARCHITECTURE.md §5.4
        self._ledger_hint_label = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont("Segoe UI", 9),
            text_color=CYAN, anchor="w", justify="left", wraplength=580,
        )
        self._ledger_hint_label.pack(anchor="w", pady=(2, 0))
        self._model_var.trace_add("write", lambda *_a: self._update_ledger_hint())
        self._fast_model_var.trace_add("write", lambda *_a: self._update_ledger_hint())
        self._update_ledger_hint()

        # モデルピッカー: 適用先セレクタ（MODEL/FASTのどちらへクリック反映するか）
        pick_row = ctk.CTkFrame(body, fg_color="transparent")
        pick_row.pack(fill="x", pady=(10, 4))
        ctk.CTkLabel(pick_row, text="一覧から選択 →", font=ctk.CTkFont("Segoe UI", 9),
                     text_color=TEXT_DIM).pack(side="left", padx=(0, 6))
        ctk.CTkSegmentedButton(
            pick_row, values=["MODEL", "FAST"], variable=self._pick_target_var,
            command=lambda _v: self._render_model_list(),
            font=ctk.CTkFont("Segoe UI", 10),
            fg_color=BG_INPUT, selected_color=CYAN, selected_hover_color="#00B5DD",
            unselected_color=BG_WIDGET, unselected_hover_color="#152030",
            text_color=TEXT_PRI, height=26,
        ).pack(side="left")

        # 検索ボックス + 件数表示
        search_row = ctk.CTkFrame(body, fg_color="transparent")
        search_row.pack(fill="x", pady=(6, 4))
        ctk.CTkEntry(
            search_row, textvariable=self._search_var,
            placeholder_text="🔍 モデル名で検索（例: claude, gpt-5, qwen3 ...）",
            font=ctk.CTkFont("Consolas", 11),
            fg_color=BG_INPUT, border_color=BORDER, border_width=1,
            text_color=TEXT_PRI, height=30,
        ).pack(side="left", fill="x", expand=True)
        self._count_label = ctk.CTkLabel(
            search_row, text="", width=120,
            font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM, anchor="e",
        )
        self._count_label.pack(side="left", padx=(8, 0))
        self._search_var.trace_add("write", self._on_search_changed)

        # コスト階級フィルタ（複数選択トグル。lokicode ModelPicker.tsx のコストチップ相当）
        # ＋ 並び順トグル（ID順/知能指数順。lokicodeには無い本ツール独自の追加）。
        cost_row = ctk.CTkFrame(body, fg_color="transparent")
        cost_row.pack(fill="x", pady=(0, 4))
        self._cost_chip_btns: dict[str, ctk.CTkButton] = {}
        for tier in ("無料", "低", "中", "高"):
            btn = ctk.CTkButton(
                cost_row, text=f"コスト {tier}", width=76, height=22,
                fg_color="transparent", hover_color="#152030",
                border_color=BORDER, border_width=1,
                text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 9),
                command=lambda t=tier: self._toggle_cost_filter(t),
            )
            btn.pack(side="left", padx=(0, 4))
            self._cost_chip_btns[tier] = btn

        ctk.CTkLabel(cost_row, text="  並び順", font=ctk.CTkFont("Segoe UI", 9),
                     text_color=TEXT_DIM).pack(side="left", padx=(8, 4))
        ctk.CTkSegmentedButton(
            cost_row, values=["ID順", "知能指数順"], variable=self._sort_display_var,
            command=lambda _v: self._render_model_list(),
            font=ctk.CTkFont("Segoe UI", 9),
            fg_color=BG_INPUT, selected_color=PURPLE, selected_hover_color="#A96FE0",
            unselected_color=BG_WIDGET, unselected_hover_color="#152030",
            text_color=TEXT_PRI, height=22,
        ).pack(side="left")

        # プロバイダフィルタ（取得済み一覧から動的に集計。多い順）
        self._provider_row = ctk.CTkFrame(body, fg_color="transparent")
        self._provider_row.pack(fill="x", pady=(0, 4))
        self._provider_chip_btns: dict[str, ctk.CTkButton] = {}
        self._render_provider_chips()

        # スクロール可能なモデル一覧。クリックで適用先（MODEL/FAST）欄へ反映。
        self._model_list = ctk.CTkScrollableFrame(
            body, fg_color=BG_INPUT, border_color=BORDER, border_width=1,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=TEXT_DIM,
        )
        self._model_list.pack(fill="both", expand=True, pady=(0, 6))
        self._render_model_list()

        # 接続テスト結果ラベル
        self._test_result = ctk.CTkLabel(
            body, text="",
            font=ctk.CTkFont("Consolas", 10), text_color=TEXT_DIM, anchor="w",
        )
        self._test_result.pack(fill="x", pady=(2, 0))

        # ボタン行
        btn_row = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=56)
        btn_row.pack(fill="x", side="bottom")
        btn_row.pack_propagate(False)

        ctk.CTkButton(
            btn_row, text="キャンセル", width=110, height=36,
            fg_color="#152030", hover_color="#1E3040",
            border_color=BORDER, border_width=1,
            text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 11),
            command=self.destroy,
        ).pack(side="right", padx=12, pady=10)

        ctk.CTkButton(
            btn_row, text="保存", width=110, height=36,
            fg_color=CYAN, hover_color="#00B5DD",
            text_color=BG_PANEL, font=ctk.CTkFont("Segoe UI", 12, "bold"),
            command=self._save,
        ).pack(side="right", padx=(0, 6), pady=10)

        self._test_btn = ctk.CTkButton(
            btn_row, text="接続テスト", width=120, height=36,
            fg_color="#0A200A", hover_color="#0F2A0F",
            border_color=GREEN, border_width=1,
            text_color=GREEN, font=ctk.CTkFont("Segoe UI", 11),
            command=self._start_test,
        )
        self._test_btn.pack(side="left", padx=12, pady=10)

    def _update_scope_hint(self) -> None:
        """空のままだと全対象が許可扱いになることを常時警告する（false sense of security対策）。"""
        text = self._scope_text.get("1.0", "end").strip()
        if not text:
            self._scope_warn.configure(
                text="⚠ 空のままだと全対象が許可扱いになります（既存動作との後方互換のため）。"
                     "バグバウンティ利用では対象範囲の設定を強く推奨します。"
            )
        else:
            self._scope_warn.configure(text="")

    def _update_readiness_hint(self) -> None:
        """STRONG/FAST モデル構成のヒューリスティック警告を表示する（非ブロッキング）。"""
        from core.model_router import assess_readiness
        warnings = assess_readiness(self._model_var.get().strip(), self._fast_model_var.get().strip())
        self._readiness_label.configure(text=("⚠ " + " / ".join(warnings)) if warnings else "")

    def _update_ledger_hint(self) -> None:
        """テレメトリ実績に基づくモデル提案を表示する（参考情報のみ・設定は変更しない）。"""
        from core.model_router import suggest_efficient_model
        strong = self._model_var.get().strip()
        fast = self._fast_model_var.get().strip()
        hints: list[str] = []
        for mode in ("CODE AUDIT", "ATTACK MODE", "WEB FUZZ", "DEFENSE MODE"):
            for model_id in (strong, fast):
                if not model_id:
                    continue
                hint = suggest_efficient_model(mode, model_id)
                if hint:
                    hints.append(hint)
                    break  # モードごとに1件まで（表示が埋まりすぎないように）
        self._ledger_hint_label.configure(
            text=("\n".join(f"💡 {h}" for h in hints)) if hints else ""
        )

    def _effort_key(self) -> str:
        """表示ラベル（速度/バランス/品質）から保存キー（speed/balanced/quality）へ変換。"""
        for k, v in EFFORT_PRESETS.items():
            if v["label"] == self._effort_var.get():
                return k
        return "balanced"

    def _update_effort_hint(self) -> None:
        preset = EFFORT_PRESETS[self._effort_key()]
        self._effort_hint.configure(text=preset["desc"])

    def _add_entry(self, parent, label, var, secret, placeholder) -> None:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=5)
        ctk.CTkLabel(row, text=label, width=80,
                     font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                     anchor="w").pack(side="left")
        ctk.CTkEntry(
            row, textvariable=var,
            placeholder_text=placeholder,
            show="*" if secret else "",
            font=ctk.CTkFont("Consolas", 11),
            fg_color=BG_INPUT, border_color=BORDER, border_width=1,
            text_color=TEXT_PRI, height=32,
        ).pack(side="left", fill="x", expand=True)

    # ── モデル一覧の自動管理 ───────────────────────────────
    _LIST_CAP = 200  # 一度に描画する最大件数（多すぎる一覧の描画負荷を抑える）

    def _sort_key(self) -> str:
        """表示ラベル（ID順/知能指数順）から sort_models() の by キーへ変換する。"""
        return "intelligence" if self._sort_display_var.get() == "知能指数順" else "id"

    @staticmethod
    def _provider_of(model_id: str) -> str:
        """モデルslugの '/' より前の部分をプロバイダとみなす（lokicode と同じ規則）。"""
        i = model_id.find("/")
        return model_id if i == -1 else model_id[:i]

    @staticmethod
    def _available_models() -> list[dict]:
        """厳選デフォルト + 取得済みキャッシュ（重複排除、キャッシュのメタデータを優先）。

        キャッシュは list[dict]（id/price_out/context/intelligence/coding）が現行形式だが、
        旧バージョンの list[str] キャッシュが残っている環境向けに文字列要素も正規化して
        受け付ける（後方互換）。同一idがpresetとキャッシュ両方にあれば、価格等が乗っている
        キャッシュ側を残す。self を使わない純粋関数のため staticmethod にして
        run_selftest.py からインスタンス化なしでテストできるようにしてある。
        """
        def _norm(m) -> dict:
            if isinstance(m, str):
                return {"id": m, "price_out": None, "context": None,
                        "intelligence": None, "coding": None}
            return {
                "id": m.get("id", ""), "price_out": m.get("price_out"), "context": m.get("context"),
                "intelligence": m.get("intelligence"), "coding": m.get("coding"),
            }

        cached = [_norm(m) for m in (config.get("available_models") or [])]
        cached = [m for m in cached if m["id"]]
        cached_ids = {m["id"] for m in cached}
        presets = [_norm(m) for m in _PRESET_MODELS if m not in cached_ids]
        return [*presets, *cached]

    def _on_search_changed(self, *_args) -> None:
        # キー入力ごとの再描画を避けるため debounce する。
        if self._search_job is not None:
            self.after_cancel(self._search_job)
        self._search_job = self.after(150, self._render_model_list)

    def _toggle_cost_filter(self, tier: str) -> None:
        if tier in self._cost_filter:
            self._cost_filter.discard(tier)
        else:
            self._cost_filter.add(tier)
        self._render_model_list()

    def _toggle_provider_filter(self, provider: str) -> None:
        if provider in self._provider_filter:
            self._provider_filter.discard(provider)
        else:
            self._provider_filter.add(provider)
        self._render_model_list()

    def _render_provider_chips(self) -> None:
        """取得済み一覧からプロバイダを多い順に集計し、フィルタチップとして描画する。"""
        for child in self._provider_row.winfo_children():
            child.destroy()
        self._provider_chip_btns = {}

        counts: dict[str, int] = {}
        for m in self._available_models():
            p = self._provider_of(m["id"])
            counts[p] = counts.get(p, 0) + 1
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]

        for provider, n in top:
            on = provider in self._provider_filter
            btn = ctk.CTkButton(
                self._provider_row, text=f"{provider} {n}", height=22,
                fg_color="#152030" if on else "transparent",
                hover_color="#152030",
                border_color=CYAN if on else BORDER, border_width=1,
                text_color=CYAN if on else TEXT_DIM, font=ctk.CTkFont("Segoe UI", 9),
                command=lambda p=provider: self._toggle_provider_filter(p),
            )
            btn.pack(side="left", padx=(0, 4))
            self._provider_chip_btns[provider] = btn

    def _render_model_list(self) -> None:
        """検索・コスト階級・プロバイダの各条件でモデル一覧を絞り込み描画する。"""
        self._search_job = None
        for child in self._model_list.winfo_children():
            child.destroy()

        # フィルタチップの選択状態（色）を更新する。
        for tier, btn in self._cost_chip_btns.items():
            on = tier in self._cost_filter
            btn.configure(
                fg_color="#152030" if on else "transparent",
                border_color=CYAN if on else BORDER,
                text_color=CYAN if on else TEXT_DIM,
            )
        for provider, btn in self._provider_chip_btns.items():
            on = provider in self._provider_filter
            btn.configure(
                fg_color="#152030" if on else "transparent",
                border_color=CYAN if on else BORDER,
                text_color=CYAN if on else TEXT_DIM,
            )

        query  = self._search_var.get().strip().lower()
        models = self._available_models()

        def _match(m: dict) -> bool:
            if query and query not in m["id"].lower():
                return False
            if self._cost_filter and cost_tier(m["price_out"]) not in self._cost_filter:
                return False
            if self._provider_filter and self._provider_of(m["id"]) not in self._provider_filter:
                return False
            return True

        matched = sort_models([m for m in models if _match(m)], by=self._sort_key())
        shown   = matched[:self._LIST_CAP]

        target_var = self._model_var if self._pick_target_var.get() == "MODEL" else self._fast_model_var
        current = target_var.get().strip()

        for m in shown:
            selected = (m["id"] == current)
            tier = cost_tier(m["price_out"])
            meta_parts = [f"コスト {tier}"]
            if m["price_out"] is not None and m["price_out"] > 0:
                meta_parts.append(f"${m['price_out']:.2f}/M")
            if m["context"]:
                ctx_k = m["context"] // 1000
                meta_parts.append(f"ctx {ctx_k}K" if ctx_k else f"ctx {m['context']}")
            if m["intelligence"] is not None:
                meta_parts.append(f"知能 {m['intelligence']:.0f}")
            label = f"{m['id']}   [{' / '.join(meta_parts)}]"
            ctk.CTkButton(
                self._model_list, text=label, height=26, anchor="w",
                fg_color="#152030" if selected else "transparent",
                hover_color="#152030",
                border_color=CYAN if selected else BORDER,
                border_width=1 if selected else 0,
                text_color=CYAN if selected else TEXT_PRI,
                font=ctk.CTkFont("Consolas", 10),
                command=lambda v=m["id"]: self._select_model(v),
            ).pack(fill="x", padx=4, pady=1)

        total = len(matched)
        if total == 0:
            ctk.CTkLabel(self._model_list, text="一致するモデルがありません",
                         font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM).pack(pady=8)
            self._count_label.configure(text="0 件")
        elif total > len(shown):
            self._count_label.configure(text=f"{len(shown)} / {total} 件")
        else:
            self._count_label.configure(text=f"{total} 件")

    def _select_model(self, model: str) -> None:
        """一覧クリック時、適用先セレクタ（MODEL/FAST）に応じて反映する。"""
        target_var = self._model_var if self._pick_target_var.get() == "MODEL" else self._fast_model_var
        target_var.set(model)
        self._render_model_list()  # 選択状態のハイライトを更新

    def _start_fetch_models(self) -> None:
        self._fetch_btn.configure(state="disabled", text="取得中…")
        self._test_result.configure(text="モデル一覧を取得中 ...", text_color=TEXT_DIM)
        threading.Thread(target=self._do_fetch_models, daemon=True).start()

    def _do_fetch_models(self) -> None:
        try:
            models = LLMClient.fetch_models(
                base_url=self._url_var.get().strip(),
                api_key=self._key_var.get().strip() or "ollama",
            )
            self.after(0, lambda: self._on_models_fetched(models))
        except Exception as e:
            msg = str(e)[:100]
            self.after(0, lambda: self._on_models_done(False, f"取得失敗: {msg}"))

    def _on_models_fetched(self, models: list[dict]) -> None:
        if not models:
            self._on_models_done(False, "モデルが取得できませんでした")
            return
        # キャッシュへ保存し、一覧・プロバイダチップを再描画する。
        config.save({"available_models": models})
        self._render_provider_chips()
        self._render_model_list()
        self._on_models_done(True, f"{len(models)} 個のモデルを取得しました")

    def _on_models_done(self, ok: bool, msg: str) -> None:
        self._fetch_btn.configure(state="normal", text="↻ 取得")
        self._test_result.configure(
            text=f"{'✓ ' if ok else '✗ '}{msg}",
            text_color=GREEN if ok else RED_C,
        )

    def _start_test(self) -> None:
        self._test_btn.configure(state="disabled", text="Testing ...")
        self._test_result.configure(text="接続中 ...", text_color=TEXT_DIM)
        threading.Thread(target=self._do_test, daemon=True).start()

    def _do_test(self) -> None:
        try:
            from openai import OpenAI  # noqa: PLC0415
            client = OpenAI(
                base_url=self._url_var.get().strip(),
                api_key=self._key_var.get().strip() or "ollama",
            )
            resp = client.chat.completions.create(
                model=self._model_var.get().strip(),
                messages=[{"role": "user", "content": "reply with just: OK"}],
                max_tokens=16,
                timeout=15,
            )
            reply = (resp.choices[0].message.content or "").strip()[:40]
            self.after(0, lambda: self._show_result(True, f"接続成功 — モデル応答: {reply}"))
        except Exception as e:
            self.after(0, lambda: self._show_result(False, str(e)[:100]))

    def _show_result(self, ok: bool, msg: str) -> None:
        self._test_btn.configure(state="normal", text="接続テスト")
        self._test_result.configure(
            text=f"{'✓ ' if ok else '✗ '}{msg}",
            text_color=GREEN if ok else RED_C,
        )

    def _save(self) -> None:
        try:
            timeout = int(self._timeout_var.get())
        except ValueError:
            timeout = 180

        data = {
            "llm_base_url": self._url_var.get().strip(),
            "llm_api_key":  self._key_var.get().strip() or "ollama",
            "llm_model":    self._model_var.get().strip(),
            "llm_timeout":  timeout,
            "report_lang":  "ja" if self._lang_var.get() == "日本語" else "en",
            "llm_fast_model":    self._fast_model_var.get().strip(),
            "llm_fast_base_url": self._fast_url_var.get().strip(),
            "llm_fast_api_key":  self._fast_key_var.get().strip(),
            "effort":            self._effort_key(),
            "allowed_targets": [
                line.strip() for line in self._scope_text.get("1.0", "end").split("\n")
                if line.strip()
            ],
            "scope_mode": self._scope_mode_var.get(),
            "tls_verify": bool(self._tls_verify_var.get()),
            "tls_ca_bundle": self._tls_ca_var.get().strip(),
        }
        config.save(data)
        self._llm.update(
            base_url=data["llm_base_url"],
            api_key=data["llm_api_key"],
            model=data["llm_model"],
            timeout=data["llm_timeout"],
        )
        self._on_save(data["llm_model"])
        self.destroy()
