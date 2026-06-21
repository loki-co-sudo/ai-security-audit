"""
gui/dialogs/settings_dialog.py — LLM接続設定ダイアログ
"""

from __future__ import annotations
import threading
import tkinter as tk
import customtkinter as ctk

from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, GREEN, RED_C,
    TEXT_PRI, TEXT_DIM, TEXT_MID, BORDER,
)
import core.config as config
from core.llm_client import LLMClient
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
        self.geometry("660x680")
        # minsize のみ設定（maxsize を固定すると最大化できなくなるため設定しない）。
        self.minsize(660, 680)

        # master=self を明示し、tkinter のデフォルトルートに依存させない
        # （スプラッシュ用ルート破棄で default root が None でも安全）。
        self._url_var     = tk.StringVar(self, value=config.get("llm_base_url"))
        self._key_var     = tk.StringVar(self, value=config.get("llm_api_key"))
        self._model_var   = tk.StringVar(self, value=config.get("llm_model"))
        self._timeout_var = tk.StringVar(self, value=str(config.get("llm_timeout")))
        self._search_var  = tk.StringVar(self)
        self._search_job  = None  # 検索の debounce 用 after ID
        # レポート言語（事前選択）。表示は「日本語/English」、保存値は ja/en。
        self._lang_var    = tk.StringVar(
            self, value="日本語" if config.get("report_lang", "ja") == "ja" else "English")

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

        body = ctk.CTkFrame(self, fg_color="transparent")
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

        # 検索ボックス + 件数表示
        search_row = ctk.CTkFrame(body, fg_color="transparent")
        search_row.pack(fill="x", pady=(10, 4))
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

        # スクロール可能なモデル一覧。クリックで MODEL 欄へ反映。
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

    def _available_models(self) -> list[str]:
        """厳選デフォルト + 取得済みキャッシュ（重複排除、デフォルトを先頭）。"""
        cached = config.get("available_models") or []
        extra  = [m for m in cached if m not in _PRESET_MODELS]
        return [*_PRESET_MODELS, *extra]

    def _on_search_changed(self, *_args) -> None:
        # キー入力ごとの再描画を避けるため debounce する。
        if self._search_job is not None:
            self.after_cancel(self._search_job)
        self._search_job = self.after(150, self._render_model_list)

    def _render_model_list(self) -> None:
        """検索条件でモデル一覧を絞り込み、スクロール一覧へ描画する。"""
        self._search_job = None
        for child in self._model_list.winfo_children():
            child.destroy()

        query   = self._search_var.get().strip().lower()
        models  = self._available_models()
        matched = [m for m in models if query in m.lower()] if query else models
        shown   = matched[:self._LIST_CAP]
        current = self._model_var.get().strip()

        for m in shown:
            selected = (m == current)
            ctk.CTkButton(
                self._model_list, text=m, height=26, anchor="w",
                fg_color="#152030" if selected else "transparent",
                hover_color="#152030",
                border_color=CYAN if selected else BORDER,
                border_width=1 if selected else 0,
                text_color=CYAN if selected else TEXT_PRI,
                font=ctk.CTkFont("Consolas", 10),
                command=lambda v=m: self._select_model(v),
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
        self._model_var.set(model)
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

    def _on_models_fetched(self, models: list[str]) -> None:
        if not models:
            self._on_models_done(False, "モデルが取得できませんでした")
            return
        # キャッシュへ保存し、一覧を再描画する。
        config.save({"available_models": models})
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
