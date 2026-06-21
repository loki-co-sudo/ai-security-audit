"""
gui/dialogs/settings_dialog.py — LLM接続設定ダイアログ
"""

from __future__ import annotations
import threading
import tkinter as tk
import customtkinter as ctk

from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, GREEN, RED_C, ORANGE_H,
    TEXT_PRI, TEXT_DIM, TEXT_MID, BORDER,
)
import core.config as config
from core.llm_client import LLMClient

# モデル候補。MODEL欄は自由入力なので、ここに無いモデル（将来の Claude Fable 等）も
# スラッグを直接入力すれば利用できる。OpenRouter経由の Claude/Fable も含む。
_PRESET_MODELS = [
    # Ollama ローカル
    "qwen2.5-coder:14b",
    "llama3.1:8b",
    "deepseek-coder-v2:16b",
    # Claude（OpenRouter経由）
    "anthropic/claude-opus-4.1",
    "anthropic/claude-sonnet-4.5",
    "anthropic/claude-haiku-4.5",
    "anthropic/claude-fable-5",   # 公開後に利用可（スラッグは登録済み）
    # その他クラウド（OpenAI / OpenRouter形式）
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "mistralai/mistral-small-24b-instruct-2501",
    "deepseek/deepseek-chat",
]

_PRESET_URLS = [
    ("Ollama (ローカル)",  "http://localhost:11434/v1"),
    ("OpenRouter",        "https://openrouter.ai/api/v1"),
    ("OpenAI",            "https://api.openai.com/v1"),
    ("LM Studio",         "http://localhost:1234/v1"),
]


class SettingsDialog(ctk.CTkToplevel):

    def __init__(self, master, llm: LLMClient, on_save: callable):
        super().__init__(master)
        self._llm     = llm
        self._on_save = on_save

        self.title("LLM 接続設定")
        self.configure(fg_color=BG_PANEL)
        self.geometry("660x600")
        self.resizable(False, False)
        self.grab_set()
        self.focus_set()

        self._url_var     = tk.StringVar(value=config.get("llm_base_url"))
        self._key_var     = tk.StringVar(value=config.get("llm_api_key"))
        self._model_var   = tk.StringVar(value=config.get("llm_model"))
        self._timeout_var = tk.StringVar(value=str(config.get("llm_timeout")))

        # CTkToplevel on Windows は grab_set() 直後に build すると blank になる既知バグ対策
        self.after(100, self._build)

    def _build(self) -> None:
        # タイトル
        hdr = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="⚙  LLM 接続設定",
            font=ctk.CTkFont("Segoe UI", 14, "bold"), text_color=CYAN,
        ).pack(side="left", padx=16, pady=12)

        body = ctk.CTkScrollableFrame(self, fg_color="transparent", scrollbar_button_color=BG_WIDGET)
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

        # フォームフィールド
        fields = [
            ("BASE URL",  self._url_var,     False, "http://localhost:11434/v1"),
            ("API KEY",   self._key_var,      True,  "ollama  または  sk-..."),
            ("MODEL",     self._model_var,    False, "qwen2.5-coder:14b"),
            ("TIMEOUT",   self._timeout_var,  False, "180"),
        ]
        for label, var, secret, placeholder in fields:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(row, text=label, width=80,
                         font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                         anchor="w").pack(side="left")
            entry = ctk.CTkEntry(
                row, textvariable=var,
                placeholder_text=placeholder,
                show="*" if secret else "",
                font=ctk.CTkFont("Consolas", 11),
                fg_color=BG_INPUT, border_color=BORDER, border_width=1,
                text_color=TEXT_PRI, height=32,
            )
            entry.pack(side="left", fill="x", expand=True)

        # モデル候補（3列ずつ折返し表示）
        ctk.CTkLabel(body, text="モデル候補 (クリックで入力 / Claude・Fableは OpenRouter経由):",
                     font=ctk.CTkFont("Segoe UI", 9),
                     text_color=TEXT_DIM).pack(anchor="w", pady=(6, 2))
        for i in range(0, len(_PRESET_MODELS), 3):
            mdl_row = ctk.CTkFrame(body, fg_color="transparent")
            mdl_row.pack(fill="x", pady=(0, 2))
            for m in _PRESET_MODELS[i:i + 3]:
                is_claude = m.startswith("anthropic/")
                ctk.CTkButton(
                    mdl_row, text=m, height=24, width=196,
                    fg_color=BG_WIDGET, hover_color="#152030",
                    border_color=ORANGE_H if is_claude else BORDER, border_width=1,
                    text_color=ORANGE_H if is_claude else TEXT_DIM,
                    font=ctk.CTkFont("Consolas", 9),
                    command=lambda v=m: self._model_var.set(v),
                ).pack(side="left", padx=(0, 4))

        # 接続テスト結果ラベル
        self._test_result = ctk.CTkLabel(
            body, text="",
            font=ctk.CTkFont("Consolas", 10), text_color=TEXT_DIM, anchor="w",
        )
        self._test_result.pack(fill="x", pady=(10, 0))

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
