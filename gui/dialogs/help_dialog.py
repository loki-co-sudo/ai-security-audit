"""
gui/dialogs/help_dialog.py — LLM接続設定のヘルプ画面

AIの利用が初めての人向けに、接続の考え方・APIキーの取得先（外部リンク）・
各項目の意味・モデルの選び方を案内する。
"""
from __future__ import annotations
import webbrowser
import customtkinter as ctk

from core.settings import (
    BG_PANEL, BG_WIDGET, CYAN, GREEN, AMBER,
    TEXT_PRI, TEXT_DIM, TEXT_MID, BORDER,
)
from gui.dialogs.base import RobustToplevel

# APIキー取得・各サービスの外部リンク
_LINK_OPENROUTER_KEYS = "https://openrouter.ai/keys"
_LINK_OPENROUTER_MODELS = "https://openrouter.ai/models"
_LINK_OPENAI_KEYS = "https://platform.openai.com/api-keys"
_LINK_OLLAMA = "https://ollama.com/download"
_LINK_OLLAMA_LIB = "https://ollama.com/library"
_LINK_LMSTUDIO = "https://lmstudio.ai/"


class HelpDialog(RobustToplevel):

    def __init__(self, master, on_close: callable | None = None):
        super().__init__(master)
        self._on_close = on_close

        self.title("ヘルプ — LLM接続設定の使い方")
        self.configure(fg_color=BG_PANEL)
        self.geometry("640x680")
        # minsize のみ設定（maxsize を固定すると最大化できなくなるため設定しない）。
        self.minsize(640, 680)

        self.protocol("WM_DELETE_WINDOW", self._close)
        self._build()
        self._apply_dark_titlebar()
        self.after(80, lambda: self._bring_to_front(grab=False))

    # ── 小さなビルダー ─────────────────────────────────────
    def _heading(self, parent, text: str, color: str = CYAN) -> None:
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont("Segoe UI", 13, "bold"),
                     text_color=color, anchor="w", justify="left",
                     wraplength=560).pack(fill="x", anchor="w", pady=(16, 4))

    def _para(self, parent, text: str, color: str = TEXT_PRI) -> None:
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont("Segoe UI", 11),
                     text_color=color, anchor="w", justify="left",
                     wraplength=560).pack(fill="x", anchor="w", pady=(0, 2))

    def _bullet(self, parent, text: str) -> None:
        ctk.CTkLabel(parent, text=f"・{text}", font=ctk.CTkFont("Segoe UI", 11),
                     text_color=TEXT_MID, anchor="w", justify="left",
                     wraplength=540).pack(fill="x", anchor="w", padx=(10, 0), pady=(0, 2))

    def _link(self, parent, label: str, url: str) -> None:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", anchor="w", padx=(10, 0), pady=(0, 3))
        ctk.CTkLabel(row, text=f"🔗 {label}: ", font=ctk.CTkFont("Segoe UI", 11),
                     text_color=TEXT_MID, anchor="w").pack(side="left")
        link = ctk.CTkLabel(row, text=url, font=ctk.CTkFont("Consolas", 11, underline=True),
                            text_color=CYAN, anchor="w", cursor="hand2")
        link.pack(side="left")
        link.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))

    # ── 画面構築 ───────────────────────────────────────────
    def _build(self) -> None:
        # ヘッダー
        hdr = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="❓  LLM接続設定の使い方",
                     font=ctk.CTkFont("Segoe UI", 14, "bold"),
                     text_color=CYAN).pack(side="left", padx=16, pady=12)

        # スクロール本文
        body = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=TEXT_DIM,
        )
        body.pack(fill="both", expand=True, padx=20, pady=(8, 4))

        self._para(body,
            "このツールは「AIモデル」に接続して、コード診断や攻撃検証などを自動で行います。"
            "AIモデルは ① お使いのPC内で動かす（ローカル）か、② インターネット上の"
            "サービスを使う（クラウド）か、のどちらかで利用します。")

        # かんたん設定
        self._heading(body, "■ まず選ぶ：ローカル or クラウド")
        self._para(body, "▼ とにかく無料で試したい → ローカル（Ollama）がおすすめ",
                   color=GREEN)
        self._bullet(body, "自分のPCでAIを動かすので料金もAPIキーも不要。")
        self._bullet(body, "下のリンクから Ollama をインストールし、使いたいモデルを入れます。")
        self._link(body, "Ollama 本体（無料・インストール）", _LINK_OLLAMA)
        self._link(body, "Ollama 使えるモデル一覧", _LINK_OLLAMA_LIB)
        self._para(body, "  設定例：BASE URL=http://localhost:11434/v1 / API KEY=ollama")

        self._para(body, "▼ 高性能なモデル（GPT-5系・Claude等）を使いたい → クラウドがおすすめ",
                   color=AMBER)
        self._bullet(body, "OpenRouter なら 1つのAPIキーで多数のモデル（GPT・Claude・Qwen等）が使えて便利。")
        self._bullet(body, "従量課金です。各サービスのサイトで残高/支払い設定が必要な場合があります。")

        # APIキーの取得
        self._heading(body, "■ APIキーの取得（クラウド利用時）")
        self._para(body, "下のリンク先でアカウントを作り、APIキーを発行してコピーし、"
                         "設定画面の「API KEY」欄に貼り付けます。")
        self._link(body, "OpenRouter（おすすめ・多数モデル対応）", _LINK_OPENROUTER_KEYS)
        self._link(body, "OpenAI（GPT を直接使う場合）", _LINK_OPENAI_KEYS)
        self._link(body, "OpenRouter モデル一覧・料金の確認", _LINK_OPENROUTER_MODELS)
        self._link(body, "LM Studio（ローカルGUI・キー不要）", _LINK_LMSTUDIO)
        self._para(body, "  ※ APIキーは他人に教えないでください。本ツールはローカルにのみ保存します。",
                   color=TEXT_DIM)

        # 各項目
        self._heading(body, "■ 各入力項目の意味")
        self._bullet(body, "BASE URL：接続先の住所。PRESETボタンで自動入力できます。")
        self._bullet(body, "API KEY：クラウドの鍵。ローカル(Ollama)なら「ollama」のままでOK。")
        self._bullet(body, "MODEL：使うAIモデル名。下の一覧から選ぶか直接入力します。")
        self._bullet(body, "TIMEOUT：応答待ちの上限秒数。大きいモデルは長めに（例: 180）。")

        # モデルの選び方
        self._heading(body, "■ モデルの選び方")
        self._bullet(body, "「↻ 取得」を押すと、接続先で実際に使えるモデル一覧を取得します。")
        self._bullet(body, "検索ボックスにキーワード（例: claude, gpt-5, qwen3）を入れて絞り込み、")
        self._bullet(body, "一覧の項目をクリックすると MODEL 欄へ反映されます。")
        self._bullet(body, "迷ったら：コード診断は高性能モデル（claude-sonnet-4.6 / gpt-5.5 等）、"
                           "軽く試すならローカルの小型モデルが目安です。")

        # 手順
        self._heading(body, "■ 設定の流れ")
        self._para(body, "①接続先を選ぶ → ②(クラウドなら)APIキーを貼る → ③「↻ 取得」"
                         "→ ④モデルを選ぶ → ⑤「接続テスト」で確認 → ⑥「保存」")

        # 閉じるボタン行
        btn_row = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=56)
        btn_row.pack(fill="x", side="bottom")
        btn_row.pack_propagate(False)
        ctk.CTkButton(
            btn_row, text="閉じる", width=120, height=36,
            fg_color=CYAN, hover_color="#00B5DD",
            text_color=BG_PANEL, font=ctk.CTkFont("Segoe UI", 12, "bold"),
            command=self._close,
        ).pack(side="right", padx=16, pady=10)

    def _close(self) -> None:
        cb = self._on_close
        self.destroy()
        if cb:
            cb()
