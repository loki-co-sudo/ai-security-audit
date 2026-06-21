"""
gui/dialogs/auth_dialog.py — WEB FUZZ 認証設定ダイアログ

認証付きWebアプリをファジングするための認証情報を入力する。
3方式（いずれか / 併用可）:
  - Cookie:        ブラウザのセッションCookieを貼り付け
  - ヘッダー:      Authorization: Bearer ... などの任意ヘッダー
  - ログインフォーム: ログインURL+資格情報（CSRFトークンは自動抽出）
"""
from __future__ import annotations
import tkinter as tk
import customtkinter as ctk

from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, AMBER, TEXT_PRI, TEXT_DIM, BORDER,
)
from gui.dialogs.base import RobustToplevel


class AuthDialog(RobustToplevel):

    def __init__(self, master, initial: dict | None = None, on_save: callable = None):
        super().__init__(master)
        self._on_save = on_save
        init = initial or {}

        self.title("WEB FUZZ 認証設定")
        self.configure(fg_color=BG_PANEL)
        self.geometry("620x560")
        self.minsize(620, 560)

        # 各フィールドの変数（master=self でデフォルトルート非依存）
        self._v = {
            k: tk.StringVar(self, value=init.get(k, ""))
            for k in ("cookie", "header_name", "header_value",
                      "login_url", "post_url", "user_field", "user_val",
                      "pass_field", "pass_val")
        }

        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._build()
        self._apply_dark_titlebar()
        self.after(80, lambda: self._bring_to_front(grab=True))

    def _entry(self, parent, label, key, placeholder, secret=False):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text=label, width=110,
                     font=ctk.CTkFont("Consolas", 10, "bold"), text_color=TEXT_DIM,
                     anchor="w").pack(side="left")
        ctk.CTkEntry(
            row, textvariable=self._v[key], placeholder_text=placeholder,
            show="*" if secret else "",
            font=ctk.CTkFont("Consolas", 11),
            fg_color=BG_INPUT, border_color=BORDER, border_width=1,
            text_color=TEXT_PRI, height=30,
        ).pack(side="left", fill="x", expand=True)

    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont("Segoe UI", 11, "bold"),
                     text_color=CYAN, anchor="w").pack(fill="x", anchor="w", pady=(12, 2))

    def _build(self):
        hdr = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🔐  認証設定（認証付きファジング）",
                     font=ctk.CTkFont("Segoe UI", 14, "bold"),
                     text_color=AMBER).pack(side="left", padx=16, pady=12)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=10)

        ctk.CTkLabel(
            body, text="使う方式の欄だけ入力してください（併用可）。空欄は無視されます。",
            font=ctk.CTkFont("Segoe UI", 9), text_color=TEXT_DIM,
            anchor="w", justify="left", wraplength=560).pack(fill="x", anchor="w")

        self._section(body, "① Cookie 認証")
        self._entry(body, "Cookie", "cookie", "sessionid=abc123; csrftoken=xyz")

        self._section(body, "② ヘッダー認証")
        self._entry(body, "ヘッダー名", "header_name", "Authorization")
        self._entry(body, "ヘッダー値", "header_value", "Bearer eyJhbGci...", secret=True)

        self._section(body, "③ ログインフォーム認証（CSRFは自動抽出）")
        self._entry(body, "ログインURL", "login_url", "http://127.0.0.1:8000/login")
        self._entry(body, "送信先URL(任意)", "post_url", "未指定ならログインURLへPOST")
        self._entry(body, "ユーザー名欄", "user_field", "username")
        self._entry(body, "ユーザー名", "user_val", "admin")
        self._entry(body, "パスワード欄", "pass_field", "password")
        self._entry(body, "パスワード", "pass_val", "secret", secret=True)

        btn_row = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=56)
        btn_row.pack(fill="x", side="bottom")
        btn_row.pack_propagate(False)
        ctk.CTkButton(
            btn_row, text="キャンセル", width=110, height=36,
            fg_color="#152030", hover_color="#1E3040",
            border_color=BORDER, border_width=1, text_color=TEXT_DIM,
            font=ctk.CTkFont("Segoe UI", 11), command=self.destroy,
        ).pack(side="right", padx=12, pady=10)
        ctk.CTkButton(
            btn_row, text="保存", width=110, height=36,
            fg_color=CYAN, hover_color="#00B5DD", text_color=BG_PANEL,
            font=ctk.CTkFont("Segoe UI", 12, "bold"), command=self._save,
        ).pack(side="right", padx=(0, 6), pady=10)
        ctk.CTkButton(
            btn_row, text="クリア", width=100, height=36,
            fg_color="#2A1A00", hover_color="#3A2400",
            border_color=AMBER, border_width=1, text_color=AMBER,
            font=ctk.CTkFont("Segoe UI", 11), command=self._clear,
        ).pack(side="left", padx=12, pady=10)

    def _save(self):
        data = {k: v.get().strip() for k, v in self._v.items() if v.get().strip()}
        if self._on_save:
            self._on_save(data)
        self.destroy()

    def _clear(self):
        for v in self._v.values():
            v.set("")
        if self._on_save:
            self._on_save({})
        self.destroy()
