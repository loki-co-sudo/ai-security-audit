"""
gui/dialogs/ledger_dialog.py — 所見台帳の閲覧と対応status・期限付き抑制の記録(P3.2)

案件ID(config.engagement_id)の台帳にある所見を一覧し、選んだ所見に対応status(open/fixed/accepted-risk)を
理由つきで記録、または理由と日数(1〜365)で期限付き抑制を記録する。台帳は追記式で、取り消しは新しい記録で上書きする。
抑制は表示から外すだけで、件数・理由・期限はレポートに必ず残る。ロジックは gui.ledger_util(Tk非依存)。
"""

from __future__ import annotations
import tkinter as tk
import customtkinter as ctk

from core.findings_ledger import STATUSES, LedgerError
from core.settings import (
    BG_PANEL, BG_WIDGET, BG_INPUT, CYAN, AMBER, TEXT_PRI, TEXT_DIM, BORDER, RED_C, GREEN, SEV_COLORS,
)
from gui import ledger_util
from gui.dialogs.base import RobustToplevel


class LedgerDialog(RobustToplevel):

    def __init__(self, master):
        super().__init__(master)
        self.title("所見台帳")
        self.configure(fg_color=BG_PANEL)
        self.geometry("860x640")
        self.minsize(640, 480)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._selected = tk.StringVar(self, value="")
        self._status_var = tk.StringVar(self, value=STATUSES[0])
        self._reason = tk.StringVar(self, value="")
        self._days = tk.StringVar(self, value="30")
        self._build()
        self.reload()
        self._apply_dark_titlebar()
        self.after(80, lambda: self._bring_to_front(grab=True))

    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        self._title = ctk.CTkLabel(hdr, text="📒  所見台帳", font=ctk.CTkFont("Segoe UI", 14, "bold"), text_color=AMBER)
        self._title.pack(side="left", padx=16, pady=12)

        # 操作欄を先にpackする(side="bottom"は本体より前。小さい窓でも操作が見える)
        act = self._action = ctk.CTkFrame(self, fg_color=BG_WIDGET, corner_radius=0)
        act.pack(fill="x", side="bottom")
        self._msg = ctk.CTkLabel(act, text="", font=ctk.CTkFont("Segoe UI", 10), text_color=RED_C,
                                 anchor="w", justify="left", wraplength=800)
        self._msg.pack(fill="x", padx=14, pady=(8, 0))
        row1 = ctk.CTkFrame(act, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=(6, 2))
        ctk.CTkLabel(row1, text="理由", width=44, anchor="w", font=ctk.CTkFont("Segoe UI", 10),
                     text_color=TEXT_DIM).pack(side="left")
        ctk.CTkEntry(row1, textvariable=self._reason, fg_color=BG_INPUT, border_color=BORDER, border_width=1,
                     text_color=TEXT_PRI, height=30, font=ctk.CTkFont("Segoe UI", 11),
                     placeholder_text="必須(状態の変更・抑制のどちらにも記録されます)").pack(side="left", fill="x", expand=True)
        row2 = ctk.CTkFrame(act, fg_color="transparent")
        row2.pack(fill="x", padx=14, pady=(4, 10))
        ctk.CTkLabel(row2, text="状態", width=44, anchor="w", font=ctk.CTkFont("Segoe UI", 10),
                     text_color=TEXT_DIM).pack(side="left")
        ctk.CTkOptionMenu(row2, values=list(STATUSES), variable=self._status_var, width=140, height=30,
                          fg_color=BG_INPUT, button_color=BORDER, text_color=TEXT_PRI).pack(side="left", padx=(0, 6))
        ctk.CTkButton(row2, text="状態を記録", width=100, height=30, fg_color=CYAN, hover_color="#00B5DD",
                      text_color=BG_PANEL, font=ctk.CTkFont("Segoe UI", 11, "bold"),
                      command=self._do_status).pack(side="left", padx=(0, 24))
        ctk.CTkLabel(row2, text="抑制", width=36, anchor="w", font=ctk.CTkFont("Segoe UI", 10),
                     text_color=TEXT_DIM).pack(side="left")
        ctk.CTkEntry(row2, textvariable=self._days, width=56, height=30, fg_color=BG_INPUT, border_color=BORDER,
                     border_width=1, text_color=TEXT_PRI).pack(side="left", padx=(0, 4))
        ctk.CTkLabel(row2, text="日間", anchor="w", font=ctk.CTkFont("Segoe UI", 10),
                     text_color=TEXT_DIM).pack(side="left", padx=(0, 6))
        ctk.CTkButton(row2, text="期限付きで抑制", width=120, height=30, fg_color="#2A1A00", hover_color="#3A2400",
                      border_color=AMBER, border_width=1, text_color=AMBER, font=ctk.CTkFont("Segoe UI", 11),
                      command=self._do_suppress).pack(side="left")
        ctk.CTkButton(row2, text="閉じる", width=80, height=30, fg_color="#152030", hover_color="#1E3040",
                      border_color=BORDER, border_width=1, text_color=TEXT_DIM, font=ctk.CTkFont("Segoe UI", 11),
                      command=self.destroy).pack(side="right")

        self._info = ctk.CTkLabel(self, text="", font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
                                  anchor="w", justify="left", wraplength=820)
        self._info.pack(fill="x", padx=16, pady=(8, 2))
        self._list = ctk.CTkScrollableFrame(self, fg_color=BG_INPUT, border_color=BORDER, border_width=1)
        self._list.pack(fill="both", expand=True, padx=14, pady=(0, 8))

    def reload(self) -> None:
        for w in self._list.winfo_children():
            w.destroy()
        try:
            res = ledger_util.list_findings()
        except LedgerError as e:
            self._title.configure(text="📒  所見台帳")
            self._info.configure(text=f"{e}")
            return
        self._title.configure(text=f"📒  所見台帳 — 案件 {res['engagement_id']}")
        rows = res["findings"]
        notes = "".join(f"\n⚠ {w}" for w in res["warnings"])
        self._info.configure(text=(f"{len(rows)}件。行を選んで下の欄から記録します。抑制は表示から外すだけで、件数・理由・期限はレポートに残ります。"
                                   if rows else "この案件の台帳にはまだ所見がありません(スキャン完了時に記録されます)。") + notes)
        if self._selected.get() not in {r["finding_id"] for r in rows}:
            self._selected.set("")
        for r in rows:
            sup = f"  [抑制中 {r['suppression_expires_at'][:10]}まで: {r['suppression_reason']}]" if r["suppressed"] else ""
            text = f"{r['severity'] or '-':<8} {r['status']:<13} {r['rule_id']}  {r['location']}  ({r['finding_id']}){sup}"
            ctk.CTkRadioButton(
                self._list, text=text, variable=self._selected, value=r["finding_id"],
                font=ctk.CTkFont("Consolas", 10), text_color=SEV_COLORS.get(str(r["severity"]).upper(), TEXT_PRI),
                fg_color=CYAN, border_width_checked=5, radiobutton_width=16, radiobutton_height=16,
            ).pack(anchor="w", padx=8, pady=3)

    def _guard(self):
        fid = self._selected.get()
        if not fid:
            self._msg.configure(text="⚠ 対象の所見を一覧から選んでください")
            return None
        return fid

    def _done(self, text: str) -> None:
        self._msg.configure(text=text, text_color=GREEN)
        self._reason.set("")
        self.reload()

    def _do_status(self) -> None:
        fid = self._guard()
        if fid is None:
            return
        try:
            ledger_util.apply_status(fid, self._status_var.get(), self._reason.get())
        except LedgerError as e:
            self._msg.configure(text=f"⚠ {e}", text_color=RED_C)
            return
        self._done(f"✓ {fid} の状態を {self._status_var.get()} として記録しました")

    def _do_suppress(self) -> None:
        fid = self._guard()
        if fid is None:
            return
        try:
            until = ledger_util.apply_suppress(fid, self._reason.get(), self._days.get())
        except LedgerError as e:
            self._msg.configure(text=f"⚠ {e}", text_color=RED_C)
            return
        self._done(f"✓ {fid} を {until[:10]} まで抑制しました(レポートには件数・理由・期限が残ります)")
