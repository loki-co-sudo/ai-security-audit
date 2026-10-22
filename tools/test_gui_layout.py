"""GUIダイアログのレイアウト回帰試験(xvfb-runの仮想ディスプレイで実行。利用者の画面には何も出さない)。

過去の不具合: AuthDialogは本体(expand=True)を先にpackしていたため、項目が増えると保存/キャンセルが窓外へ切れた。
xvfb-runが無い環境ではSKIPする(GUIの目視確認の代替ではなく、ボタンが窓内に収まることだけを固定する)。
"""
import os
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r'''
import sys, json
sys.path.insert(0, sys.argv[1])
import customtkinter as ctk
from gui.dialogs.auth_dialog import AuthDialog
root = ctk.CTk()
out = {}
for h in (720, 480):
    d = AuthDialog(root, initial={}, on_save=lambda *a: None)
    d.geometry(f"620x{h}+0+0")
    for _ in range(6):
        d.update_idletasks(); d.update()
    win_bottom = d.winfo_rooty() + d.winfo_height()
    row = d._btn_row
    out[h] = {"row_bottom": row.winfo_rooty() + row.winfo_height(), "win_bottom": win_bottom,
              "row_h": row.winfo_height(), "row_top_ok": row.winfo_rooty() >= d.winfo_rooty()}
    d.destroy()
root.destroy()
print(json.dumps(out))
'''


EXP_CHILD = r'''
import sys, json
sys.path.insert(0, sys.argv[1])
import customtkinter as ctk
from gui.dialogs.expectations_dialog import ExpectationsDialog
root = ctk.CTk()
saved = []
out = {}
d = ExpectationsDialog(root, initial=[{"path": "/account", "param": "id", "value": "1", "a": "allow", "b": "deny"}],
                       on_save=saved.append)
d.geometry("680x420+0+0")
for _ in range(6):
    d.update_idletasks(); d.update()
row = d._btn_row
out["row_ok"] = row.winfo_height() >= 50 and row.winfo_rooty() + row.winfo_height() <= d.winfo_rooty() + d.winfo_height() + 1
out["initial"] = d._text.get("1.0", "end").strip()
d._text.delete("1.0", "end"); d._text.insert("1.0", "/ok id a=allow b=deny\n/bad id a=maybe b=deny")
d._save(); d.update()
out["error_shown"] = d._error.cget("text")
out["still_open"] = bool(d.winfo_exists()) and not saved
d._text.delete("1.0", "end"); d._text.insert("1.0", "/ok id a=allow b=deny")
d._save()
out["saved"] = saved
root.destroy()
print(json.dumps(out, ensure_ascii=False))
'''


ENG_CHILD = r'''
import sys, json, os, tempfile
sys.path.insert(0, sys.argv[1])
from unittest import mock
import customtkinter as ctk
from core import config
from core.llm_client import LLMClient
from gui.dialogs.settings_dialog import SettingsDialog
import gui.app as A
from core import event_bus as ev
out = {}
root = ctk.CTk()
saved = []
llm = LLMClient(base_url="http://127.0.0.1:1/v1", api_key="x", model="m", timeout=1)
with mock.patch.object(config, "save", lambda d: saved.append(d)):
    d = SettingsDialog(root, llm, on_save=lambda m: None)
    for _ in range(4):
        d.update_idletasks(); d.update()
    d._engagement_var.set("bad/id"); d._save(); d.update()
    out["error"] = d._eng_error.cget("text"); out["saved_after_bad"] = len(saved); out["alive_after_bad"] = bool(d.winfo_exists())
    d._engagement_var.set("lab-1"); d._save()
    out["saved_id"] = saved[-1].get("engagement_id") if saved else None
root.destroy()
# パネル: engagement_id設定時だけRESULTが台帳へ記録される
work = tempfile.mkdtemp(); os.chdir(work)
app = A.App()
res = {"scan_id": "scan_t1", "target": "http://127.0.0.1:8080/", "mode": "WEB FUZZ", "state": "completed", "findings": [],
       "coverage": [], "errors": [], "started_at": "2026-10-22T00:00:00", "finished_at": "2026-10-22T00:00:01"}
for key in ("audit", "attack", "fuzz", "defense"):
    app._panels[key].dispatch(ev.Event(ev.RESULT, dict(res, mode=key.upper())))
out["no_id_has_ledger"] = any("ledger" in (app._panels[k]._scan_result or {}) for k in app._panels)
out["no_id_dir"] = os.path.exists("reports/engagements")
with mock.patch.dict(config._cfg, {"engagement_id": "lab-gui"}):
    for i, key in enumerate(("audit", "attack", "fuzz", "defense")):
        app._panels[key].dispatch(ev.Event(ev.RESULT, dict(res, scan_id=f"scan_p{i}", mode=key.upper())))
    out["has_ledger"] = {k: "ledger" in (app._panels[k]._scan_result or {}) for k in app._panels}
    out["recorded"] = sum(1 for l in open("reports/engagements/lab-gui/events.jsonl", encoding="utf-8") if '"scan_recorded"' in l)
app.destroy()
print(json.dumps(out, ensure_ascii=False))
'''


LEDGER_CHILD = r'''
import sys, json, os, tempfile
sys.path.insert(0, sys.argv[1])
from unittest import mock
import customtkinter as ctk
from core import config
from gui.ledger_util import attach_ledger
from gui.dialogs.ledger_dialog import LedgerDialog
from tools.test_findings_ledger import finding, scan, unit_cov
os.chdir(tempfile.mkdtemp())
out = {}
root = ctk.CTk()
with mock.patch.dict(config._cfg, {"engagement_id": ""}):
    d = LedgerDialog(root)
    d.update()
    out["unset_info"] = d._info.cget("text")
    d.destroy()
with mock.patch.dict(config._cfg, {"engagement_id": "lab-dlg"}):
    r = scan("s1", [finding("/a q"), finding("/b id", "SQLI")], unit_cov("/a", "q") + unit_cov("/b", "id"))
    for f in r["findings"]:
        f.setdefault("description", "d")
    fids = [x["finding_id"] for x in attach_ledger(r)["ledger"]["findings"]]
    d = LedgerDialog(root)
    d.geometry("860x420+0+0")
    for _ in range(6):
        d.update_idletasks(); d.update()
    a = d._action
    out["action_visible"] = a.winfo_height() > 60 and a.winfo_rooty() + a.winfo_height() <= d.winfo_rooty() + d.winfo_height() + 1
    out["rows"] = len(d._list.winfo_children())
    d._do_status(); out["no_selection"] = d._msg.cget("text")
    d._selected.set(fids[0]); d._status_var.set("fixed")
    d._do_status(); out["no_reason"] = d._msg.cget("text")
    d._reason.set("修正を確認"); d._do_status(); out["status_ok"] = d._msg.cget("text")
    d._selected.set(fids[1]); d._reason.set("調整中"); d._days.set("0"); d._do_suppress(); out["bad_days"] = d._msg.cget("text")
    d._days.set("14"); d._do_suppress(); out["suppress_ok"] = d._msg.cget("text")
    for _ in range(3):
        d.update_idletasks(); d.update()
    out["suppressed_row_shown"] = any("抑制中" in w.cget("text") for w in d._list.winfo_children())
    out["reason_cleared"] = d._reason.get()
    d.destroy()
    from core.findings_ledger import Ledger
    L = Ledger("lab-dlg").findings(include_suppressed=True)["findings"]
    out["ledger"] = {x["finding_id"]: (x["status"], x["suppressed"]) for x in L}
    out["fids"] = fids
root.destroy()
print(json.dumps(out, ensure_ascii=False))
'''


@unittest.skipUnless(shutil.which("xvfb-run"), "xvfb-runが無いためGUIレイアウト試験を実行できない")
class LedgerDialogTest(unittest.TestCase):
    def test_dialog_requires_selection_and_reason_and_records_to_the_ledger(self):
        import json
        p = subprocess.run(["xvfb-run", "-a", "-s", "-screen 0 1600x1000x24", sys.executable, "-c", LEDGER_CHILD, ROOT],
                           capture_output=True, text=True, timeout=90, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr[-1200:])
        o = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertIn("案件ID", o["unset_info"])                                            # 未設定なら案内だけ
        self.assertTrue(o["action_visible"], o)                                              # 小さい窓でも操作欄が見える
        self.assertEqual(o["rows"], 2)
        self.assertIn("選んで", o["no_selection"])
        self.assertIn("理由", o["no_reason"])                                                # 理由なしは記録されない
        self.assertTrue(o["status_ok"].startswith("✓"), o)
        self.assertIn("1〜365", o["bad_days"])
        self.assertTrue(o["suppress_ok"].startswith("✓"), o)
        self.assertTrue(o["suppressed_row_shown"])
        self.assertEqual(o["reason_cleared"], "")
        self.assertEqual(o["ledger"][o["fids"][0]], ["fixed", False])
        self.assertEqual(o["ledger"][o["fids"][1]], ["open", True])


STRUCT_CHILD = r'''
import sys, json
sys.path.insert(0, sys.argv[1])
from unittest import mock
import customtkinter as ctk
from core import config
from core.llm_client import LLMClient
from gui.dialogs.settings_dialog import SettingsDialog
root = ctk.CTk()
saved = []
llm = LLMClient(base_url="http://127.0.0.1:1/v1", api_key="x", model="m", timeout=1)
out = {}
with mock.patch.object(config, "save", lambda d: saved.append(d)):
    d = SettingsDialog(root, llm, on_save=lambda m: None)
    for _ in range(4):
        d.update_idletasks(); d.update()
    out["default_off"] = not d._structured_var.get()
    d._structured_var.set(True); d._structured_ctx_var.set("50"); d._save(); d.update()
    out["error"] = d._structured_error.cget("text"); out["saved_after_bad"] = len(saved); out["alive"] = bool(d.winfo_exists())
    d._structured_ctx_var.set("16384"); d._save()
    out["saved"] = {k: saved[-1].get(k) for k in ("llm_structured", "llm_structured_num_ctx")} if saved else None
root.destroy()
print(json.dumps(out, ensure_ascii=False))
'''


@unittest.skipUnless(shutil.which("xvfb-run"), "xvfb-runが無いためGUIレイアウト試験を実行できない")
class StructuredSettingsTest(unittest.TestCase):
    def test_default_off_invalid_num_ctx_keeps_the_dialog_open_and_valid_values_are_saved(self):
        import json
        p = subprocess.run(["xvfb-run", "-a", "-s", "-screen 0 1600x1000x24", sys.executable, "-c", STRUCT_CHILD, ROOT],
                           capture_output=True, text=True, timeout=90, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr[-1200:])
        o = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertTrue(o["default_off"])
        self.assertIn("llm_structured_num_ctx", o["error"])
        self.assertEqual((o["saved_after_bad"], o["alive"]), (0, True))
        self.assertEqual(o["saved"], {"llm_structured": True, "llm_structured_num_ctx": 16384})


@unittest.skipUnless(shutil.which("xvfb-run"), "xvfb-runが無いためGUIレイアウト試験を実行できない")
class EngagementGuiTest(unittest.TestCase):
    def test_settings_validate_the_id_and_all_four_panels_record_results_only_when_set(self):
        import json
        p = subprocess.run(["xvfb-run", "-a", "-s", "-screen 0 1600x1000x24", sys.executable, "-c", ENG_CHILD, ROOT],
                           capture_output=True, text=True, timeout=90, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr[-1200:])
        out = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertIn("案件ID", out["error"])
        self.assertEqual((out["saved_after_bad"], out["alive_after_bad"]), (0, True))      # 不正IDは保存せず閉じない
        self.assertEqual(out["saved_id"], "lab-1")
        self.assertFalse(out["no_id_has_ledger"])                                          # 未設定=従来どおり何もしない
        self.assertFalse(out["no_id_dir"])
        self.assertTrue(all(out["has_ledger"].values()), out["has_ledger"])
        self.assertEqual(out["recorded"], 4)                                               # 1スキャンにつき1回だけ記録


@unittest.skipUnless(shutil.which("xvfb-run"), "xvfb-runが無いためGUIレイアウト試験を実行できない")
class AuthDialogLayoutTest(unittest.TestCase):
    def test_action_buttons_stay_inside_the_window_even_when_the_window_is_short(self):
        p = subprocess.run(["xvfb-run", "-a", "-s", "-screen 0 1600x1000x24", sys.executable, "-c", CHILD, ROOT],
                           capture_output=True, text=True, timeout=60, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        import json
        out = json.loads(p.stdout.strip().splitlines()[-1])
        for h, r in out.items():
            self.assertGreaterEqual(r["row_h"], 50, (h, r))                    # ボタン行が潰れていない
            self.assertLessEqual(r["row_bottom"], r["win_bottom"] + 1, (h, r))   # 窓の下端を越えない
            self.assertTrue(r["row_top_ok"], (h, r))


@unittest.skipUnless(shutil.which("xvfb-run"), "xvfb-runが無いためGUIレイアウト試験を実行できない")
class ExpectationsDialogTest(unittest.TestCase):
    def test_buttons_visible_invalid_input_keeps_dialog_open_and_valid_input_is_saved(self):
        import json
        p = subprocess.run(["xvfb-run", "-a", "-s", "-screen 0 1600x1000x24", sys.executable, "-c", EXP_CHILD, ROOT],
                           capture_output=True, text=True, timeout=60, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        out = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertTrue(out["row_ok"], out)
        self.assertEqual(out["initial"], "/account id 1 a=allow b=deny")          # 既存の表が復元される
        self.assertTrue(out["error_shown"].startswith("⚠ 2行目"), out)            # 不正行は行番号つきで表示
        self.assertTrue(out["still_open"], out)                                   # 不正な入力では閉じず、保存もしない
        self.assertEqual([(r["path"], r["a"], r["b"]) for r in out["saved"][0]], [("/ok", "allow", "deny")])


if __name__ == "__main__":
    unittest.main()