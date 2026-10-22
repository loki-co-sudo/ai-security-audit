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