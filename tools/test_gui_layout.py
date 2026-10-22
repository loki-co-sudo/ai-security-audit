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


if __name__ == "__main__":
    unittest.main()
