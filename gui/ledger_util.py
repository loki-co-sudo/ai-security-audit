"""
gui/ledger_util.py — GUIのスキャン結果を所見台帳へ記録し、レポート用ビューを付ける(P3.2)

config.json の engagement_id が空なら何もしない(既定)。設定されていれば、完了したスキャン結果を
reports/engagements/<id>/ へ追記し、report_view(抑制・差分・所見ごとの状態)を結果に付ける。
台帳の失敗はスキャン結果を隠さず、errorsへ注記する。呼び出し元は結果を1スキャンにつき1回だけ渡すこと。
"""

from __future__ import annotations

from core import config
from core.findings_ledger import Ledger, LedgerError


def attach_ledger(result):
    """結果(ScanResult.to_dict())を台帳へ記録して返す。対象外(未設定・結果なし・scan_idなし)は同じオブジェクトをそのまま返す。"""
    eid = config.get("engagement_id", "")
    if not eid or not isinstance(result, dict) or not result.get("scan_id"):
        return result
    out = dict(result)
    out["engagement_id"] = eid
    try:
        led = Ledger(eid)
        led.record_scan(out)
        out["ledger"] = led.report_view(out)
    except (LedgerError, OSError) as e:
        out["errors"] = list(out.get("errors") or []) + [f"所見台帳への記録に失敗しました: {e}"]
    return out
