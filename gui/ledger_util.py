"""
gui/ledger_util.py — GUIのスキャン結果を所見台帳へ記録し、レポート用ビューを付ける(P3.2)

config.json の engagement_id が空なら何もしない(既定)。設定されていれば、完了したスキャン結果を
reports/engagements/<id>/ へ追記し、report_view(抑制・差分・所見ごとの状態)を結果に付ける。
台帳の失敗はスキャン結果を隠さず、errorsへ注記する。呼び出し元は結果を1スキャンにつき1回だけ渡すこと。
"""

from __future__ import annotations

from datetime import datetime, timedelta

from core import config
from core.findings_ledger import STATUSES, Ledger, LedgerError


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


MAX_SUPPRESS_DAYS = 365      # 抑制は期限付きが前提。無期限・極端に長い抑制はGUIから作らない


def _ledger(eid: str | None = None) -> Ledger:
    eid = config.get("engagement_id", "") if eid is None else eid
    if not eid:
        raise LedgerError("案件IDが未設定です(設定ダイアログの「📒 案件ID」)")
    return Ledger(eid)


def list_findings(eid: str | None = None) -> dict:
    """案件の所見一覧(抑制中も含む)。{engagement_id, findings, warnings}。台帳が無ければ空。"""
    led = _ledger(eid)
    res = led.findings(include_suppressed=True)
    return {"engagement_id": led.engagement_id, "findings": res["findings"], "warnings": res["warnings"]}


def apply_status(finding_id: str, status: str, reason: str, eid: str | None = None) -> None:
    """対応statusを記録する(理由必須。検証は台帳側)。"""
    if status not in STATUSES:
        raise LedgerError(f"statusは{'/'.join(STATUSES)}のいずれかです")
    _ledger(eid).set_status(finding_id, status, reason)


def apply_suppress(finding_id: str, reason: str, days, eid: str | None = None) -> str:
    """期限付き抑制を記録して期限(ISO)を返す。daysは1〜365の整数(無期限は作れない)。"""
    try:
        n = int(str(days).strip())
    except (TypeError, ValueError):
        raise LedgerError("抑制の日数は整数で指定してください")
    if not 1 <= n <= MAX_SUPPRESS_DAYS:
        raise LedgerError(f"抑制の日数は1〜{MAX_SUPPRESS_DAYS}で指定してください")
    until = (datetime.now().astimezone() + timedelta(days=n)).isoformat(timespec="seconds")
    _ledger(eid).suppress(finding_id, reason, until)
    return until

