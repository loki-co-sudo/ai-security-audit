"""gui/result_notice.py — スキャン結果の実行状態と注意(errors・未検査)を、レポートを開かなくても出力欄で分かるようにする。

Tk非依存の `notice_lines()` と、出力欄へ追記する `show()`。errorsは生成元でマスク済みだが、念のためここでも
`mask_log_line` を通す。注意が無い完了(completed・errors空)では何も出さない。
"""

from __future__ import annotations

from core import redaction

MAX_DETAILS = 8
_STATE_JA = {"completed": "完了", "partial": "一部完了", "failed": "失敗", "cancelled": "中断"}


def notice_lines(result) -> list[tuple[str, str]]:
    """[(テキスト, タグ)]。出さない場合は空リスト。"""
    if not isinstance(result, dict):
        return []
    state = str(result.get("state") or "")
    errors = [str(e) for e in (result.get("errors") or [])]
    gaps = [c for c in (result.get("coverage") or []) if isinstance(c, dict) and c.get("status") not in ("tested", None)]
    if state == "completed" and not errors:
        return []
    if not state and not errors:
        return []
    label = _STATE_JA.get(state, state or "状態不明")
    head = f"\n── 結果の状態: {label}({state})・注意{len(errors)}件"
    if gaps:
        head += f"・未検査/失敗の検査単位{len(gaps)}件"
    out = [(head + " ──\n", "high")]
    for e in errors[:MAX_DETAILS]:
        out.append((f"  ! {redaction.mask_log_line(e, set())[:200]}\n", "dim"))
    if len(errors) > MAX_DETAILS:
        out.append((f"  … ほか{len(errors) - MAX_DETAILS}件(レポートのErrorsで確認)\n", "dim"))
    out.append(("  レポート出力時は、証拠の整合性・完全性も各所見の証拠欄に表示されます。\n", "dim"))
    return out


def show(out_box, result) -> None:
    """GUIスレッドから呼ぶこと。"""
    for text, tag in notice_lines(result):
        out_box.append(text, tag)
