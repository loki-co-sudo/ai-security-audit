"""
core/autonomy/research_report.py — 自律調査の編集可能なレポートドラフト（Markdown・ファイルを書くだけで外部へ提出しない）

要求仕様 §4.G: 人間が根拠を追跡できる形で、概要・前提・期待動作と観測・再現手順・対照・証拠参照と保存状態・
未確認事項・棄却した仮説・未調査範囲・終了理由と予算・人間のレビュー状態を載せる。
確定していないもの（候補・未判定・検証不能・未検査）を所見として書かない。深刻度は型からの見積りで、影響の測定ではない。
応答本文は載せない（証拠ファイル側にマスク済みで保存）。
"""
from __future__ import annotations

from core.evidence_store import EVIDENCE_ROOT, inspect_evidence

_STATE_JA = {"completed": "完了", "partial": "一部のみ(検証不能・未検査・未判定・候補あり)", "failed": "失敗", "cancelled": "中断"}


def _md(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def _ev_line(scan_id: str, eid: str, root: str | None) -> str:
    r = inspect_evidence(root, scan_id, eid)
    return f"`{eid}`（整合性: {r['integrity']} / 完全性: {r['completeness']}）"


def render_markdown(result: dict, *, evidence_root: str | None = None) -> str:
    root = evidence_root or EVIDENCE_ROOT
    scan_id, m, b = result["scan_id"], result["metrics"], result["budget"]
    by = {h["hypothesis_id"]: h for h in result["hypotheses"]}
    out = [f"# 自律調査レポート（ドラフト）: {result['case_id']}", "",
           f"- 実行: run_id=`{result['run_id']}` / 実行状態: **{_STATE_JA.get(result['state'], result['state'])}**",
           f"- 終了理由: `{result['end_reason']}`（`{result['finish_reason']}`）",
           f"- 予算: リクエスト {b.get('requests_used', m['requests_used'])}/{b['configured']['max_requests']}、LLM呼出 0。"
           f"人間の調査介入: {m['human_interventions']}件（実行範囲の承認は別記録）",
           "- 成果の段階: **意図的に埋め込まれた欠陥（模擬環境）に対する、初見ケースでの調査**。新規脆弱性・ゼロデイの発見を主張しない。",
           "- 人間のレビュー状態: **未レビュー**（本書は機械が生成したドラフトで、確定判断ではない）",
           f"- 再開: {'対応' if result['resumable'] else '未対応（中断したRunは再開できない）'}", ""]
    out += ["## 前提（提供された情報）", "",
            "- 公開仕様（操作・パス・アクセス条件の条項・返却項目）、アカウントの権限区分、実行範囲と予算。仮説・検査手順・期待値は提供されていない。",
            "- 期待値（『拒否されるべき』等）は、仕様の条項と、観測した所有/共有関係に結び付くものだけを独立した根拠として扱った。", ""]
    out += ["## 所見（根拠付き: 対照を実施し、期待値が仕様に結び付くもの）", ""]
    if not result["findings"]:
        out += ["該当なし（不備が無いことの証明ではない。未検査・未判定の範囲を参照）。", ""]
    groups: dict = {}
    for f in result["findings"]:
        groups.setdefault((f["family"], f["op_id"]), []).append(f)
    for i, ((fam, op), members) in enumerate(groups.items(), 1):
        f = members[0]
        h = by[f["hypothesis_id"]]
        out += [f"### {i}. {_md(f['description'])}", "",
                f"- 種別: `{f['rule_id']}` / 確認状態: `{f['verification_state']}` / 深刻度（型からの見積り）: {f['severity']}",
                f"- 位置: `{_md(f['location'])}`",
                "- 根拠: " + "; ".join(_md(x.get("text") or x.get("what")) + (f"（{x['clause']}）" if x.get("clause") else "")
                                      for x in h["basis"]),
                f"- 事前登録した予測: {_md(h['prediction_if_true'])}（登録seq {h['registered_seq']}・予測ハッシュ `{h['prediction_sha']}`）",
                f"- 反証条件: {_md(h['falsification'])}",
                f"- 観測: probe `{f['probe_exp']}` → HTTP {h['probe_status_code']}。判定理由 `{h['reason']}`"
                + (f"。仕様外の項目: {f['unexpected_fields']}" if f["unexpected_fields"] else ""),
                f"- 対照: `{f['control_exp']}` → {f['control_state']}" if f["control_exp"] else "- 対照: 不要（同じ応答の項目比較で自己完結）",
                "- 再現手順（許可された操作のみ）:"] + [f"  - {_md(x)}" for x in f["repro"]]
        out += ["- 証拠:"] + [f"  - {_ev_line(scan_id, e, root)}" for e in f["evidence_ids"]]
        if len(members) > 1:
            out += [f"- 同じ操作を別ロールでも確認（重複確認。新しい情報ではなく、同じ欠陥の再現）: "
                    + ", ".join(f"`{x['probe_exp']}`" for x in members[1:])]
        missing = f["evidence_missing"]
        out += ["- 証拠充足: " + ("一式あり" if f["evidence_complete"] else "不足あり（不足 %d件）" % missing), ""]
    out += ["## 候補（逸脱は観測したが確定していない）", ""]
    if not result["candidates"]:
        out += ["該当なし。", ""]
    for c in result["candidates"]:
        h = by[c["hypothesis_id"]]
        out += [f"- `{c['hypothesis_id']}`: 理由 `{c['reason']}`（対照 {c['control_state']}）。"
                + (f" 期待値が推定: {_md(c['ungrounded_reason'])}。" if not c["grounded"] else "")
                + " 証拠: " + (", ".join(_ev_line(scan_id, e, root) for e in c["evidence_ids"]) or "なし")]
    out += ["", "## 棄却した仮説（予測が反証され、対照が通ったもの）", ""]
    out += [f"- 件数 {len(result['refuted'])}。例: " + ", ".join(f"`{r['hypothesis_id']}`" for r in result["refuted"][:5])
            if result["refuted"] else "該当なし。", ""]
    out += ["## 検証不能（現在の能力では確認できない）", ""]
    out += [f"- `{u['op_id']}`: {_md(u['reason'])}。必要な能力: {_md(u['needed_capability'])}" for u in result["unverifiable"]] or ["該当なし。"]
    out += ["", "## 未判定・未検査・未解決の観測", ""]
    out += [f"- 未判定 {len(result['undetermined'])}件: " + ", ".join(f"`{u['hypothesis_id']}`({u['reason']})" for u in result["undetermined"][:8])
            if result["undetermined"] else "- 未判定: なし"]
    out += [f"- 未検査 {len(result['not_examined'])}件（理由 `{result['finish_reason']}`）。予算や優先度の都合で調べていない仮説で、問題が無いという意味ではない"]
    out += [f"- 観測できなかった項目: `{_md(u['what'])}`（{_md(u['why'])}）" for u in result["unknowns"]]
    out += ["", "## 研究判断の記録（要約）", "",
            f"- 有効な仮説 {m['hypotheses_valid']}件（却下 {m['hypotheses_rejected']}件）、実験 {m['experiments']}件（うち探索 {m['discovery_experiments']}件）。",
            f"- 対照の実施率 {m['control_rate']}（分母 {m['control_denominator']}）、事前登録の違反 {len(m['prereg_violations'])}件。",
            "- 観測→仮説→登録した予測→計画→Gate判断→操作→結果→状態更新の順序は、ジャーナル（`reports/runs/<run_id>/journal.jsonl`）で追跡できる。",
            "- 優先順位の理由（上位）:"]
    for d in result["decision_log"][:6]:
        out.append("  - " + _md(d.get("purpose")) + (f" `{d['exp_id']}` value={d['value']}" if "exp_id" in d else f"（{_md(d.get('why', ''))}）"))
    out += ["", "## 制約", "",
            "- 仮説の型は開発者が与えた5種類（IDOR/機能レベル認可/未認証/過剰な項目/状態変更の認可）で、型の外の仮説は作れない。",
            "- 同じ欠陥を別ロールで重複して確認するため、リクエストの一部は新しい情報を生まない（redundant confirmations）。",
            "- 深刻度は型からの見積りで、影響の測定ではない。"]
    return "\n".join(out) + "\n"
