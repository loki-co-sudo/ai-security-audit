"""
core/autonomy/lab_report.py — ローカル模擬案件の診断レポート(Markdown)

証拠のない推測を確認済みの事実として書かない。各所見は「どの固定テスト操作で・何を観測し・期待値とどう違ったか」を
証拠IDとハッシュ検証結果つきで示す。深刻度は案件設定の事前評価(severity_hint)であり、影響の実測ではないと明記する。
外部サービスへの提出機能は持たない(ファイルを書くだけ)。応答本文は載せない(証拠ファイル側にマスク済みで保存)。
"""
from __future__ import annotations
import os

from core.autonomy.lab_case import LabCase
from core.evidence_store import EVIDENCE_ROOT, inspect_evidence

_STATE_JA = {"completed": "完了", "partial": "一部のみ(未判定・未検査あり)", "failed": "失敗", "cancelled": "中断"}
_HSTATUS_JA = {"supported": "不備を支持する観測あり", "refuted": "期待どおり(全probeが適合)",
               "undetermined": "未判定(通信失敗・期限切れ等)", "partially_tested": "一部のみ検査",
               "untested": "未検査", "unverified_deviation": "逸脱は観測したが対照が未実施(候補)"}


def _md(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_markdown(case: LabCase, result: dict, *, evidence_root: str | None = None) -> str:
    store_root = evidence_root or EVIDENCE_ROOT
    out = [f"# 診断レポート: {case.title}", "",
           f"- 案件ID: `{case.case_id}`(split: {case.split})",
           f"- 実行: run_id=`{result['run_id']}` / 方式: `{result['strategy']}` / 実行状態: "
           f"**{_STATE_JA.get(result['state'], result['state'])}**",
           f"- 終了理由: `{result['end_reason']}`(選択終了: `{result['finish_reason']}`)",
           "- 注意: 本レポートはローカル模擬環境での評価結果であり、実在システムに対する有効性を示すものではない。", ""]
    out += ["## 期待される正常動作(案件設定)", ""] + [f"- {_md(x)}" for x in case.normal_behavior] + [""]
    out += ["## 所見", ""]
    if not result["findings"]:
        out += ["確認できた不備はない(これは不備が無いことの証明ではない。未検査範囲を参照)。", ""]
    for i, f in enumerate(result["findings"], 1):
        feat = case.features[f["feature"]]["title"]
        out += [f"### {i}. {_md(f['description'])}", "",
                f"- 案件ID: `{case.case_id}` / 対象機能: {_md(feat)} / 種別: `{f['rule_id']}`",
                f"- 確認状態: `{f['verification_state']}`"
                + ("(複数のprobeまたは対照の適合で裏付け)" if f["verification_state"] == "corroborated"
                   else "(単独の機械的観測。人による確認は未実施)"),
                f"- 深刻度: {f['severity']}(案件設定の事前評価であり、実際の影響の測定ではない)", ""]
        out += ["**使用した固定テスト操作**", ""]
        for tid in f["test_ids"] + f["control_test_ids"]:
            t = case.tests[tid]
            r = result["tests"][tid]
            out.append(f"- `{tid}`({ {'control': '対照', 'navigation': 'ナビゲーション'}.get(t.kind, 'probe') }): {_md(t.purpose)} → "
                       f"結果 `{r['outcome']}` / HTTP {r['status_code']}")
        out += ["", "**再現手順**", ""] + [f"1. {_md(x)}" for x in f["repro"]]
        out += ["", "**観測内容と期待される正常動作との差**", ""]
        for tid, diffs in f["diffs"].items():
            out += [f"- `{tid}`: " + _md("; ".join(diffs))]
        out += ["", "**確認できた影響**", "",
                "- 期待される正常動作(拒否・非露出など)に反する応答が、登録済みの固定テスト操作で観測された。"
                "それ以上の影響(実データ漏えいの範囲など)は測定していない。", "", "**証拠**", ""]
        if not f["evidence_complete"]:
            miss = ", ".join(f"`{t}`" for t in f.get("evidence_missing_test_ids", []))
            out.append("- 証拠が不足している(保存の省略・失敗" + (f"。保存証拠が無いテスト: {miss}" if miss else "")
                       + ")。観測は保持するが、第三者が保存証拠だけで再検証できない。確認済みとして扱わないこと。")
        for lim in f.get("observation_limits", []):
            out.append(f"- 制約: `{lim['test_id']}` の応答本文が不完全({lim['reason']})。読めた範囲の観測であり、本文依存の判定は完全な本文を見ていない。")
        for eid in f["evidence_ids"]:
            chk = inspect_evidence(store_root, result["scan_id"], eid)
            out.append(f"- `{eid}`: 保存物の整合性={chk['integrity']} / 取得内容の完全性={chk['completeness']}"
                       + ("(ハッシュ一致は保存後に変更が無いことだけを示す。取得内容は一部のみ)" if chk["completeness"] == "truncated" else ""))
        out += ["", f"**改善案**: {_md(f['remediation'])}", ""]
    if result.get("candidates"):
        out += ["## 対照が未実施の逸脱(候補・所見としては確定しない)", "",
                "期待との差は観測したが、探査の信頼性を確かめる対照が未実施のため、不備とは確定していない。"
                "全環境が同じ応答を返す等でも同じ差が出るため、対照を実行してから判断する。", ""]
        for c in result["candidates"]:
            out += [f"- **{_md(c['title'])}**(`{c['hypothesis_id']}` / 対照: {c['control_state']})",
                    f"  - 逸脱したテスト: {', '.join(f'`{t}`' for t in c['test_ids'])} / 未実施の対照: "
                    f"{', '.join(f'`{t}`' for t in c['control_test_ids']) or '-'}"]
            for lim in c.get("observation_limits", []):
                out.append(f"  - 制約: `{lim['test_id']}` の応答本文が不完全({lim['reason']})")
        out.append("")
    if result.get("chains") or result.get("open_chains"):
        out += ["## 連鎖の仮説(小さな不備の組合せ)", "",
                "各メンバーの不備が観測済みであることだけを根拠にした**仮説**で、連鎖そのものは実行・確認していない。"
                "深刻度は規則による見積りで、測定値ではない。", ""]
        for c in result.get("chains", []):
            out += [f"- **{_md(c['title'])}**(見積り: {c['severity']} / 状態: 仮説)",
                    f"  - メンバー: {', '.join(f'`{m}`' for m in c['members'])}",
                    f"  - 理由: {_md(c['rationale'])}", f"  - 改善案: {_md(c['remediation'])}"]
        for c in result.get("open_chains", []):
            miss = "; ".join(f"{t}: {', '.join(hs)}" for t, hs in c["missing"].items())
            out.append(f"- 未完成の連鎖候補: {_md(c['title'])} — 観測済み: {', '.join(c['members_supported'])} / 残りの未判定: {miss}")
        out.append("")
    out += ["## 検証済み・未検証事項", "", "| 仮説 | 状態 | 実行したテスト | 未実行のテスト |", "|---|---|---|---|"]
    for hid, h in result["hypotheses"].items():
        out.append(f"| {_md(h['title'])} | {_HSTATUS_JA.get(h['status'], h['status'])} | "
                   f"{', '.join(h['tests_run']) or '-'} | {', '.join(h['tests_not_run']) or '-'} |")
    out += ["", "## 未検査範囲と終了理由", ""]
    for u in result["untested"]:
        extra = f"(未判定: {', '.join(u['inconclusive'])})" if u["inconclusive"] else ""
        out.append(f"- {_md(u['title'])}: 未実行 {', '.join(u['tests_not_run']) or '-'}{extra}")
    for o in result["out_of_scope"]:
        out.append(f"- 検査対象外: {_md(o['title'])} — {_md(o['reason'])}")
    nr = {t: r for t, r in result["tests"].items() if r["state"] == "not_run"}
    if nr:
        out += ["", "実行しなかったテストと理由:", ""] + [f"- `{t}`: `{r['reason']}`" for t, r in nr.items()]
    out += ["", f"終了理由: `{result['finish_reason']}`。予算: リクエスト {result['budget']['requests_used']}/"
            f"{result['budget']['requests_max']}。未判定・未実施・予算切れは「問題なし」を意味しない。"]
    if result["errors"]:
        out += ["", "実行時の記録:", ""] + [f"- {_md(e)}" for e in result["errors"][:20]]
    return "\n".join(out) + "\n"


def write_report(case: LabCase, result: dict, out_dir: str, *, evidence_root: str | None = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{case.case_id}_{result['strategy']}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(case, result, evidence_root=evidence_root))
    return path
