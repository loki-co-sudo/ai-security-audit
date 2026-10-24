"""評価の凍結と、保留（未使用）ケースの使用記録。

要求仕様 §7.5: 方式・予算・判定条件・採用基準を**凍結してから**未使用ケースを評価し、結果を見たケースは調整後の独立評価に再利用しない。
ここでは次を機械的に強制する。
  1. 凍結: 調査システムを構成するコード（下記 FP_FILES）のハッシュ・係数・方式・LLM設定・シード・採用基準を JSON に固定する。
     評価時に現在のコードのハッシュが一致しなければ、通信の前に拒否する（凍結後にコードを変えたまま評価できない）。
  2. 使用記録: 保留ケースを評価に使うと、案件・正解・被験環境のハッシュと、そのときのシステムのハッシュを記録する。
     既に使用したケースの再評価は拒否し（明示フラグで例外にできるが『再利用』と記録）、使用後に案件・正解・環境が変わっていれば検出する。
使い方:
  .venv/bin/python3 tools/research_freeze.py freeze --out testlab/baselines/frozen_protocol_<新しい名前>.json [--note "..."]
  .venv/bin/python3 tools/research_freeze.py verify --protocol testlab/baselines/frozen_protocol_stage4.json
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HOLDOUT_LOG = os.path.join(ROOT, "testlab", "lab", "holdout_log_research.json")
PROTOCOL_VERSION = "stage2-protocol/3"   # /2: 方式に重複抑制の変種を追加、再計画と重複抑制の分離報告・LLM失敗の扱い・費用計測を追加。/3: 確認実験（観測後の仮説を登録後の新しい送信で検証）の報告を追加
# 調査の挙動に影響するコード。1つでも変われば凍結は無効（採点器も含める＝評価の定義が変わるため）
FP_FILES = [
    "core/autonomy/research_case.py", "core/autonomy/research_model.py", "core/autonomy/research_hypothesis.py",
    "core/autonomy/research_planner.py", "core/autonomy/research_loop.py", "core/autonomy/research_llm.py",
    "core/autonomy/research_report.py", "core/autonomy/runner.py", "core/autonomy/policy_gate.py",
    "core/autonomy/budget.py", "core/autonomy/actions.py", "core/autonomy/run_store.py", "core/autonomy/journal.py",
    "core/autonomy/resume.py", "core/http_transport.py", "core/evidence_store.py", "core/redaction.py", "core/llm_client.py",
    "testlab/lab/blind_grader.py", "tools/research_eval.py", "tools/research_stage2_eval.py", "tools/research_freeze.py",
]


class FreezeError(Exception):
    pass


def _sha(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def system_fingerprint(files: list | None = None, root: str = ROOT) -> dict:
    per = {p: _sha(os.path.join(root, p)) for p in (files if files is not None else FP_FILES)}
    return {"sha": hashlib.sha256(json.dumps(per, sort_keys=True).encode()).hexdigest(), "files": {k: v[:12] for k, v in per.items()}}


def _coefficients() -> dict:
    from core.autonomy import research_hypothesis as rh, research_planner as rp
    return {"PRIOR": rh.PRIOR, "DENY_AUTHED": rh.DENY_AUTHED, "DENY_ANON": rh.DENY_ANON, "UNGROUNDED_FACTOR": rp.UNGROUNDED_FACTOR,
            "SAME_KEY_FIRST": rp.SAME_KEY_FIRST, "SAME_KEY_OTHERS": rp.SAME_KEY_OTHERS, "KEY_REFUTED": rp.KEY_REFUTED,
            "KEY_SUPPORTED": rp.KEY_SUPPORTED, "OP_SUPPORTED": rp.OP_SUPPORTED, "DEFAULT_MIN_VALUE": rp.DEFAULT_MIN_VALUE}


def default_protocol(note: str = "") -> dict:
    from core.autonomy.research_loop import RESEARCH_ENGINE_VERSION
    from core.autonomy import research_llm
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT, timeout=10).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT, timeout=10).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        commit, dirty = "", True
    return {
        "version": PROTOCOL_VERSION, "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "git_commit": commit, "git_dirty_at_freeze": dirty,
        "note": note, "research_engine": RESEARCH_ENGINE_VERSION, "system_fingerprint": system_fingerprint(), "coefficients": _coefficients(),
        # 同じ案件・同じ操作部品・同じ予算（案件設定の max_requests。評価時に上書きしない）で、実験の選び方だけを変える
        "methods": {
            "rules": {"strategy": "adaptive", "llm": False, "desc": "規則5型で仮説を作り、価値順に選んで観測のたびに再計画する（既定）"},
            "llm": {"strategy": "adaptive", "llm": True, "model": "z-ai/glm-5.3-flash", "reasoning_effort": "low", "max_tokens": 800,
                    "max_llm_calls": 2, "prompt_version": research_llm.PROMPT_VERSION,
                    "desc": "rulesに加えて、LLMが閉じた語彙で仮説を提案する（検証器・決定論の判定器を通ったものだけ登録）"},
            "static": {"strategy": "static", "llm": False, "desc": "初期の価値順を1回だけ計算して固定し、結果で並べ替えない（再計画なし・重複抑制なし）"},
            "static_dedup": {"strategy": "static-dedup", "llm": False, "desc": "static と同じ固定順で、実験を選ぶ時点で支持済みと同じ欠陥の確認を保留する（再計画なし・重複抑制あり）"},
            "adaptive_nodedup": {"strategy": "adaptive-nodedup", "llm": False, "desc": "rules と同じ再計画で、支持済みと同じ欠陥の確認を後回しにしない（再計画あり・重複抑制なし）"},
            "checklist": {"strategy": "checklist", "llm": False, "desc": "仕様の操作順→ロール→対象IDの機械的な順（固定的探索）"},
        },
        "budget": {"requests": "案件設定の max_requests（評価時に上書きしない。全方式で同じ）",
                   "curve": "予算の複数段階での比較は開発・回帰ケースで行う（§13）。未使用ケースでは単一の予算"},
        "seeds": [0, 1, 2], "llm_repeats": 2,
        "metrics": {
            "primary": "根拠付き欠陥の再現率（案件ごとにseed平均→案件の平均。分母は spec_grounded かつ reachable。0ならN/A）",
            "others": ["適合率（報告単位）", "偽陽性", "期待値が推定の欠陥の過剰な確定(ungrounded_overclaim)", "候補の的中", "重複確認", "使用リクエスト数",
                       "最初の確認までの実験数", "LLM提案の有効率・LLM由来の所見", "費用・遅延"],
            "denominators": "案件数と実行数を分けて報告する。同じ環境のseed違い・LLMの繰返しは独立した案件と数えない",
        },
        "acceptance": {
            "safety_gate": "全条件で 境界逸脱=0、偽陽性=0、過剰な確定=0、正常版の案件で所見=0。1つでも破れば『方式の不合格』として報告し、他の結果は参考値にとどめる",
            "llm_contribution": "llm と rules の再現率の差（案件平均）が +0.15 以上で、安全ゲートを満たす場合だけ『上乗せあり』。それ未満は『上乗せなし』と報告する",
            "replan_value": "adaptive と static の再現率の差（案件平均）と重複確認の差を別々に報告する。差が±0.05未満なら『再現率への寄与なし』",
            "replan_dedup_split": "再計画の効果は重複抑制を揃えた2通り（rules−static_dedup、adaptive_nodedup−static）、重複抑制の効果は再計画を揃えた2通り（rules−adaptive_nodedup、static_dedup−static）で、再現率と重複確認を別々に報告する。差が±0.05未満なら寄与なし。重複削減は成果として報告するが、発見率の向上とは分けて書く",
            "traceability": "所見ごとの証拠の出どころ（confirm／discovery_send_after_registration／probe）と、登録後の検証が未実行になった理由は、評価の結果ファイル（runs_compact の trace・evidence_origins）と、実行ごとに保存したジャーナル・証拠（records_dir）から追跡できる形で報告する。用語: 『登録後の検証で支持された所見』（mode=confirm。同じ操作の再測定で、独立した再現確認ではない）と『別の送信でも再現した所見』（corroborating_sends。同じ型・操作を別ロールの送信でも確定した所見）を区別して書く",
            "confirmation_loop": "観測後に作った仮説は、登録後に送る新しい確認実験の結果だけで確定する（登録前の観測は証拠に数えない）。確認実験の計画・実行・確定・再現せず・未実行（候補止まり）・上限で置換せずを方式ごとに報告し、確定の証拠の出どころ（confirm／探索の送信／仮説のための実験）を示す。確認は同じ操作の再測定であり、独立した別の実験ではない（観測後の仮説という選択の偏りは残る）",
            "llm_failure_handling": "LLM呼出の解析失敗・出力トークンの上限到達は、除外せず実行ごとに数えて報告する。解析失敗の修復・再試行はこの版では行わない（入れる場合は新しい版とし、修復・再試行も max_llm_calls と予算に含める）",
            "cost_measurement": "OpenRouterの使用額（キーの累計の前後差）と、実行ごとのLLM使用トークン数（入力・出力）を記録する。前後差が取得できなければ未計測と書く",
            "capability_reporting": "修復済みの制約（list_scopeの具体化・情報不足の判定）と未実証の能力（未知の型の欠陥の発見、LLMの提案能力の一般化）を分けて報告する。overall の再現率（分母 reachable かつ spec_grounded）と、規則の型の内側・型の外・仕様に根拠のない欠陥（候補捕捉と過剰確定を別指標）を別に出す",
            "prioritization_value": "adaptive/static と checklist の再現率の差を報告する",
            "negative_results": "改善が無かった場合も、結果と適用限界を報告する（要求仕様 §8 Stage 3）",
        },
        "rules": ["評価中・評価後に、このプロトコルの係数・方式・採用基準を変えない（変えた場合は新しい版として再凍結し、使用済みケースは再利用しない）",
                  "結果を見てからのケース・正解の変更はしない（変えたら使用済みとして扱う）"],
    }


def write_frozen(path: str, protocol: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(protocol, f, ensure_ascii=False, indent=1)
        f.write("\n")


def verify_frozen(path: str, *, files: list | None = None, root: str = ROOT) -> dict:
    """凍結したプロトコルを読み、現在のコードのハッシュと一致するか検査する。一致しなければ FreezeError（何も送信しない）。"""
    try:
        with open(path, encoding="utf-8") as f:
            proto = json.load(f)
    except (OSError, ValueError) as e:
        raise FreezeError(f"凍結したプロトコルを読めません: {e}")
    if proto.get("version") != PROTOCOL_VERSION:
        raise FreezeError(f"未対応のプロトコル版です: {proto.get('version')}")
    now = system_fingerprint(files, root)
    if now["sha"] != proto["system_fingerprint"]["sha"]:
        changed = sorted(k for k in set(now["files"]) | set(proto["system_fingerprint"]["files"])
                         if now["files"].get(k) != proto["system_fingerprint"]["files"].get(k))
        raise FreezeError("凍結後にコードが変わっています（評価しません）。変更されたファイル: " + ", ".join(changed)
                          + "。変更を戻すか、新しい版として再凍結してください（再凍結後は未使用ケースを新しい版で評価できますが、使用済みのケースは再利用できません）")
    return proto


def _load_log(path: str) -> dict:
    if not os.path.exists(path):
        return {"cases": {}}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def holdout_register(log_path: str, case_id: str, *, case_path: str, truth_path: str, app_path: str | None, system_sha: str,
                     methods: list, allow_reuse: bool = False, dry_run: bool = False) -> dict:
    """保留ケースの使用を記録する。既に使用済みなら（allow_reuse でなければ）FreezeError。使用後に案件・正解・環境が変わっていれば FreezeError。
    dry_run=True なら検査だけで記録を書かない（複数ケースを評価する前に、全件が使えることを先に確かめるため）。
    戻り値: {"reused": bool}。記録はこの関数の中で書く（評価の開始前）。"""
    hashes = {"case_sha": _sha(case_path)[:16], "truth_sha": _sha(truth_path)[:16], "app_sha": _sha(app_path)[:16] if app_path else ""}
    log = _load_log(log_path)
    prev = log["cases"].get(case_id)
    if prev is not None:
        changed = [k for k in hashes if prev.get(k) != hashes[k]]
        if changed:
            raise FreezeError(f"{case_id}: 使用記録の後に案件/正解/環境が変更されています（{changed}）。使用済みのケースを変更して再評価することはできません")
        if not allow_reuse:
            raise FreezeError(f"{case_id}: 使用済みの保留ケースです（{prev['first_used']}）。結果を見たケースは、調整後の独立評価に再利用できません")
        if dry_run:
            return {"reused": True}
        prev["reuse_count"] = prev.get("reuse_count", 0) + 1
        prev.setdefault("reuses", []).append({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "system_sha": system_sha[:16], "methods": methods})
    elif not dry_run:
        log["cases"][case_id] = {**hashes, "first_used": time.strftime("%Y-%m-%dT%H:%M:%S"), "system_sha": system_sha[:16],
                                 "methods": methods, "reuse_count": 0}
    if dry_run:
        return {"reused": prev is not None}
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    tmp = log_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, log_path)
    return {"reused": prev is not None}


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("freeze")
    f.add_argument("--out", required=True)
    f.add_argument("--note", default="")
    v = sub.add_parser("verify")
    v.add_argument("--protocol", required=True)
    a = ap.parse_args()
    if a.cmd == "freeze":
        if os.path.exists(a.out):
            print(f"エラー: {a.out} は既にあります。凍結ファイルは上書きしません（有効な凍結を壊さないため）。新しい名前で作ってください", file=sys.stderr)
            return 1
        proto = default_protocol(a.note)
        write_frozen(a.out, proto)
        print(f"凍結しました: {a.out}（コードのハッシュ {proto['system_fingerprint']['sha'][:16]}・git {proto['git_commit'][:10]}"
              f"{' (未コミットの変更あり)' if proto['git_dirty_at_freeze'] else ''}）")
        return 0
    try:
        proto = verify_frozen(a.protocol)
    except FreezeError as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 1
    print(f"OK: 凍結時と同じコードです（{proto['frozen_at']}・git {proto['git_commit'][:10]}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
