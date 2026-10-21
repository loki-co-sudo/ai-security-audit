"""
agents/base_agent.py — エージェント抽象基底クラス
"""

from __future__ import annotations
import json
import os
import re
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from core.event_bus import EventBus
import core.event_bus as ev
import core.config as config
from core.llm_client import LLMClient
from core.model_router import build_fast_client, fast_signature, current_effort
from core.scope_guard import in_scope
from core.findings import (
    ScanState, VerificationState, Finding, CoverageItem, ScanResult, new_scan_result, new_id,
)

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# 品質エフォート時の検証パス（強モデルによる敵対的レビュー）のシステムプロンプト。
# lokicode agent-v3 の「強い検証器（賢さの壁）」を移植: 別モデルの微妙な誤りを
# 拾うため、量産ではなく最終の批判役として STRONG モデルで実行する。
_VERIFY_SYS = """You are a senior application-security reviewer performing an adversarial QA \
pass over another analyst's draft findings from an AUTHORIZED assessment. Your job is to raise \
precision, not to re-do the whole analysis.

Do the following:
1. Remove or downgrade findings that are false positives or overclaims not supported by the evidence.
2. Correct wrong severities and CWE ids.
3. Add any clearly-missed CRITICAL or HIGH issue that the provided evidence plainly supports.
4. Keep only findings a competent operator would act on.

CRITICAL OUTPUT RULE: reproduce the FULL corrected set of findings using the EXACT same marker \
format as the draft (e.g. ---VULN_START---/---VULN_END--- or ---FINDING_START---/---FINDING_END---), \
so a downstream parser still works. Do not add commentary outside the markers. If nothing is \
credible, say so plainly with no markers."""


def _count_severities(text: str) -> dict:
    """ストリーミング中テキストから深刻度を集計する。"""
    return {s: len(re.findall(rf"SEVERITY:\s*{s}\b", text, re.I)) for s in _SEVERITIES}


# ─── 検証器アンサンブル（judge ensembling） ───────────────────
# AGENT_ARCHITECTURE.md §5.3。品質エフォート時、検証パスを独立に複数回走らせ、
# マーカー単位（NAME/TITLE + LINES の組）の過半数一致で採用する所見を決める。
_MARKER_RE = re.compile(r"---(VULN|FINDING)_START---(.*?)---\1_END---", re.S)


def _parse_marker_findings(text: str) -> list[tuple[str, str]]:
    """マーカー形式の所見を (signature, 完全なブロック文字列) のリストとして抽出する。

    signature は NAME/TITLE + LINES から作る大まかな識別子（同一所見の再現判定に使う。
    audit/fuzz は `NAME:`+`LINES:`、recon（攻撃仮説）は `TITLE:`（LINESなし）を使うため両対応する）。
    このマッチングは完全一致ベースであり、独立したLLM呼び出しの文言差（例:
    「SQL Injection in login」↔「SQL injection via username param」）を吸収できない粗い近似に
    過ぎない — 一致しなかった所見は「誤り」ではなく「比較不能」であり、呼び出し側
    （_verify_findings）は最終結果から所見を消さず、必ず含めた上で人間に可視化すること。
    """
    out: list[tuple[str, str]] = []
    for m in _MARKER_RE.finditer(text):
        marker_type, body = m.group(1), m.group(2)
        name_m = re.search(r"(?:NAME|TITLE):\s*(.+)", body)
        lines_m = re.search(r"LINES:\s*(.+)", body)
        name = name_m.group(1).strip().lower() if name_m else ""
        lines = lines_m.group(1).strip() if lines_m else ""
        signature = f"{name}|{lines}" if (name or lines) else body.strip()[:120]
        out.append((signature, f"---{marker_type}_START---{body}---{marker_type}_END---"))
    return out


def _tag_minority(block: str) -> str:
    """所見ブロックの先頭マーカー直後に CONFIDENCE 行を挿入する（過半数不一致の少数意見マーク）。"""
    return re.sub(r"(---(?:VULN|FINDING)_START---)", r"\1\nCONFIDENCE: ENSEMBLE_MINORITY", block, count=1)


def _vote_findings(samples: list[str]) -> tuple[str, list[str]]:
    """複数の検証結果から全所見を採用する（マーカー単位のunion方式）。

    過半数のサンプルに登場した所見はそのまま、過半数に届かなかった所見は
    `CONFIDENCE: ENSEMBLE_MINORITY` を付記した上で、どちらも最終結果に含める。
    以前は過半数に届かない所見を最終レポートから除外していたが、これは
    `_parse_marker_findings` 自身が明言する「除外＝誤検知の確定ではない・サイレントに
    消さない」という方針と矛盾していた。加えて quality effort の既定値
    `verify_samples=2` では、旧方式の閾値（過半数=2）が実質「全会一致必須」と等価になり、
    2回中1回しか検出されなかった所見（見逃し防止の観点で本来一番拾いたいケース）が
    機械的に落ちる設計不備だったため、union方式に変更した（advisorレビュー指摘）。

    戻り値は (全所見を含む結合文字列, 少数意見としてタグ付けした所見ブロックのリスト)。
    後者は呼び出し側が「こういう所見も参考として載っています」と案内するための情報であり、
    最終結果からの除外リストではない（前者にも同じブロックが含まれる）。
    シグネチャ一致は粗い近似（_parse_marker_findings 参照）のため、少数意見＝誤検知の
    確定でもない。マーカー付き所見が1件も取れなければ、最初のサンプルをそのまま返す。
    """
    threshold = len(samples) // 2 + 1
    counts: dict[str, int] = {}
    representative: dict[str, str] = {}
    order: list[str] = []
    for sample in samples:
        seen_in_sample: set[str] = set()
        for signature, block in _parse_marker_findings(sample):
            if signature not in seen_in_sample:
                counts[signature] = counts.get(signature, 0) + 1
                seen_in_sample.add(signature)
            representative.setdefault(signature, block)
            if signature not in order:
                order.append(signature)
    if not order:
        return samples[0], []
    kept_blocks: list[str] = []
    minority: list[str] = []
    for sig in order:
        block = representative[sig]
        if counts.get(sig, 0) >= threshold:
            kept_blocks.append(block)
        else:
            tagged = _tag_minority(block)
            kept_blocks.append(tagged)
            minority.append(tagged)
    return "\n\n".join(kept_blocks), minority

# レポート/分析の出力言語をLLMに指示するディレクティブ。
# 設定 (report_lang) に応じて全エージェントの system プロンプトへ自動付与する。
_LANG_DIRECTIVE = {
    "ja": "\n\n# 出力言語\nすべての分析・説明・レポート本文は日本語で記述してください。"
          "コード・識別子・技術用語・固有名詞は原語のままで構いません。",
    "en": "\n\n# Output language\nWrite all analysis, explanations and report content in English. "
          "Keep code, identifiers, technical terms and proper nouns in their original form.",
}


class BaseAgent(ABC):
    """全エージェントが継承する基底クラス。"""

    def __init__(self, bus: EventBus, llm: LLMClient):
        self.bus  = bus
        self.llm  = llm
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._effort_override: str | None = None
        self._result_finalized = False
        self._last_scan_result = None
        self._current_mode = ""
        self._current_target = ""
        self._scan_id: str | None = None
        # 任意: LLM呼出前の予算ゲート(core.autonomy.budget.LLMGate)。未設定なら従来どおり無制限。
        self._llm_gate = None
        self._llm_denials: list[str] = []   # 予算で拒否した呼出の理由コード(Runnerが最終結果へ反映する)

    # ── ライフサイクル ─────────────────────────────────────
    def start(self, **kwargs) -> None:
        """バックグラウンドスレッドで run() を起動する。"""
        self._stop_event.clear()
        self._result_finalized = False
        self._last_scan_result = None
        self._scan_id = None
        self._thread = threading.Thread(
            target=self._safe_run,
            kwargs=kwargs,
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """停止シグナルを送信する。run() 内で is_stopped() を確認して終了する。"""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def _safe_run(self, **kwargs) -> None:
        try:
            self.run(**kwargs)
        except Exception as e:
            self._log(f"[AGENT ERROR] {e}")
            self._finalize(state=ScanState.FAILED.value, errors=[str(e)])
            return
        if not self._result_finalized:
            # run()が_finalize()（_done()経由含む）を呼ばずに終了した経路。
            # 主にSTOPによる早期return（既存コードの多数の`if self.is_stopped(): return`が
            # bus.done()を呼んでいなかったため、GUIのボタンが再有効化されないまま
            # 残るバグがあった。ここで一度だけ確実に最終化する（P1.1）。
            state = ScanState.CANCELLED.value if self.is_stopped() else ScanState.COMPLETED.value
            self._finalize(state=state)

    @abstractmethod
    def run(self, **kwargs) -> None:
        """サブクラスが実装するメイン処理。バックグラウンドスレッドで実行される。"""

    def _begin_scan(self) -> str:
        """スキャンIDを確定する（P1.2）。

        run()冒頭（_current_mode/_current_target設定直後）で呼ぶと、証拠保存
        （core/evidence_store.EvidenceStore）等がfinalize前からscan_idを参照できる。
        呼ばない場合は_finalize()が初回確定時に新規生成する（後方互換・呼び出し必須ではない）。
        """
        if self._scan_id is None:
            self._scan_id = new_id("scan")
        return self._scan_id

    def _finalize(self, *, state: str, errors: list[str] | None = None,
                  findings: list[Finding] | None = None,
                  coverage: list[CoverageItem] | None = None,
                  mode: str = "", target: str = "",
                  engagement_id: str = "default") -> ScanResult:
        """最終ScanResultを確定しRESULT→DONEの順で一度だけ送出する（P1.1）。

        例外・STOP・早期return・正常終了のすべての経路が最終的にここへ集約される
        （_safe_run参照）。2回目以降の呼び出しは無視し、最初の確定結果を返す
        （DONEを一度だけ送る契約を、個々のエージェントが意識せず満たせるようにする）。
        findings/coverageを渡さない（未移行の）エージェントは空リストのまま確定する
        ——これは「検出0件」ではなくデータ未提供を意味する。呼び出し側
        （report_generator等）は移行済みかどうかをschema_versionやfindings空リスト
        単独で判定しないこと。
        """
        if self._result_finalized:
            return self._last_scan_result
        self._result_finalized = True
        sr = new_scan_result(
            mode=mode or self._current_mode,
            target=target or self._current_target,
            engagement_id=engagement_id,
        )
        if self._scan_id:
            sr.scan_id = self._scan_id  # _begin_scan()で先に確定済みならそれを使う(P1.2)
        sr.state = state
        sr.errors = list(errors or [])
        sr.findings = list(findings or [])
        sr.coverage = list(coverage or [])
        sr.model = getattr(self.llm, "model", "") or ""
        self._last_scan_result = sr
        self.bus.result(sr.to_dict())
        # completed以外（partial/failed/cancelled）は成功扱いにしない。
        self.bus.done(error=(state != ScanState.COMPLETED.value))
        return sr

    # ── Event Bus ヘルパー ─────────────────────────────────
    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.bus.log(f"[{ts}] {msg}")

    def _out(self, text: str, tag: str = "") -> None:
        self.bus.output(text, tag)

    def _step(self, idx: int, state: str) -> None:
        self.bus.step(idx, state)

    def _status(self, msg: str) -> None:
        self.bus.status(msg)

    def _alert(self, severity: str, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.bus.alert(severity, message, ts)

    def _stats(self, counts: dict) -> None:
        self.bus.stats(counts)

    def _done(self, error: bool = False) -> None:
        """従来の完了通知ヘルパー。内部で_finalize()によるRESULT確定を伴う（P1.1）。

        findings/coverageを渡さない移行前のエージェントでも、DONEを一度だけ・
        RESULT確定後に送る契約は自動的に満たされる（2回目以降の呼び出しは無視される）。
        """
        self._finalize(state=ScanState.FAILED.value if error else ScanState.COMPLETED.value)

    # ── スコープガード（バグバウンティ対応・BOUNTY_ROADMAP.md Phase A） ──
    def _check_scope(self, target: str) -> bool:
        """範囲外なら scope_mode に応じて警告 or ブロックする。呼び出し元は
        False が返ったら即 return すること（block時は_finalize()によるRESULT/DONE確定済み）。

        allowed_targets が空（既定）なら常に True（後方互換・全対象許可）。
        """
        allowed = config.get("allowed_targets") or []
        ok, msg = in_scope(target, allowed)
        if ok:
            return True
        mode = config.get("scope_mode", "warn")
        if mode == "block":
            self._out(f"\n[ SCOPE BLOCK ] {msg}（scope_mode=block のため実行を中止しました）\n",
                      "critical")
            self._log(f"Scope block: {msg}")
            self._finalize(state=ScanState.FAILED.value, errors=[msg], target=target)
            return False
        self._out(f"\n[ SCOPE WARNING ] {msg}（scope_mode=warn のため続行します）\n", "high")
        self._log(f"Scope warning: {msg}")
        return True

    # ── LLM ヘルパー ──────────────────────────────────────
    @staticmethod
    def _apply_language(messages: list[dict]) -> list[dict]:
        """設定の report_lang に応じて system プロンプトへ言語指示を付与する。"""
        directive = _LANG_DIRECTIVE.get(config.get("report_lang", "ja"))
        if not directive:
            return messages
        out = [dict(m) for m in messages]
        for m in out:
            if m.get("role") == "system":
                m["content"] = (m.get("content", "") or "") + directive
                return out
        out.insert(0, {"role": "system", "content": directive.strip()})
        return out

    def _stream_llm(self, messages: list[dict], live_stats: bool = False) -> str:
        """LLMをストリーミングし、各チャンクを OUTPUT イベントで流す。

        live_stats=True のとき、累積テキストから深刻度を逐次集計し、変化したら
        STATS イベントを送る（DETECTION SUMMARY のリアルタイム更新）。
        """
        acc = {"text": "", "last": None}

        def _chunk(chunk: str) -> None:
            self._out(chunk)
            if live_stats:
                acc["text"] += chunk
                counts = _count_severities(acc["text"])
                if counts != acc["last"]:
                    acc["last"] = counts
                    self._stats(counts)

        msgs = self._apply_language(messages)
        if not self._llm_permitted(msgs, "strong"):
            return ""
        kwargs = self._llm_call_kwargs()
        text = self.llm.stream(
            messages=msgs,
            on_chunk=_chunk,
            on_error=lambda e: self._out(f"\n[ LLM ERROR ] {e}\n", "critical"),
            **kwargs,
        )
        if self._llm_gate is not None:
            self._llm_gate.after_call(None)   # ストリーミングは使用量を取得しない(不明として数える)
        return text

    # ── LLM予算ゲート(任意・呼出前に制限する) ─────────────────
    def _llm_permitted(self, messages: list[dict], role: str) -> bool:
        gate = self._llm_gate
        if gate is None:
            return True
        decision = gate.before_call(messages, role)
        if decision.ok:
            return True
        self._llm_denials.append(decision.reason)
        self._log(f"LLM呼出を予算により拒否: {decision.reason}")
        self._out(f"\n[ LLM BUDGET ] 呼出を拒否しました: {decision.reason}\n", "high")
        return False

    def _llm_call_kwargs(self) -> dict:
        gate = self._llm_gate
        mt = getattr(gate, "max_output_tokens", None) if gate is not None else None
        return {} if mt is None else {"max_tokens": mt}

    def _fast_client(self) -> LLMClient:
        """FAST（廉価）モデルのクライアントを返す。未設定なら STRONG を共用する。

        設定が変わったら再生成する（設定ホットリロードに追従）。FAST が未設定なら
        self.llm（STRONG）をそのまま返すため、単一モデル時と同一挙動になる。
        """
        sig = fast_signature(self.llm)
        if getattr(self, "_fast_sig", None) != sig:
            self._fast = build_fast_client(self.llm)
            self._fast_sig = sig
        return self._fast

    def _complete_llm(self, messages: list[dict], role: str = "fast") -> str:
        """LLMを非ストリーミングで呼び出す（短い補助的な推論に使用）。

        role="fast"（既定）は機械的・量の出る生成に FAST モデルを使う。
        role="strong" を明示すると STRONG モデルを使う。
        """
        client = self._fast_client() if role == "fast" else self.llm
        msgs = self._apply_language(messages)
        if not self._llm_permitted(msgs, role):
            return ""
        kwargs = self._llm_call_kwargs()
        usage: dict = {}
        if self._llm_gate is not None:
            kwargs["usage_out"] = usage
        try:
            text = client.complete(msgs, **kwargs)
        except Exception as e:
            self._log(f"LLM error: {e}")
            if self._llm_gate is not None:
                self._llm_gate.after_call(None)
            return ""
        if self._llm_gate is not None:
            self._llm_gate.after_call(usage or None)
        return text

    # ── 推論エフォート ────────────────────────────────────
    def set_effort_override(self, level: str | None) -> None:
        """難易度ルーター（AUTO）による一時的なエフォート上書き。Noneでグローバル設定に戻す。

        config.effort（グローバル設定）は変更しない。1回のrun()にのみ影響する。
        """
        self._effort_override = level

    def _effort(self) -> dict:
        """現在の推論エフォート（速度/バランス/品質）のプリセット dict を返す。

        set_effort_override() で上書きされていればそちらを優先する。
        """
        return current_effort(self._effort_override)

    def _verify_findings(self, evidence: str, draft: str, samples: int = 1) -> str:
        """品質エフォート時、STRONG モデルで所見を敵対的に再検証し誤検知を削減する。

        samples>1（検証器アンサンブル・§5.3）のときは検証パスを独立に複数回走らせ、
        マーカー単位（NAME/TITLE+LINES）でunion方式により全所見を採用する（_vote_findings）。
        一致判定は文言差を吸収できない粗い近似のため、過半数に届かなかった所見も
        「誤検知と確定」はせず、`CONFIDENCE: ENSEMBLE_MINORITY` を付記した上で戻り値
        （＝最終レポートに載る内容）にそのまま含める（除外はしない。少数意見であることは
        出力ボックスとレポートの両方で人間が確認できる）。
        検証後の全所見（マーカー形式）を返す。マーカーが失われた場合はドラフトを維持する。
        """
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out("  VERIFICATION PASS — 強モデルによる批判的レビュー (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        results: list[str] = []
        for i in range(max(1, samples)):
            if samples > 1:
                self._status(f"AI が所見を再検証中（誤検知の除去・アンサンブル {i + 1}/{samples}回目）...")
                if i > 0:
                    self._out(f"\n  ── アンサンブル検証 {i + 1}/{samples} 回目 ──\n\n", "dim")
            else:
                self._status("AI が所見を再検証中（誤検知の除去）...")
            verified = self._stream_llm([
                self.llm.system(_VERIFY_SYS),
                self.llm.user(
                    "Review and finalize these draft findings. Reproduce the full corrected set "
                    "in the same marker format.\n\n"
                    f"EVIDENCE / CONTEXT:\n{evidence}\n\n"
                    f"DRAFT FINDINGS:\n{draft}"
                ),
            ], live_stats=True)
            # マーカーが1つも無ければそのサンプルは解析不能とみなし多数決から除外する。
            if "_START---" in verified:
                results.append(verified)
        if not results:
            return draft
        if len(results) == 1:
            return results[0]
        self._out("\n\n" + "─" * 56 + "\n", "sep")
        self._out(f"  ENSEMBLE VOTE — {len(results)}回の検証結果を統合（全所見を採用）\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        kept, minority = _vote_findings(results)
        if minority:
            self._out(
                f"\n  ℹ 過半数一致に届かなかった所見 {len(minority)}件\n"
                f"    （文言差により別所見と判定された可能性あり。誤検知と断定はできないため "
                f"CONFIDENCE: ENSEMBLE_MINORITY として本文にも含めています — 除外はしません）:\n\n",
                "high",
            )
            self._out("\n\n".join(minority) + "\n", "dim")
        return kept

    # ── 構造化所見への変換（P1.1/P1.2） ────────────────────
    @staticmethod
    def _findings_from_markers(parsed: list[dict], corroborated: bool,
                               known_evidence_ids: set[str] | None = None,
                               rejected_evidence_ids: list[str] | None = None) -> list[Finding]:
        """`tools.report_generator._findings_and_counts()`が返す辞書列をFindingへ変換する
        共通ヘルパー。NAME/SEVERITY/CWE/LINES/FIXマーカー形式（---VULN_START---等）を
        前提とするため、DEFENSE MODEのTHREAT形式など異なるスキーマは個別に変換すること。

        品質エフォートの検証パス（`_verify_findings`）を通過した所見のみ
        verification_state="corroborated"とし、アンサンブル少数意見(ENSEMBLE_MINORITY)は
        LLMの同意だけで昇格させず"observed"のまま残す。

        `known_evidence_ids`（P1.2）が渡された場合、LLM出力の`EVIDENCE_IDS:`行を
        カンマ/空白区切りで解釈し、この集合に存在するIDのみ`Finding.evidence_ids`へ
        採用する。存在しないID（LLMの誤記・幻覚）は黙って除外する（採用しない）。
        これは証拠の紐付けが正しいという意味論的な保証ではない —
        LLMが実際に対応する証拠を正しく引用したかどうかまでは検証できない。
        `rejected_evidence_ids`（任意のlist）が渡された場合、除外したIDの説明をそこへ追加する
        （呼び出し側がScanResult.errorsへ反映する）。
        `known_evidence_ids`がNoneの場合（save_evidence未対応/無効の呼び出し元）は
        EVIDENCE_IDS行自体を無視する（空リストのまま）。
        """
        out: list[Finding] = []
        for f in parsed:
            is_minority = f.get("confidence") == "ENSEMBLE_MINORITY"
            vstate = (VerificationState.CORROBORATED.value if (corroborated and not is_minority)
                      else VerificationState.OBSERVED.value)
            evidence_ids: list[str] = []
            if known_evidence_ids:
                raw = f.get("evidence_ids_raw") or ""
                candidates = [c.strip() for c in re.split(r"[,\s]+", raw) if c.strip()]
                evidence_ids = [c for c in candidates if c in known_evidence_ids]
                if rejected_evidence_ids is not None:
                    # 存在しないID(LLMの誤記・幻覚)を黙って捨てず、validation errorとして残す
                    rejected_evidence_ids.extend(
                        f"未知の証拠IDを除外: {c}（所見: {f.get('name') or 'unnamed'}）"
                        for c in candidates if c not in known_evidence_ids)
            out.append(Finding(
                finding_id=new_id("finding"),
                rule_id=f.get("ref") or "UNSPECIFIED",
                location=f.get("lines") or "",
                severity=(f.get("severity") or "LOW").upper(),
                verification_state=vstate,
                description=f.get("name") or "",
                remediation=f.get("fix") or "",
                snippet=f.get("snippet") or "",
                analysis=f.get("attack") or "",
                verifier_support={"ensemble_minority": True} if is_minority else {},
                evidence_ids=evidence_ids,
            ))
        return out

    # ── モデル別コスト×精度台帳（§5.4・記録のみ） ──────────
    def _record_telemetry(self, mode: str, target: str, detections: dict, elapsed: float) -> None:
        """スキャンごとに (model, 検出数, 所要時間) を reports/telemetry.jsonl へ追記する。

        AGENT_ARCHITECTURE.md §5.4「モデル別コスト×精度台帳」の第一段階（まずは記録だけ）。
        コスパ最良モデルの提案などの分析機能は将来実装。書き込み失敗は握りつぶし本処理を止めない。
        """
        try:
            os.makedirs("reports", exist_ok=True)
            record = {
                "ts": datetime.now().isoformat(timespec="seconds"),
                "mode": mode,
                "target": target,
                "model": self.llm.model,
                "effort": self._effort_override or config.get("effort", "balanced"),
                "detections": dict(detections or {}),
                "total_detections": sum((detections or {}).values()),
                "elapsed_sec": round(elapsed, 1),
            }
            with open(os.path.join("reports", "telemetry.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self._log(f"Telemetry write error: {e}")

    # ── 成果物の保存 ──────────────────────────────────────
    def _save_investigation(self, mode_title: str, target: str, body: str) -> str | None:
        """調査レポートを reports/investigation/ に Markdown 保存する。"""
        from tools import report_generator  # noqa: PLC0415
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            doc = (
                f"# AI Security Audit — {mode_title} Investigation Report\n"
                f"- Target: {target}\n- Date: {ts}\n- Engine: {self.llm.model}\n\n{body}"
            )
            path = report_generator.save_artifact(doc, "investigation", ext="md")
            self._out(f"\n  💾 調査レポートを保存しました: {path}\n", "green")
            self._log(f"Investigation report saved: {path}")
            return path
        except Exception as e:
            self._out(f"\n  [ 保存エラー ] {e}\n", "high")
            self._log(f"Artifact save error: {e}")
            return None

    def _save_poc(self, target: str, exploit_text: str) -> str | None:
        """生成した PoC を reports/poc/ に Markdown 保存する（送信はしない）。"""
        if not exploit_text.strip():
            return None
        from tools import report_generator  # noqa: PLC0415
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            doc = (
                f"# Generated PoC — {target}\n"
                f"- Date: {ts}\n- Engine: {self.llm.model}\n"
                f"- NOTE: これらの PoC はローカル生成のみ。対象へ送信・実行されていません。\n\n"
                f"{exploit_text}\n"
            )
            path = report_generator.save_artifact(doc, "poc", ext="md")
            self._out(f"\n  💾 PoC を保存しました: {path}\n", "green")
            self._log(f"PoC saved: {path}")
            return path
        except Exception as e:
            self._out(f"\n  [ 保存エラー ] {e}\n", "high")
            self._log(f"Artifact save error: {e}")
            return None
