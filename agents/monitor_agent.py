"""
agents/monitor_agent.py — リアルタイム防御監視エージェント

ログファイルを継続監視し、AIが攻撃パターンを検知・分類・解説する。
パターン集約フィルタにより、同一IP/同一シグネチャの連続アラートをN分間隔で集約しLLM呼び出しを削減。
"""

from __future__ import annotations
import re
from urllib.parse import unquote_plus
import time
from datetime import datetime
from collections import deque
from agents.base_agent import BaseAgent
from tools.log_watcher import LogWatcher, normalize_log_line
from tools.report_generator import _findings_and_counts
import core.config as config
from core import redaction
from core.evidence_store import EvidenceStore
from core.findings import CoverageItem, ScanState, CoverageStatus
from core.settings import (
    ATTACK_PATTERNS, LOG_BATCH_SIZE, LOG_MAX_CONTEXT,
    LOG_WATCH_INTERVAL,
)

SYSTEM_PROMPT = """You are an elite blue team SOC analyst and incident responder. \
You are analyzing real-time log entries for signs of ongoing attacks.

Your task:
1. **Classify the threat** type (SQL Injection, XSS, LFI, RFI, Command Injection, Brute Force, Scanner, APT, etc.)
2. **Assess severity** (CRITICAL if active exploitation, HIGH if probe with high success likelihood, etc.)
3. **Identify attacker TTPs** (Tactics, Techniques, Procedures) using MITRE ATT&CK framework
4. **Timeline the attack** — is this part of a larger campaign?
5. **Suggest immediate defensive actions**

Output format:

---THREAT_START---
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
THREAT_TYPE: [classification]
MITRE_TTP: [ATT&CK technique ID (e.g. T1190) only if you are certain it exists; otherwise N/A — never guess an ID]
ATTACKER_IP: [if identifiable]
TIMELINE: [Is this isolated or part of a sequence?]
ANALYSIS:
[Detailed threat analysis]
IMMEDIATE_ACTIONS:
[Specific steps to take right now]
---THREAT_END---

Be concise but thorough. Flag false positives explicitly."""

_EVIDENCE_INSTRUCTION = """

If (and only if) a suspicious entry carries an "evidence_id" and you rely on it for a threat, \
add this line to that threat's block after ATTACKER_IP:
EVIDENCE_IDS: [comma-separated evidence_id value(s) that support this threat]. \
Only cite evidence_id values that were literally given to you — never invent one. \
An evidence_id only shows that a signature matched that log line; it does not prove the threat."""

# パターン集約フィルタ設定
_AGGREGATION_WINDOW  = 300   # 5分間の集約ウィンドウ（秒）
_IP_PATTERN          = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


_ACCESS_LOG_UA = re.compile(r'"[A-Z]+ [^"]*" \d{3} \S+ "[^"]*" "(?P<ua>[^"]*)"\s*$')


def _decoded_variants(line: str, max_len: int = 8000) -> list[str]:
    """生の行と、URLデコード(+を空白扱い)1回・2回後の行(重複除去)。巨大行は先頭だけをデコードする。"""
    raw = line[:max_len]
    once = unquote_plus(raw)
    twice = unquote_plus(once)
    return list(dict.fromkeys([line, once, twice]))


def _extract_ip(line: str) -> str:
    """ログ行からIPアドレスを抽出する（見つからない場合は空文字）。"""
    m = _IP_PATTERN.search(line)
    return m.group(0) if m else ""


class MonitorAgent(BaseAgent):

    def run(self, log_path: str, watch_mode: bool = True, max_seconds: float | None = None) -> None:
        self._current_mode, self._current_target = "DEFENSE", log_path
        scan_id = self._begin_scan()  # 証拠保存(EvidenceStore)がfinalize前から使うため(P1.2)
        self.bus.clear()
        t0 = time.time()
        deadline = t0 + max_seconds if max_seconds else None
        timed_out = lambda: deadline is not None and time.time() >= deadline  # noqa: E731
        self._status(f"監視開始: {log_path}")

        self._out(
            "╔══════════════════════════════════════════════════════╗\n"
            "║      DEFENSE MODE — AUTONOMOUS THREAT MONITOR        ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n",
            "header",
        )
        self._out(f"  LOG SOURCE : {log_path}\n", "dim")
        self._out(f"  MODE       : {'CONTINUOUS WATCH' if watch_mode and not log_path.lower().endswith('.gz') else 'SINGLE PASS'}\n", "dim")
        self._out(f"  STARTED    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", "dim")

        watcher = LogWatcher(log_path)
        parse_problems: dict[str, int] = {}
        context_buffer: deque[str] = deque(maxlen=LOG_MAX_CONTEXT)
        batch_buffer:   list[str]  = []   # マスク済みの行のみ保持（LLM送信・表示用）
        batch_evidence: list[str | None] = []  # batch_bufferと同順の証拠ID（保存OFF/省略時None）
        # 証拠保存（P1.2・save_evidence設定時のみ。既定OFF）。観測=シグネチャ一致の決定的事実。
        store = EvidenceStore(scan_id) if config.get("save_evidence", False) else None
        known_evidence_ids: set[str] = set()
        analyses:       list[str]  = []   # 調査レポート保存用にAI分析を蓄積
        total_alerts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        last_ai_call   = 0.0
        AI_COOLDOWN    = 15.0  # 連続AI呼び出し間隔（秒）

        # パターン集約フィルタ: (ip, pattern_name) → 最終送信タイムスタンプ
        _agg_last_sent: dict[tuple[str, str], float] = {}

        self._out("─" * 56 + "\n", "sep")
        self._out("  MONITORING STARTED — waiting for log entries ...\n", "section")
        self._out(f"  Pattern aggregation: {_AGGREGATION_WINDOW}s window per (IP, signature)\n", "dim")
        self._out("─" * 56 + "\n\n", "sep")

        try:
            for line in watcher.watch(
                interval=LOG_WATCH_INTERVAL,
                stop_fn=lambda: self.is_stopped() or timed_out(),
                single_pass=not watch_mode,
            ):
                if self.is_stopped() or timed_out():
                    break

                line = line.rstrip()
                if not line:
                    continue
                line, problem = normalize_log_line(line)      # JSONLは平坦化。不正行も捨てず検知へ回す(P4.3)
                if problem:
                    parse_problems[problem] = parse_problems.get(problem, 0) + 1

                # 攻撃パターン検出は生の行で行い、以降の保存・LLM送信・表示にはマスク済みの行のみ使う
                masked_line = redaction.mask_log_line(line)
                context_buffer.append(masked_line)
                matched = self._pattern_match(line)

                if matched:
                    now_ts = time.time()
                    ip = _extract_ip(line)
                    deduped_matches = []
                    for pattern_name in matched:
                        key = (ip, pattern_name)
                        last_sent = _agg_last_sent.get(key, 0.0)
                        if now_ts - last_sent < _AGGREGATION_WINDOW:
                            continue  # 集約: 同一IPの同一パターンはスキップ
                        _agg_last_sent[key] = now_ts
                        deduped_matches.append(pattern_name)

                    if not deduped_matches:
                        continue  # すべて集約済み → スキップ

                    batch_buffer.append(masked_line)
                    eid = None
                    if store is not None:
                        eid = store.save_log_evidence(
                            source=log_path, line=masked_line, patterns=deduped_matches)
                        if eid:
                            known_evidence_ids.add(eid)
                    batch_evidence.append(eid)
                    for pattern_name in deduped_matches:
                        sev = self._quick_severity(pattern_name)
                        msg = f"{pattern_name}: {masked_line[:80]}"
                        # ALERT TIMELINEに送出（DefensePanelのタイムラインに表示）
                        self._alert(sev, msg)
                        # AI出力エリアにも即時表示
                        self._out(
                            f"  [{datetime.now().strftime('%H:%M:%S')}] "
                            f"[{sev:8}] {pattern_name:20} — {masked_line[:80]}\n",
                            sev.lower(),
                        )
                        total_alerts[sev] = total_alerts.get(sev, 0) + 1
                    self._stats(total_alerts)

                # バッチサイズ到達 or タイムアウト → AI分析
                now = time.time()
                if (len(batch_buffer) >= LOG_BATCH_SIZE or
                        (batch_buffer and now - last_ai_call > AI_COOLDOWN)):
                    analyses.append(self._analyze_batch(
                        batch_buffer, list(context_buffer), batch_evidence))
                    batch_buffer.clear()
                    batch_evidence.clear()
                    last_ai_call = now

        except Exception as e:
            watch_error = str(e)
            self._log(f"Monitor error: {e}")
        else:
            watch_error = None

        # 残バッファを最終分析
        if batch_buffer and not self.is_stopped():
            analyses.append(self._analyze_batch(batch_buffer, list(context_buffer), batch_evidence))

        # 調査レポートを保存
        combined_analyses = "\n\n---\n\n".join(a for a in analyses if a)
        body = (
            f"## Log Source\n{log_path}\n\n"
            f"## Alert Summary\n"
            f"- CRITICAL: {total_alerts['CRITICAL']}  /  HIGH: {total_alerts['HIGH']}  /  "
            f"MEDIUM: {total_alerts['MEDIUM']}  /  LOW: {total_alerts['LOW']}\n\n"
            f"## AI Threat Analyses\n"
            + (combined_analyses or "(AI分析は実施されませんでした)")
        )
        self._save_investigation("DEFENSE MODE", log_path, body)

        total = sum(total_alerts.values())
        parsed_findings, counts = _findings_and_counts("DEFENSE MODE", combined_analyses)
        self._record_telemetry("DEFENSE MODE", log_path, total_alerts, time.time() - t0)
        self._out("\n" + "═" * 56 + "\n", "sep")
        self._out(f"  MONITORING ENDED  |  {total} alerts generated\n",
                  "critical" if total_alerts.get("CRITICAL", 0) else "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Monitor stopped. Total alerts: {total}")
        self._status(f"監視終了 — {total} alerts.")

        rejected: list[str] = []
        findings = self._findings_from_markers(
            parsed_findings, corroborated=False,
            known_evidence_ids=known_evidence_ids or None, rejected_evidence_ids=rejected)
        coverage = self._build_coverage(log_path, len(analyses))
        state, errors = self._determine_state(watch_error=watch_error, analyses=analyses)
        errors += self._log_source_notes(watcher.stats, parse_problems)
        if deadline is not None and timed_out() and not self.is_stopped():
            errors.append(f"指定時間({max_seconds:g}秒)で監視を終了しました。この間に書かれた行だけが対象です")
        if (watcher.stats["truncations"] or watcher.stats["partial_discarded"] or watcher.stats["archive_truncated"]
                or watcher.stats["archive_error"] or watcher.stats["journal_error"]) and state == ScanState.COMPLETED.value:
            state = ScanState.PARTIAL.value        # 縮小(copytruncate等)・アーカイブの上限超過/破損では行を取りこぼし得る
        if store is not None:
            errors = errors + [f"証拠保存エラー: {e}" for e in store.save_errors]
            errors = errors + [f"証拠保存を省略: {o}" for o in store.omissions]
        errors = errors + rejected
        self._finalize(state=state, errors=errors, findings=findings, coverage=coverage,
                       mode="DEFENSE", target=log_path)

    @staticmethod
    def _log_source_notes(stats: dict, problems: dict) -> list[str]:
        """入力ログの扱いに関する注記(取りこぼし得る条件・不正行)。exactly-onceは保証しない。"""
        notes = []
        if stats["rotations"]:
            notes.append(f"ログのローテーションを{stats['rotations']}回検知(旧ファイルの残りを読んでから新ファイルへ切替。"
                         "ポーリング間隔内に複数回回転した場合は中間ファイルを読めない可能性)")
        if stats["truncations"]:
            notes.append(f"ログの縮小(copytruncate等)を{stats['truncations']}回検知。縮小前に読めなかった行は取りこぼした可能性があります")
        if stats["partial_discarded"]:
            notes.append(f"縮小により不完全な末尾行を{stats['partial_discarded']}件破棄しました")
        if stats["partial_flushed"]:
            notes.append(f"回転した旧ファイルの未完の最終行を{stats['partial_flushed']}件、そのまま1行として処理しました")
        if stats["missing_polls"]:
            notes.append(f"ログファイルが一時的に存在しない状態を{stats['missing_polls']}回検知しました")
        if stats["archive_truncated"]:
            notes.append("入力が展開後の上限(256MiB)または1行の上限(1MiB)を超えたため、超過分を読み飛ばしたか、そこで読み取りを終了しました")
        if stats["archive_error"]:
            notes.append(f"gzipアーカイブを最後まで読めませんでした({stats['archive_error']})。読めた分だけを対象にしています")
        if stats["journal_error"]:
            notes.append(f"journaldを最後まで読めませんでした: {stats['journal_error']}。読めた分だけを対象にしています")
        if problems.get("invalid_json"):
            notes.append(f"JSONLとして不正な行が{problems['invalid_json']}件ありました(生テキストとして検知は実施)")
        return notes

    # ── 構造化所見・実行状態(P1.1) ─────────────────────────
    @staticmethod
    def _build_coverage(log_path: str, batch_count: int) -> list[CoverageItem]:
        """監視対象ログのCoverageItemを返す（P1.1）。

        ATTACK_PATTERNSは常に全行へ適用される（設定で個別無効化する仕組みが無い）ため、
        パターン別のtested/skippedは意味を持たない。ログソース単位の記録に留める。
        """
        return [CoverageItem(
            target_ref=log_path, rule_id="LOG_MONITOR",
            status=CoverageStatus.TESTED.value,
            reason=f"{batch_count} batch(es) analyzed",
        )]

    def _determine_state(self, *, watch_error: str | None,
                         analyses: list[str]) -> tuple[str, list[str]]:
        """実行状態(completed/partial/failed/cancelled)を判定する（P1.1）。

        completedは「監視対象について処理を完了した」意味であり、アラート0件は
        脅威が無い保証ではない。ログ監視中の例外やAI分析の全空応答は、検査の実績に
        応じてpartialとする（検出0件の成功とは区別する）。
        """
        errors: list[str] = []
        if self.is_stopped():
            return ScanState.CANCELLED.value, errors
        if watch_error:
            errors.append(f"ログ監視中にエラーが発生しました: {watch_error}")
            return ScanState.PARTIAL.value, errors
        non_empty = [a for a in analyses if a and a.strip()]
        if analyses and not non_empty:
            errors.append("AI脅威分析がすべて空応答でした（LLM呼び出し失敗の可能性）")
            return ScanState.PARTIAL.value, errors
        return ScanState.COMPLETED.value, errors

    def _pattern_match(self, line: str) -> list[str]:
        """ログ行に攻撃パターンが含まれるか検査。一致したパターン名を返す。

        生の行に加え、URLデコード(1回・2回)後の行でも照合する(`%27%20OR%201%3D1` 等のエンコード回避を見逃さない)。
        SCANNERはアクセスログ形式(combined)ならUser-Agent欄だけを見る(記事slugや資料名の `zap`/`nmap` を誤検知しない)。
        """
        variants = _decoded_variants(line)
        ua = _ACCESS_LOG_UA.search(line)
        matched = []
        for name, pattern in ATTACK_PATTERNS.items():
            subject = [ua.group("ua")] if (name == "SCANNER" and ua) else variants
            if any(re.search(pattern, v) for v in subject):
                matched.append(name)
        return matched

    def _quick_severity(self, pattern_name: str) -> str:
        """パターン名から暫定深刻度を返す。AI分析前の速報用。"""
        critical = {"CMD_INJECTION", "SSRF"}
        high     = {"SQL_INJECTION", "LFI_RFI", "XSS"}
        medium   = {"BRUTE_FORCE", "PATH_TRAVERSAL", "SCANNER",
                    "SENSITIVE_FILE_PROBE", "CMS_PROBE"}
        if pattern_name in critical: return "CRITICAL"
        if pattern_name in high:     return "HIGH"
        if pattern_name in medium:   return "MEDIUM"
        return "LOW"

    def _analyze_batch(self, lines: list[str], context: list[str],
                       evidence_ids: list[str | None] | None = None) -> str:
        """バッチログをLLMに送り、深層分析を実施する。分析テキストを返す。"""
        self._out("\n" + "─" * 56 + "\n", "sep")
        self._out(f"  AI THREAT ANALYSIS  ({len(lines)} suspicious entries)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")
        self._log(f"Sending {len(lines)} entries to AI ...")

        recent_ctx = "\n".join(context[-30:]) if len(context) > 30 else "\n".join(context)
        ids = list(evidence_ids or [])
        if any(ids):
            # LLMへ渡すIDの集合をここで固定する。引用された実在IDのみ_findings_from_markersが採用する
            suspect = "\n".join(
                (f"[evidence_id={ids[i]}] " if i < len(ids) and ids[i] else "") + ln
                for i, ln in enumerate(lines))
        else:
            suspect = "\n".join(lines)

        result = self._stream_llm([
            self.llm.system(SYSTEM_PROMPT + (_EVIDENCE_INSTRUCTION if any(ids) else "")),
            self.llm.user(
                f"RECENT LOG CONTEXT (last 30 lines):\n```\n{recent_ctx}\n```\n\n"
                f"SUSPICIOUS ENTRIES REQUIRING ANALYSIS:\n```\n{suspect}\n```\n\n"
                f"Analyze these log entries for threat classification and severity."
            ),
        ])
        self._out("\n", "")
        return result