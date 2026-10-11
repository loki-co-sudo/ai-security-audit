"""
agents/audit_agent.py — コードセキュリティ監査エージェント

ソースコードを読み込み、LLMがセマンティクス解析で未知の脆弱性を推論する。
AST静的解析プリプロセッサで危険関数・構造を事前抽出しプロンプトに注入する。
"""

from __future__ import annotations
import ast
import os
import re
import time
from agents.base_agent import BaseAgent
from tools import cve_client
from tools.report_generator import _findings_and_counts
from core.findings import CoverageItem, ScanState, CoverageStatus
import core.config as config
from core import redaction
from core.evidence_store import EvidenceStore

# ---------- AST 静的解析プリプロセッサ ----------

# 注目する危険関数・メソッド群（カテゴリ別）
_AST_DANGEROUS_CALLS = {
    "CODE_EXEC":       {"eval", "exec", "compile", "__import__", "importlib.import_module"},
    "OS_CMD":          {"os.system", "os.popen", "subprocess.call", "subprocess.Popen",
                        "subprocess.run", "subprocess.check_output", "subprocess.check_call",
                        "os.execv", "os.execl", "os.spawnl"},
    "FILE_OPS":        {"open", "os.remove", "os.unlink", "os.rmdir", "os.rename", "shutil.rmtree",
                        "os.chmod", "os.chown", "pathlib.Path.read_text", "pathlib.Path.write_text"},
    "TEMPLATE":        {"render_template", "render_template_string", "Template"},
    "SHELL_INJECTION": {"os.system", "subprocess.call(shell=True)", "os.popen", "commands.getoutput",
                        "commands.getstatusoutput"},
    "PATH_TRAVERSAL":  {"os.path.join", "pathlib.Path", "open", "tarfile.extractall",
                        "zipfile.ZipFile.extractall", "shutil.unpack_archive"},
    "SQL":             {"execute", "executemany", "raw", "cursor.execute", "cursor.executemany",
                        "connection.execute", "engine.execute"},
    "DESERIALIZATION": {"pickle.load", "pickle.loads", "yaml.load", "json.loads",
                        "marshal.load", "marshal.loads", "dill.load", "dill.loads"},
    "CRYPTO_WEAK":     {"hashlib.md5", "hashlib.sha1", "cryptography.hazmat", "random.random",
                        "random.randint", "random.choice", "secrets.token_urlsafe"},
    "AUTH_BYPASS":     {"request.cookies.get", "request.headers.get", "session.get",
                        "jwt.decode(verify=False)", "json.loads(request.data)"},
    "RACE_CONDITION":  {"threading.Lock", "threading.RLock", "multiprocessing.Lock",
                        "asyncio.Lock", "time.sleep"},
    "SSRF":            {"requests.get", "requests.post", "urllib.request.urlopen",
                        "httpx.get", "httpx.post", "aiohttp.ClientSession.get"},
    "XXE":             {"etree.parse", "etree.fromstring", "lxml.etree.parse",
                        "xml.dom.minidom.parse", "xml.sax.parse", "defusedxml"},
    "LOGGING_LEAK":    {"logging.info", "logging.debug", "logging.error", "logging.warning",
                        "print", "loguru.logger.info", "sys.stderr.write"},
    "HARDCODED_SECRET": {"API_KEY", "SECRET_KEY", "PASSWORD", "TOKEN", "PRIVATE_KEY",
                         "DATABASE_URL", "CONNECTION_STRING"},
}


class _AstVisitor(ast.NodeVisitor):
    """ソースコード上の危険箇所を抽出する AST ビジター。"""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def _match_call(self, func_name: str | None) -> list[str]:
        if not func_name:
            return []
        matched = []
        lower = func_name.lower()
        for category, names in _AST_DANGEROUS_CALLS.items():
            for name in names:
                if name.lower() in lower or lower.endswith("." + name.lower().split(".")[-1]):
                    matched.append(category)
                    break
        return matched

    def visit_Call(self, node: ast.Call) -> None:
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = getattr(node.func, "attr", None)
            if func_name and isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{func_name}"
        if func_name:
            categories = self._match_call(func_name)
            if categories:
                self.findings.append({
                    "line": node.lineno,
                    "call": func_name,
                    "categories": categories,
                })
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.isupper():
                name = target.id
                matched = self._match_call(name)
                if matched:
                    self.findings.append({
                        "line": node.lineno,
                        "call": name,
                        "categories": matched,
                    })
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in {"pickle", "dill", "marshal", "yaml"}:
                self.findings.append({
                    "line": node.lineno,
                    "call": f"import {alias.name}",
                    "categories": ["DESERIALIZATION"],
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in {"pickle", "dill", "marshal", "yaml"}:
            self.findings.append({
                "line": node.lineno,
                "call": f"from {node.module} import ...",
                "categories": ["DESERIALIZATION"],
            })
        self.generic_visit(node)


def ast_scan(source_code: str) -> dict:
    """AST静的解析プリプロセッサ。危険関数と構造を抽出しプロンプト注入用に返す。"""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return {"findings": [], "summary": "(AST解析失敗: 構文エラー)"}

    visitor = _AstVisitor()
    visitor.visit(tree)

    if not visitor.findings:
        return {"findings": [], "summary": "特筆すべき危険パターンはASTで検出されませんでした。"}

    # カテゴリ別に集約
    by_cat: dict[str, list[dict]] = {}
    for f in visitor.findings:
        for cat in f["categories"]:
            by_cat.setdefault(cat, []).append(f)

    summary_lines = ["## AST 静的解析結果（参考情報）\n"]
    for cat, items in sorted(by_cat.items()):
        distinct = sorted(set(f"{it['call']} (L{it['line']})" for it in items))
        summary_lines.append(f"- **{cat}**: {', '.join(distinct[:8])}")
    summary_lines.append("")

    return {"findings": visitor.findings, "summary": "\n".join(summary_lines)}


def smart_truncate(source: str, max_chars: int = 12000) -> str:
    """入力トランケーション戦略改善: 末尾優先・importスキップ分割。

    基本戦略: 先頭から max_chars*0.15 と末尾から max_chars*0.85 を結合。
    ファイル前半（import定義など）＋後半（主要ロジック）の両方をカバーする。
    ファイル全体が max_chars 未満ならそのまま返す。
    """
    if len(source) <= max_chars:
        return source
    head_size = int(max_chars * 0.15)
    tail_size = max_chars - head_size - 80  # 省略マーカー分を引く
    head = source[:head_size]
    tail = source[-tail_size:]
    marker = (
        f"\n\n# ... ({len(source) - head_size - tail_size} 文字省略: "
        f"中間部分・importの大部分をスキップ) ...\n\n"
    )
    return head + marker + tail


STEPS = [
    "ターゲットファイルを読み込み中",
    "AST静的解析 & コード構造分析中",
    "AIエージェントが論理バグを推論中",
    "脆弱性情報をストリーミング中",
    "深刻度スコアを評価中",
    "CVEデータベース照合中",
    "監査レポートを最終化中",
]

SYSTEM_PROMPT = """You are an elite white-hat penetration tester and code auditor specializing in discovering \
*novel, unknown vulnerabilities* that do NOT appear in any CVE database.

Analyze the provided code focusing on:

## PRIORITY 1 — Authentication & Session Logic Flaws
- Authentication bypass through business logic errors (NOT injection alone)
- Session fixation, token prediction, insecure token validation
- Privilege escalation via logic flaws

## PRIORITY 2 — Business Logic Vulnerabilities
- Race conditions and TOCTOU (Time-of-Check-Time-of-Use) flaws
- State machine violations, step-skipping in workflows
- Negative number / integer overflow abuse

## PRIORITY 3 — Architectural & Design Weaknesses
- Unsafe trust assumptions about caller inputs
- Missing security controls at API/module boundaries
- Indirect injection flows that scanners miss

For EVERY vulnerability found, use this EXACT format:

---VULN_START---
NAME: [Descriptive vulnerability name]
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW]
CWE: [CWE-XXX or "Novel — No CVE/CWE Match"]
LINES: [affected line numbers]
SNIPPET:
```
[exact vulnerable code]
```
ATTACK:
[Step-by-step exploitation scenario]
FIX:
```
[corrected code]
```
---VULN_END---

Think deeply. Find the semantic gap between *intent* and *implementation*."""


_EVIDENCE_INSTRUCTION = """

If (and only if) the AST pre-scan reference lists entries with an "evidence_id" and you rely on \
one of them for a finding, add this line to that finding's block after LINES:
EVIDENCE_IDS: [comma-separated evidence_id value(s) that support this finding]. \
Only cite evidence_id values that were literally given to you — never invent one. \
An evidence_id only shows that the AST pre-scan flagged that line; it does not prove the finding."""


def save_ast_evidence(store: EvidenceStore, path: str, source: str,
                      ast_result: dict) -> tuple[set[str], str, list[str]]:
    """ASTプリスキャンの決定的観測をコード証拠として保存する（標準/LangGraph共通・P1.2）。

    `source`はマスク済みのソースを渡すこと。戻り値は (LLMへ渡すID集合,
    プロンプトに足す「AST evidence IDs」節, errors用メッセージ)。保存できなかった
    該当行はIDなしのまま（上限は`store.omissions`として返す）。
    """
    known: set[str] = set()
    src_lines = source.splitlines()
    entries: list[str] = []
    seen: set[tuple] = set()
    for hit in ast_result["findings"]:
        key = (hit["line"], hit["call"])
        if key in seen:
            continue
        seen.add(key)
        ln = hit["line"]
        eid = store.save_code_evidence(
            path=path, line_start=ln, line_end=ln,
            excerpt=src_lines[ln - 1] if 0 < ln <= len(src_lines) else "",
            source="ast_prescan",
        )
        if eid:
            known.add(eid)
            entries.append(f"- evidence_id={eid} L{ln} {hit['call']}")
    listing = ("\n## AST evidence IDs\n" + "\n".join(entries) + "\n") if entries else ""
    errors = [f"証拠保存エラー: {e}" for e in store.save_errors]
    errors += [f"証拠保存を省略: {o}" for o in store.omissions]
    return known, listing, errors


class AuditAgent(BaseAgent):

    def run(self, path: str) -> None:
        self._current_mode, self._current_target = "AUDIT", path
        scan_id = self._begin_scan()  # 証拠保存(EvidenceStore)がfinalize前から使うため(P1.2)
        self.bus.clear()
        t0 = time.time()

        # Step 0: ファイル読み込み
        self._step(0, "running")
        self._log(f"Reading: {path}")
        time.sleep(0.2)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError as e:
            self._log(f"File error: {e}")
            self._step(0, "error")
            self._finalize(state=ScanState.FAILED.value, errors=[f"ファイル読み込みエラー: {e}"],
                           mode="AUDIT", target=path)
            return
        lines = source.count("\n") + 1
        # LLM送信・証拠保存の前に、機密名へのリテラル代入の値をマスクする(P1.2)。
        # 改行を跨がないため行番号は元ソースと一致する。ast_scanは構文解析のため元ソースを使う。
        source = redaction.mask_source(source)
        self._log(f"Loaded {lines} lines ({len(source)} bytes)")
        self._step(0, "done")

        # Step 1: AST静的解析 + ヘッダー表示
        self._step(1, "running")
        self._out(
            "╔══════════════════════════════════════════════════════╗\n"
            "║      CODE AUDIT — AUTONOMOUS VULNERABILITY SCAN      ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n",
            "header",
        )
        self._out(f"  TARGET : {path}\n", "dim")
        self._out(f"  LINES  : {lines}\n", "dim")
        self._out(f"  MODEL  : {self.llm.model}\n\n", "dim")

        # AST静的解析プリプロセッサ（P0: 危険関数・構造を事前抽出しプロンプトに注入）
        ast_result = ast_scan(source)
        ast_count = len(ast_result["findings"])
        self._out(f"  AST PREPROCESSOR : {ast_count} suspicious pattern(s) found\n", "dim")
        if ast_count > 0:
            self._out(ast_result["summary"], "code")
        time.sleep(0.3)

        # ── 証拠保存（P1.2・save_evidence設定時のみ。既定OFF） ──
        # 保存対象はASTプリスキャンの決定的観測のみ。LLMが後から報告する行番号で抜粋を
        # 作ると「モデルの主張の言い換え」になり裏付けにならないため作らない。
        # LLMへ渡すIDの集合をここで固定し、_findings_from_markersで実在IDのみ採用する。
        known_evidence_ids: set[str] = set()
        evidence_errors: list[str] = []
        evidence_listing = ""
        if config.get("save_evidence", False) and ast_result["findings"]:
            known_evidence_ids, evidence_listing, evidence_errors = save_ast_evidence(
                EvidenceStore(scan_id), path, source, ast_result)
            if evidence_errors:
                self._log(f"evidence: {len(evidence_errors)}件の保存エラー/省略")
        self._step(1, "done")

        # Step 2-3: LLM 推論（ストリーミング）— smart_truncate で末尾優先トランケーション
        if self.is_stopped(): return
        self._step(2, "running")
        self._step(3, "running")
        self._status(f"AI が {os.path.basename(path)} を深層解析中 ...")
        self._log("Connecting to LLM ...")
        self._out("─" * 56 + "\n", "sep")
        self._out("  AI REASONING OUTPUT  (streaming)\n", "section")
        self._out("─" * 56 + "\n\n", "sep")

        audit_max_chars = 12000
        was_truncated = len(source) > audit_max_chars
        truncated = smart_truncate(source, audit_max_chars)
        user_prompt = (
            f"Analyze this code for unknown and logic-based security vulnerabilities:\n\n"
            f"```python\n{truncated}\n```"
        )
        if ast_result["findings"]:
            user_prompt += (
                f"\n\n## AST Pre-scan Reference (use cautiously — verify manually)\n"
                f"{ast_result['summary']}\n{evidence_listing}"
            )
        system_prompt = SYSTEM_PROMPT + (_EVIDENCE_INSTRUCTION if known_evidence_ids else "")
        full = self._stream_llm([
            self.llm.system(system_prompt),
            self.llm.user(user_prompt),
        ], live_stats=True)
        self._step(3, "done")
        self._step(2, "done")

        if self.is_stopped(): return

        # 検証パス: 品質エフォート時のみ実行（EFFORT_PRESETS["quality"]["verify_pass"]）。
        # quality時はさらに verify_samples 回のアンサンブル多数決（§5.3）で誤検知を削減する。
        effort = self._effort()
        if effort.get("verify_pass"):
            full = self._verify_findings(
                f"```python\n{source[:6000]}\n```", full, samples=effort.get("verify_samples", 1))

        # Step 4: 深刻度集計
        self._step(4, "running")
        parsed_findings, counts = _findings_and_counts("CODE AUDIT", full)
        time.sleep(0.2)
        self._step(4, "done")

        # Step 5: CVEデータベース照合（並列化: 全CWEをバッチ送出）
        self._step(5, "running")
        cwe_nums = list(dict.fromkeys(re.findall(r'CWE-(\d+)', full)))[:8]
        if not effort.get("cve_lookup"):
            self._out("\n  (CVE照合: 速度エフォートのためスキップ)\n", "dim")
            time.sleep(0.2)
        elif cwe_nums and not self.is_stopped():
            self._out("\n" + "─" * 56 + "\n", "sep")
            self._out("  CVE CORRELATION  (NVD Database · 並列照合)\n", "section")
            self._out("─" * 56 + "\n\n", "sep")
            cwe_ids = [f"CWE-{n}" for n in cwe_nums]

            # 永続キャッシュヒット時は即応答、API要時のみレート制限待機
            cached_count = 0
            persistent = cve_client._load_persistent_cache()
            for cwe_id in cwe_ids:
                if cwe_id in persistent:
                    cached_count += 1
            if cached_count < len(cwe_ids):
                self._out(f"  NVD API照合中（{len(cwe_ids) - cached_count}件）...\n", "dim")
                time.sleep(6.5)  # NVD レート制限: 5 req/30s

            # 並列照合
            results_map = cve_client.search_batch(cwe_ids)
            for cwe_id in cwe_ids:
                if self.is_stopped():
                    break
                results = results_map.get(cwe_id, [])
                self._out(f"\n  ● {cwe_id} — 関連CVE:\n", "label")
                self._out(cve_client.format_results(results), "code")
                self._out("\n", "")
        else:
            self._out("\n  (CWE識別子なし — CVE照合スキップ)\n", "dim")
            time.sleep(0.3)
        self._step(5, "done")

        # Step 6: 最終化
        self._step(6, "running")
        self._save_investigation("CODE AUDIT", path, f"## AI Reasoning Output\n{full}\n")
        time.sleep(0.2)
        self._step(6, "done")

        total = sum(counts.values())
        self._stats(counts)
        self._record_telemetry("CODE AUDIT", path, counts, time.time() - t0)
        self._out("\n\n" + "═" * 56 + "\n", "sep")
        self._out(f"  SCAN COMPLETE  |  {total} vulnerabilities detected\n", "green")
        self._out("═" * 56 + "\n", "sep")
        self._log(f"Audit complete. {total} issues found.")
        self._status(f"Audit complete — {total} vulnerabilities detected.")

        rejected: list[str] = []
        findings = self._findings_from_markers(
            parsed_findings, corroborated=bool(effort.get("verify_pass")),
            known_evidence_ids=known_evidence_ids or None, rejected_evidence_ids=rejected)
        coverage = self._build_coverage(path, was_truncated)
        state, errors = self._determine_state(triage_text=full)
        errors = errors + evidence_errors + rejected
        self._finalize(state=state, errors=errors, findings=findings, coverage=coverage,
                       mode="AUDIT", target=path)

    # ── 構造化所見・実行状態(P1.1) ─────────────────────────
    @staticmethod
    def _build_coverage(path: str, was_truncated: bool) -> list[CoverageItem]:
        """対象ファイルの検査状況をCoverageItemへ変換する（P1.1）。

        smart_truncate()によりファイルサイズ上限を超えた分（中間部分）はLLMへ渡って
        いないため、"未検査"として明示する（ページ数等の代用指標にしない方針）。
        """
        coverage = [CoverageItem(target_ref=path, status=CoverageStatus.TESTED.value,
                                 rule_id="LLM_CODE_REVIEW")]
        if was_truncated:
            coverage.append(CoverageItem(
                target_ref=f"{path} (中間部分)", status=CoverageStatus.SKIPPED.value,
                rule_id="LLM_CODE_REVIEW",
                reason="ファイルサイズがsmart_truncateの上限を超えたため中間部分を省略",
            ))
        return coverage

    def _determine_state(self, *, triage_text: str) -> tuple[str, list[str]]:
        """実行状態(completed/partial/failed/cancelled)を判定する（P1.1）。

        completedは「対象ファイルについて解析を完了した」意味であり、脆弱性が
        無い保証ではない。AI推論が空応答の場合は検出0件の成功と区別しpartialとする。
        """
        errors: list[str] = []
        if self.is_stopped():
            return ScanState.CANCELLED.value, errors
        if not triage_text.strip():
            errors.append("AI推論が空応答でした（LLM呼び出し失敗の可能性）")
            return ScanState.PARTIAL.value, errors
        return ScanState.COMPLETED.value, errors