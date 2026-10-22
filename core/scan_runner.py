"""GUIに依存しないスキャン実行層(P3.1): ATTACK/AUDIT/DEFENSE/WEB FUZZの実行・入力検査・集約・結果のマスク。

cli.pyの薄い実行部から使う。標準出力へは何も出さず(進捗はstderr)、設定の一時上書きはこのプロセス内だけでconfig.jsonへ保存しない。
"""
from __future__ import annotations

from contextlib import redirect_stdout
import ipaddress
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit

from agents.audit_agent import AuditAgent
from agents.fuzz_capabilities import AutonomousFuzzAgent, auth_action_args
from agents.monitor_agent import MonitorAgent
from agents.recon_agent import ReconAgent
from core import config, event_bus as ev, redaction
from core.autonomy.actions import new_grant
from core.llm_client import LLMClient
from core.model_router import classify_effort
from core.redaction import mask_source
from core.scope_guard import extract_host, in_scope


APPROVAL_TTL_SECONDS = 300


class RunnerError(Exception):
    """入力・設定の不備。メッセージに秘密値を含めない。"""


CLIError = RunnerError


def make_llm():
    return LLMClient(base_url=config.get("llm_base_url"), api_key=config.get("llm_api_key"),
                     model=config.get("llm_model"), timeout=config.get("llm_timeout"))


def resolve_effort(effort, llm, description):
    """autoだけ難易度ルーター(classify_effort)で1コール分類する。config.jsonへは保存しない。"""
    if effort != "auto":
        return effort
    level = classify_effort(description, llm)
    print(f"effort auto -> {level}", file=sys.stderr, flush=True)
    return level


def check_rules(rules, flag):
    out = []
    for rule in rules:
        rule = rule.strip() if isinstance(rule, str) else ""
        if not rule:
            raise CLIError(f"{flag}は空にできません")
        try:
            ipaddress.ip_network(rule, strict=False)
        except ValueError:
            if not re.fullmatch(r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", rule):
                raise CLIError(f"{flag}はhost/IP/CIDRを指定してください（URL/pathは不可）")
        out.append(rule)
    return out


def check_target(target):
    url = urlsplit(target if "://" in target else "http://" + target)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise CLIError("対象URLにはHTTP(S)のhost/pathだけを指定してください（認証値・queryは不可）")
    return url


def check_path(value):
    if not value or len(value) > 4096 or "\x00" in value or any(ord(c) < 32 for c in value):
        raise CLIError("対象パスが不正です")


def target_excluded(target, excluded):
    return bool(excluded) and in_scope(extract_host(target if "://" in target else "http://" + target), excluded)[0]


def aggregate(results, skipped):
    """逐次実行した各対象の結果を1つにまとめる。全対象completedのときだけcompleted。"""
    states = [r.get("state") for r in results]
    if skipped or any(st == "cancelled" for st in states):
        state = "cancelled"
    elif all(st == "completed" for st in states):
        state = "completed"
    elif all(st == "failed" for st in states):
        state = "failed"
    else:
        state = "partial"
    findings = [{**f, "target": r.get("target")} for r in results for f in r.get("findings", [])]
    errors = [f"{r.get('target')}: {e}" for r in results for e in r.get("errors", [])]
    errors += [f"{t}: 中断のため未実行" for t in skipped]
    return {"state": state, "batch": True, "errors": errors, "findings": findings, "results": results}


def masked(value, secrets):
    if isinstance(value, str):
        return redaction.mask_log_line(value, secrets)
    if isinstance(value, dict):
        return {k: masked(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [masked(v, secrets) for v in value]
    return value


class ConsoleBus(ev.EventBus):
    def __init__(self, secrets):
        super().__init__()
        self.secrets, self.result_payload = secrets, None

    def emit(self, kind, payload=None):
        if kind == ev.RESULT:
            self.result_payload = masked(payload, self.secrets)
        elif kind in (ev.LOG, ev.STATUS):
            print(masked(str(payload), self.secrets), file=sys.stderr, flush=True)


def run_attack(target, allow, exclude, profile, port_scope, udp, no_web, effort, on_agent, was_interrupted,
               llm_factory=None):
    """ATTACK MODE(偵察のみ)を1回実行する。許可は--allow必須・scope_mode=blockで固定、除外は許可より優先。
    設定の上書きはこのプロセス内だけで、config.jsonへは保存しない。CTF能動機能・exploit生成は公開しない。"""
    exclude = check_rules(exclude, "--exclude")
    check_target(target)
    if target_excluded(target, exclude):
        raise CLIError("除外対象のため実行しませんでした（除外は許可より優先）")
    with redirect_stdout(sys.stderr):
        config.load()
        saved = {k: config._cfg.get(k) for k in ("allowed_targets", "scope_mode")}
        config._cfg.update(allowed_targets=list(allow), scope_mode="block")
        try:
            llm = (llm_factory or make_llm)()
            bus = ConsoleBus(set())
            agent = ReconAgent(bus, llm)
            agent.set_effort_override(resolve_effort(
                effort, llm, f"ATTACK MODE reconnaissance of {target}"))
            on_agent(agent)
            if was_interrupted():
                agent.stop()
            agent._safe_run(target=target, scan_web=not no_web, intensity=profile,
                            generate_exploit=False, port_scope=port_scope, scan_udp=udp)
        finally:
            config._cfg.update(saved)
    return bus.result_payload or {"state": "failed", "errors": ["最終結果が通知されませんでした"], "findings": []}


def run_local(mode, target, effort, on_agent, was_interrupted, duration=None, llm_factory=None):
    """CODE AUDIT(標準エンジン)またはDEFENSE(ログ1回走査)を実行して最終結果を返す。ローカルファイルのみ・Runジャーナル無し。"""
    if not (Path(target).is_file() or (mode == "audit" and Path(target).is_dir())):
        raise CLIError("対象のファイル(auditはディレクトリも可)が見つかりません")
    if duration is not None and not 1 <= duration <= 86400:
        raise CLIError("--durationは1〜86400秒で指定してください")
    with redirect_stdout(sys.stderr):
        config.load()
        llm = (llm_factory or make_llm)()
        bus = ConsoleBus(set())
        agent = AuditAgent(bus, llm) if mode == "audit" else MonitorAgent(bus, llm)
        agent.set_effort_override(resolve_effort(effort, llm, f"{mode.upper()} of {target}" + (
            "\n" + mask_source(Path(target).read_text(encoding="utf-8", errors="replace")[:4000])
            if mode == "audit" and Path(target).is_file() else "")))
        on_agent(agent)
        if was_interrupted():
            agent.stop()
        agent._safe_run(path=target) if mode == "audit" else agent._safe_run(log_path=target, watch_mode=duration is not None, max_seconds=duration)
    return bus.result_payload or {"state": "failed", "errors": ["最終結果が通知されませんでした"], "findings": []}


def run_fuzz_targets(targets, kw, command, allow, journal_root, auth, roles, secrets, effort, llm,
                     on_agent, was_interrupted):
    """WEB FUZZ(自律経路)を対象ごとに逐次実行する。(results, skipped)を返す。

    kwは新規実行/再開で共通の設定。対象ごとにコピーして次の対象へ状態を持ち越さない。
    resume時はkwに除外が無く、除外判定をしない(開始時のRunを再開するだけ)。
    """
    results, skipped = [], []
    for i, target in enumerate(targets):
        if was_interrupted():
            skipped = targets[i:]
            break
        one = {**kw, "target": target}
        if command != "resume" and target_excluded(target, one["excluded_targets"]):
            results.append({"target": target, "state": "failed", "findings": [],
                            "errors": ["除外対象のため実行しませんでした（除外は許可より優先）"]})
            continue
        one.update(allowed_targets=allow, journal_root=journal_root,
                   auth=auth.get("a"), auth_b=auth.get("b"), approvals=[
                       new_grant("web.authenticate", auth_action_args(target, r),
                                 expires_at=time.time() + APPROVAL_TTL_SECONDS) for r in roles])
        bus = ConsoleBus(secrets)
        agent = AutonomousFuzzAgent(bus, llm)
        on_agent(agent)
        agent.set_effort_override(resolve_effort(effort, llm, f"WEB FUZZ of {target}"))
        if was_interrupted():
            agent.stop()
        agent._safe_run(**one)
        r = bus.result_payload or {"state": "failed", "errors": ["最終結果が通知されませんでした"], "findings": []}
        r["run_id"] = agent.last_run_id
        r.setdefault("target", target)
        results.append(r)
    return results, skipped
