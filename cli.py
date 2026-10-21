"""自律化Phase B4: WEB FUZZのヘッドレス実行・再開・状態確認。"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import json
import ipaddress
import re
import os
from pathlib import Path
import signal
import sqlite3
import stat
import sys
import tempfile
import time
from urllib.parse import urlsplit

from agents.fuzz_capabilities import AutonomousFuzzAgent, auth_action_args, load_profile
from core import config, event_bus as ev, redaction
from core.engagement import EngagementError, parse_idor_expectations
from core.autonomy.actions import new_grant
from core.autonomy.journal import JOURNAL_ROOT, replay, validate_run_id
from core.autonomy.run_store import STATE_FILE
from core.llm_client import LLMClient
from core.settings import DEFAULT_SCAN_PROFILE, SCAN_PROFILES

APPROVAL_TTL_SECONDS = 300
AUTH_FIELDS = frozenset(("cookie", "header_name", "header_value", "login_url", "post_url",
                        "user_field", "user_val", "pass_field", "pass_val", "confirm_url", "expect_text"))
SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class CLIError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparseのメッセージには未知の引数に渡された秘密値が含まれ得る。
        raise CLIError("引数が不正です。--helpで使用方法を確認してください")


def nonnegative(value):
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("0以上を指定してください")
    return n


def parser():
    p = Parser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan").add_subparsers(dest="mode", required=True)
    fuzz = scan.add_parser("fuzz")
    resume = commands.add_parser("resume")
    status = commands.add_parser("status")
    for sub in (fuzz, resume, status):
        sub.add_argument("--allow", action="append", required=True, help="許可host/IP/CIDR。複数は繰り返す")
        sub.add_argument("--journal-root", default=JOURNAL_ROOT)
        sub.add_argument("--out", help="結果JSONの追加保存先")
        sub.add_argument("--fail-on", choices=["none", *SEVERITIES], default="none")
    for sub in (fuzz, resume):
        sub.add_argument("--auth-file", help='0600のJSON: {"a": {...}, "b": {...}}')
        sub.add_argument("--approve-auth", default="", help="今回だけ認証を承認する役割: a または a,b（5分有効）")
        sub.add_argument("--effort", choices=("speed", "balanced", "quality"))
    fuzz.add_argument("--target", required=True)
    fuzz.add_argument("--engagement", help="案件設定JSON(秘密値は含めない): engagement_id / idor_expectations")
    fuzz.add_argument("--profile", choices=list(SCAN_PROFILES), default=DEFAULT_SCAN_PROFILE)
    fuzz.add_argument("--max-requests", type=nonnegative, default=200)
    fuzz.add_argument("--max-pages", type=nonnegative, default=20)
    fuzz.add_argument("--max-llm-calls", type=nonnegative)
    fuzz.add_argument("--permit-t2", action="store_true")
    fuzz.add_argument("--tls-verify", action=argparse.BooleanOptionalAction, default=None)
    fuzz.add_argument("--tls-ca-bundle")
    for sub in (resume, status):
        sub.add_argument("run_id")
    resume.add_argument("--retry-unknown", action="append", default=[], metavar="TASK_ID")
    resume.add_argument("--additional-requests", type=nonnegative, default=0)
    return p


def read_auth(path):
    if not path:
        return {}
    if os.name != "posix":
        raise CLIError("このOSでは認証ファイルの0600相当の権限を確認できません")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
            raise CLIError("認証ファイルは実行ユーザー所有の通常ファイル・権限0600が必要です")
        raw = f.read(65537)
    if len(raw) > 65536:
        raise CLIError("認証ファイルが大きすぎます")
    data = json.loads(raw)
    if not isinstance(data, dict) or not data or set(data) - {"a", "b"}:
        raise CLIError("認証ファイルにはa/bのオブジェクトを指定してください")
    for entry in data.values():
        if (not isinstance(entry, dict) or not entry or set(entry) - AUTH_FIELDS
                or any(not isinstance(v, str) for v in entry.values())):
            raise CLIError("認証設定の形式が不正です")
    if "b" in data and "a" not in data:
        raise CLIError("認証bには認証aも必要です")
    return data


def read_engagement(path):
    """案件設定(非機密)を読む。未知のキーは拒否する(認証値などを誤って入れた場合に黙って無視しない)。"""
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        raise CLIError("案件設定ファイルが見つかりません")
    if p.stat().st_size > 262144:
        raise CLIError("案件設定ファイルが大きすぎます")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise CLIError("案件設定ファイルをJSONとして読めません")
    if not isinstance(data, dict) or set(data) - {"engagement_id", "idor_expectations"}:
        raise CLIError("案件設定のキーはengagement_id/idor_expectationsのみです（認証値はこのファイルに入れません）")
    eid = data.get("engagement_id")
    if eid is not None and not (isinstance(eid, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", eid)):
        raise CLIError("engagement_idは英数字・._-の64文字以内で指定してください")
    try:
        data["idor_expectations"] = parse_idor_expectations(data.get("idor_expectations"))
    except EngagementError as e:
        raise CLIError(f"案件設定が不正です: {e}")
    return data


def masked(value, secrets):
    if isinstance(value, str):
        return redaction.mask_log_line(value, secrets)
    if isinstance(value, dict):
        return {k: masked(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [masked(v, secrets) for v in value]
    return value


def exit_code(result, fail_on="none"):
    state = result.get("state")
    if state == "cancelled":
        return 130
    if state != "completed":
        return 2
    if fail_on != "none" and any(SEVERITIES.get(f.get("severity", "").lower(), 0) >= SEVERITIES[fail_on]
                                 for f in result.get("findings", [])):
        return 1
    return 0


def save_json(path, result):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cli-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def status_result(run_id, root, allowed):
    validate_run_id(run_id)
    path = Path(root, run_id, STATE_FILE).resolve()
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("BEGIN")
        meta = dict(db.execute("SELECT key,value FROM meta"))
        profile = json.loads(meta["profile_json"])
        if sorted(profile["allowed_targets"]) != sorted(allowed):
            raise CLIError("開始時と同じ--allowを指定してください")
        tasks = [{"task_id": t, "state": s, "requests_used": r, "consumption_unknown": bool(u)}
                 for t, s, r, u in db.execute(
                     "SELECT task_id,state,requests_used,consumption_unknown FROM tasks ORDER BY idx")]
    finally:
        db.close()
    events = replay(run_id, root).events
    last = events[-1] if events else {}
    state = last.get("state", "unknown") if last.get("type") == "run_finished" else "incomplete"
    return {"run_id": run_id, "scan_id": meta.get("scan_id"), "state": state,
            "tasks": tasks, "errors": last.get("errors", []), "findings": [],
            "findings_available": False}


class ConsoleBus(ev.EventBus):
    def __init__(self, secrets):
        super().__init__()
        self.secrets, self.result_payload = secrets, None

    def emit(self, kind, payload=None):
        if kind == ev.RESULT:
            self.result_payload = masked(payload, self.secrets)
        elif kind in (ev.LOG, ev.STATUS):
            print(masked(str(payload), self.secrets), file=sys.stderr, flush=True)


def main(argv=None):
    args = None
    agent = None
    out_validated = False
    interrupted = False
    secrets = set()
    engagement = {}
    previous = signal.getsignal(signal.SIGINT)

    def stop(signum, frame):
        nonlocal interrupted
        interrupted = True
        if agent is not None:
            agent.stop()

    signal.signal(signal.SIGINT, stop)
    result = {"state": "failed", "errors": [], "findings": []}
    try:
        args = parser().parse_args(argv)
        if any(not a.strip() for a in args.allow):
            raise CLIError("--allowは空にできません")
        args.allow = [a.strip() for a in args.allow]
        for rule in args.allow:
            try:
                ipaddress.ip_network(rule, strict=False)
            except ValueError:
                if not re.fullmatch(r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", rule):
                    raise CLIError("--allowはhost/IP/CIDRを指定してください（URL/pathは不可）")
        if args.out:
            out = Path(args.out).resolve()
            if out.is_relative_to(Path(args.journal_root).resolve()):
                raise CLIError("--outはRun保存ディレクトリの外を指定してください")
            if getattr(args, "auth_file", None) and out == Path(args.auth_file).resolve():
                raise CLIError("--outと認証ファイルは別にしてください")
        out_validated = True
        if args.command == "status":
            result = status_result(args.run_id, args.journal_root, args.allow)
            if args.fail_on != "none":
                raise CLIError("statusは所見を再評価しません。--fail-onはscan/resumeで指定してください")
        else:
            auth = read_auth(args.auth_file)
            secrets = AutonomousFuzzAgent._known_secrets(auth.get("a"), auth.get("b"))
            roles = args.approve_auth.split(",") if args.approve_auth else []
            if len(set(roles)) != len(roles) or any(r not in auth for r in roles):
                raise CLIError("--approve-authは認証ファイルにある役割a/bを指定してください")
            if set(roles) != set(auth):
                raise CLIError("認証を適用するには全役割への--approve-authが必要です（送信しません）")
            if args.command == "resume":
                if any(e["type"] == "run_finished" for e in replay(args.run_id, args.journal_root).events):
                    raise CLIError("終了済みのRunは再開できません。resumeはクラッシュからの復旧専用です")
                kw = load_profile(args.run_id, args.journal_root)
                if bool(auth.get("a")) != kw.pop("has_auth") or bool(auth.get("b")) != kw.pop("has_auth_b"):
                    raise CLIError("再開には開始時と同じ認証役割のファイルと新しい承認が必要です")
                if sorted(kw["allowed_targets"]) != sorted(args.allow):
                    raise CLIError("開始時と同じ--allowを指定してください")
                kw.update(resume_run_id=args.run_id, retry_unknown=args.retry_unknown,
                          additional_requests=args.additional_requests)
            else:
                kw = {k: getattr(args, k) for k in (
                    "target", "profile", "max_requests", "max_pages", "max_llm_calls", "permit_t2",
                    "tls_verify", "tls_ca_bundle")}
                engagement = read_engagement(args.engagement)
                kw["idor_expectations"] = engagement.get("idor_expectations", [])
            target = urlsplit(kw["target"] if "://" in kw["target"] else "http://" + kw["target"])
            if target.scheme not in ("http", "https") or not target.hostname or target.username or target.password or target.query or target.fragment:
                raise CLIError("対象URLにはHTTP(S)のhost/pathだけを指定してください（認証値・queryは不可）")
            kw.update(allowed_targets=args.allow, journal_root=args.journal_root,
                      auth=auth.get("a"), auth_b=auth.get("b"), approvals=[
                          new_grant("web.authenticate", auth_action_args(kw["target"], r),
                                    expires_at=time.time() + APPROVAL_TTL_SECONDS) for r in roles])
            with redirect_stdout(sys.stderr):
                config.load()
                llm = LLMClient(base_url=config.get("llm_base_url"), api_key=config.get("llm_api_key"),
                                model=config.get("llm_model"), timeout=config.get("llm_timeout"))
                bus = ConsoleBus(secrets)
                agent = AutonomousFuzzAgent(bus, llm)
                agent.set_effort_override(args.effort)
                if interrupted:
                    agent.stop()
                agent._safe_run(**kw)
                result = bus.result_payload or {"state": "failed", "errors": ["最終結果が通知されませんでした"], "findings": []}
                result["run_id"] = agent.last_run_id
                if engagement.get("engagement_id"):
                    result["engagement_id"] = engagement["engagement_id"]
    except SystemExit:
        result = None
        raise
    except CLIError as e:
        result = {"state": "failed", "errors": [str(e)], "findings": []}
    except Exception as e:
        result = {"state": "failed", "errors": [f"CLI処理に失敗しました ({type(e).__name__})"], "findings": []}
    finally:
        try:
            if result is not None:
                if interrupted:
                    result["state"] = "cancelled"
                result = masked(result, secrets)
                if args is not None:
                    paths = []
                    if agent is not None and agent.last_run_id:
                        paths.append(Path(args.journal_root, agent.last_run_id, "cli_result.json"))
                    if args.out and out_validated:
                        paths.insert(0, Path(args.out))
                    for path in paths:
                        try:
                            save_json(path, result)
                        except OSError:
                            result.setdefault("errors", []).append("結果JSONの保存に失敗しました")
                            if result["state"] != "cancelled":
                                result["state"] = "failed"
                print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        finally:
            signal.signal(signal.SIGINT, previous)
    return exit_code(result, args.fail_on if args else "none")


if __name__ == "__main__":
    sys.exit(main())
