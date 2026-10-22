"""自律化Phase B4: WEB FUZZのヘッドレス実行・再開・状態確認。"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import json
import re
import os
from pathlib import Path
import signal
import sqlite3
import stat
import sys
import tempfile

from agents.fuzz_capabilities import AutonomousFuzzAgent, load_profile
from core import config
from core.engagement import EngagementError, parse_idor_expectations
from core.findings_ledger import DEFAULT_ROOT as LEDGER_ROOT, STATUSES as LEDGER_STATUSES, Ledger, LedgerError
from core.autonomy.journal import JOURNAL_ROOT, replay, validate_run_id
from core.autonomy.run_store import STATE_FILE
from core.llm_client import LLMClient
from core.scan_runner import (CLIError, aggregate, check_path, check_rules, check_target, masked,
                              run_attack as _run_attack, run_fuzz_targets, run_local as _run_local)
from tools.openapi_loader import OpenApiError, list_operations, load_openapi, select_points
from core.settings import DEFAULT_SCAN_PROFILE, SCAN_PROFILES

AUTH_FIELDS = frozenset(("cookie", "header_name", "header_value", "login_url", "post_url",
                        "user_field", "user_val", "pass_field", "pass_val", "confirm_url", "expect_text"))
SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparseのメッセージには未知の引数に渡された秘密値が含まれ得る。
        raise CLIError("引数が不正です。--helpで使用方法を確認してください")


def nonnegative(value):
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("0以上を指定してください")
    return n


def positive_rate(value):
    n = float(value)
    if not 0 < n <= 1000:
        raise argparse.ArgumentTypeError("0より大きく1000以下の秒あたりリクエスト数を指定してください")
    return n


EFFORT_CHOICES = ("speed", "balanced", "quality", "auto")


def render_markdown(result):
    from tools.report_generator import generate_markdown
    parts = result["results"] if result.get("batch") else [result]
    return "\n\n".join(generate_markdown(r.get("mode", ""), r.get("target", ""), "", r.get("model", ""),
                                          scan_result=r) for r in parts)


# config.jsonのprofilesで使えるキー → (フラグ, 対象モード)。秘密値・未知キーは受け付けない
PROFILE_KEYS = {
    "engagement_id": ("--engagement-id", None), "target": ("--target", None), "effort": ("--effort", None),
    "allow": ("--allow", ("fuzz", "attack")), "exclude": ("--exclude", ("fuzz", "attack")),
    "scan_profile": ("--profile", ("fuzz", "attack")),
    "rate_limit_rps": ("--rate-limit-rps", ("fuzz",)), "scope_mode": (None, None),
    "max_requests": ("--max-requests", ("fuzz",)), "max_pages": ("--max-pages", ("fuzz",)),
    "tls_verify": ("--tls-verify", ("fuzz",)), "tls_ca_bundle": ("--tls-ca-bundle", ("fuzz",)),
}


def expand_profile(argv, profiles):
    """--use-profile NAME をconfig.jsonのprofilesから引数列へ展開する。明示した引数が常に優先。"""
    argv = list(argv)
    if "--use-profile" not in argv:
        return argv
    i = argv.index("--use-profile")
    if i + 1 >= len(argv):
        raise CLIError("--use-profileには名前が必要です")
    name = argv[i + 1]
    del argv[i:i + 2]
    prof = (profiles or {}).get(name) if isinstance(profiles, dict) else None
    if not isinstance(prof, dict):
        raise CLIError("config.jsonのprofilesに指定された名前がありません")
    mode = argv[1] if len(argv) > 1 and argv[0] == "scan" else None
    if mode is None:
        raise CLIError("--use-profileはscanコマンドでのみ使えます")
    for key, value in prof.items():
        if key not in PROFILE_KEYS:
            raise CLIError(f"profilesに未対応のキーがあります: {key}（秘密値は置けません）")
        flag, modes = PROFILE_KEYS[key]
        if key == "scope_mode":     # 新規実行は常にblock。緩める値は受け付けず、blockの明示だけ許す
            if value != "block":
                raise CLIError("profilesのscope_modeにはblockだけ指定できます（warnへは緩められません）")
            continue
        if modes is not None and mode not in modes:
            continue
        if any(a == flag or a.startswith(flag + "=") or (key == "tls_verify" and a == "--no-tls-verify")
               for a in argv):
            continue
        if key == "tls_verify":
            if not isinstance(value, bool):
                raise CLIError("profilesのtls_verifyは真偽値にしてください")
            argv.append(flag if value else "--no-tls-verify")
        elif isinstance(value, list):
            for v in value:
                argv.extend([flag, str(v)])
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            argv.extend([flag, str(value)])
        else:
            raise CLIError(f"profilesの{key}の値の型が不正です")
    return argv


def parser():
    p = Parser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan").add_subparsers(dest="mode", required=True)
    fuzz = scan.add_parser("fuzz")
    audit = scan.add_parser("audit")
    audit_t = audit.add_mutually_exclusive_group(required=True)
    audit_t.add_argument("--target", help="監査するPythonソースのパス（ローカルのファイルまたはディレクトリ）")
    audit_t.add_argument("--targets-file", help="1行1パス(#でコメント、最大50件)。逐次実行")
    defense = scan.add_parser("defense")
    defense_t = defense.add_mutually_exclusive_group(required=True)
    defense_t.add_argument("--target", help="解析するアクセスログのパス（ローカルファイル・既定は1回だけ走査）")
    defense_t.add_argument("--targets-file", help="1行1パス(#でコメント、最大50件)。逐次実行")
    defense.add_argument("--duration", type=float, metavar="SECONDS",
                         help="指定すると1回走査ではなく有限時間(1〜86400秒)だけログを監視する。追記行も対象")
    attack = scan.add_parser("attack")
    attack_t = attack.add_mutually_exclusive_group(required=True)
    attack_t.add_argument("--target", help="偵察対象のhost/IP/URL。--allowで明示した範囲内のみ実行")
    attack_t.add_argument("--targets-file", help="1行1対象(#でコメント、最大50件)。逐次実行。各対象に--allow/--excludeを適用")
    attack.add_argument("--allow", action="append", required=True, help="許可host/IP/CIDR。複数は繰り返す")
    attack.add_argument("--exclude", action="append", default=[], help="除外host/IP/CIDR。許可より優先")
    attack.add_argument("--profile", choices=list(SCAN_PROFILES), default=DEFAULT_SCAN_PROFILE)
    attack.add_argument("--port-scope", choices=("common", "extended"), default="common")
    attack.add_argument("--udp", action="store_true", help="UDPスキャンも行う")
    attack.add_argument("--no-web", action="store_true", help="Web探査を行わない")
    for sub in (audit, defense, attack):
        sub.add_argument("--out", help="結果JSONの追加保存先")
        sub.add_argument("--fail-on", choices=["none", *SEVERITIES], default="none")
        sub.add_argument("--effort", choices=EFFORT_CHOICES)
    for sub in (fuzz, audit, defense, attack):
        sub.add_argument("--use-profile", metavar="NAME", help="config.jsonのprofilesの設定を既定値として使う(明示引数が優先)")
        sub.add_argument("--format", choices=("json", "md"), default="json",
                         help="stdoutの形式。mdはバグバウンティ提出用Markdown(既定json)")
        sub.add_argument("--engagement-id", help="指定すると完了した結果を所見台帳(reports/engagements/<id>)へ記録する")
        sub.add_argument("--ledger-root", default=LEDGER_ROOT, help=argparse.SUPPRESS)
    resume = commands.add_parser("resume")
    status = commands.add_parser("status")
    openapi = commands.add_parser("openapi", help="OpenAPI JSONのoperation一覧を表示する(通信しない)")
    openapi.add_argument("file")
    diff = commands.add_parser("diff", help="台帳内の2つのscanを比較する")
    diff.add_argument("--before", required=True)
    diff.add_argument("--after", required=True)
    diff.add_argument("--include-suppressed", action="store_true")
    mark = commands.add_parser("mark", help="所見の対応statusを記録する(open/fixed/accepted-risk)")
    mark.add_argument("finding_id")
    mark.add_argument("state", choices=LEDGER_STATUSES)
    mark.add_argument("--reason", required=True)
    suppress = commands.add_parser("suppress", help="所見を期限付きで抑制する(理由・期限必須)")
    suppress.add_argument("finding_id")
    suppress.add_argument("--reason", required=True)
    suppress.add_argument("--until", required=True, help="期限(ISO 8601。例: 2026-12-31T00:00:00+09:00)")
    findings_cmd = commands.add_parser("findings", help="台帳の所見一覧")
    findings_cmd.add_argument("--include-suppressed", action="store_true")
    for sub in (diff, mark, suppress, findings_cmd):
        sub.add_argument("--engagement-id", required=True)
        sub.add_argument("--ledger-root", default=LEDGER_ROOT, help=argparse.SUPPRESS)
    for sub in (diff, findings_cmd):
        sub.add_argument("--fail-on", choices=["none", *SEVERITIES], default="none")
        sub.add_argument("--out", help="結果JSONの追加保存先")
    for sub in (fuzz, resume, status):
        sub.add_argument("--allow", action="append", required=True, help="許可host/IP/CIDR。複数は繰り返す")
        sub.add_argument("--journal-root", default=JOURNAL_ROOT)
        sub.add_argument("--out", help="結果JSONの追加保存先")
        sub.add_argument("--fail-on", choices=["none", *SEVERITIES], default="none")
    for sub in (fuzz, resume):
        sub.add_argument("--auth-file", help='0600のJSON: {"a": {...}, "b": {...}}')
        sub.add_argument("--approve-auth", default="", help="今回だけ認証を承認する役割: a または a,b（5分有効）")
        sub.add_argument("--effort", choices=EFFORT_CHOICES)
    group = fuzz.add_mutually_exclusive_group(required=True)
    group.add_argument("--target")
    group.add_argument("--targets-file", help="1行1URL(#でコメント)。逐次実行。--auth-fileとは併用不可")
    fuzz.add_argument("--openapi", help="ローカルのOpenAPI 3.x JSON。--openapi-opで明示したGET+queryだけを検査対象に加える")
    fuzz.add_argument("--openapi-op", action="append", default=[], metavar="OPERATION_ID",
                      help="検査するoperation(複数指定可。全自動選択はしない)")
    fuzz.add_argument("--openapi-exclude", action="append", default=[], metavar="OPERATION_ID")
    fuzz.add_argument("--exclude", action="append", default=[], help="除外host/IP/CIDR。許可より優先")
    fuzz.add_argument("--engagement", help="案件設定JSON(秘密値は含めない): engagement_id / idor_expectations")
    fuzz.add_argument("--profile", choices=list(SCAN_PROFILES), default=DEFAULT_SCAN_PROFILE)
    fuzz.add_argument("--max-requests", type=nonnegative, default=200)
    fuzz.add_argument("--max-pages", type=nonnegative, default=20)
    fuzz.add_argument("--rate-limit-rps", type=positive_rate, default=None,
                      help="案件側の送信レート上限(秒あたり)。プロファイルの上限より緩めることはできない")
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


def read_targets(path, validate=None):
    p = Path(path)
    if not p.is_file() or p.stat().st_size > 262144:
        raise CLIError("対象ファイルが見つからないか大きすぎます")
    targets = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line not in targets:
            targets.append(line)
    if not targets or len(targets) > 50:
        raise CLIError("対象ファイルには1〜50件のURLを指定してください")
    for t in targets:
        (validate or check_target)(t)
    return targets


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
    if not isinstance(data, dict) or set(data) - {"engagement_id", "idor_expectations", "exclude"}:
        raise CLIError("案件設定のキーはengagement_id/idor_expectations/excludeのみです（認証値はこのファイルに入れません）")
    if not isinstance(data.get("exclude", []), list):
        raise CLIError("excludeは配列で指定してください")
    data["exclude"] = check_rules(data.get("exclude", []), "exclude")
    eid = data.get("engagement_id")
    if eid is not None and not (isinstance(eid, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", eid)):
        raise CLIError("engagement_idは英数字・._-の64文字以内で指定してください")
    try:
        data["idor_expectations"] = parse_idor_expectations(data.get("idor_expectations"))
    except EngagementError as e:
        raise CLIError(f"案件設定が不正です: {e}")
    return data


def exit_code(result, fail_on="none"):
    state = result.get("state")
    if state == "cancelled":
        return 130
    if state != "completed":
        return 2
    if fail_on != "none" and any(SEVERITIES.get(f.get("severity", "").lower(), 0) >= SEVERITIES[fail_on]
                                 for f in active_findings(result)):
        return 1
    return 0


def active_findings(result):
    """期限内の抑制(台帳のreport_view)を除いた所見。台帳が無い/記録に失敗した場合は全所見(安全側)。"""
    out = []
    for r in result["results"] if result.get("batch") else [result]:
        rows = (r.get("ledger") or {}).get("findings", [])
        out.extend(f for i, f in enumerate(r.get("findings", [])) if not (i < len(rows) and rows[i].get("suppressed")))
    return out


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


def openapi_list(path):
    try:
        ops = list_operations(load_openapi(path))
    except OpenApiError as e:
        raise CLIError(f"OpenAPIを読めません: {e}")
    return {"state": "completed", "errors": [], "findings": [], "operations": [o.to_dict() for o in ops]}


def ledger_command(args):
    """台帳の参照・更新コマンド。結果はJSON、問題はCLIError(failed/exit 2)。"""
    try:
        led = Ledger(args.engagement_id, args.ledger_root)
        if args.command == "mark":
            led.set_status(args.finding_id, args.state, args.reason)
            return {"state": "completed", "finding_id": args.finding_id, "status": args.state, "errors": [], "findings": []}
        if args.command == "suppress":
            led.suppress(args.finding_id, args.reason, args.until)
            return {"state": "completed", "finding_id": args.finding_id, "suppressed_until": args.until,
                    "errors": [], "findings": []}
        if args.command == "findings":
            res = led.findings(args.include_suppressed)
            return {"state": "completed", "errors": [], **res}
        res = led.diff(args.before, args.after, args.include_suppressed)
        # 閾値判定の対象は新規・再発のみ(不在や未検証は所見ではない)。抑制分は除外済み。
        res["findings"] = [i for i in res["items"] if i["state"] in ("NEW", "REGRESSED")]
        return {"state": "completed", "errors": [], **res}
    except LedgerError as e:
        raise CLIError(str(e))


def record_ledger(args, engagement, result):
    """engagement_idが指定された場合だけ、完了した各scan結果を所見台帳へ追記し、レポート用の台帳ビューを付ける。台帳の失敗はscan結果を隠さない。"""
    eid = getattr(args, "engagement_id", None) or (engagement or {}).get("engagement_id")
    if not eid or args.command != "scan":
        return
    result["engagement_id"] = eid
    try:
        led = Ledger(eid, args.ledger_root)
        for r in (result["results"] if result.get("batch") else [result]):
            if r.get("scan_id"):
                led.record_scan(r)
                r["ledger"] = led.report_view(r)
    except LedgerError as e:
        result.setdefault("errors", []).append(f"所見台帳への記録に失敗しました: {e}")
        result["ledger_error"] = True


def _llm():
    return LLMClient(base_url=config.get("llm_base_url"), api_key=config.get("llm_api_key"),
                     model=config.get("llm_model"), timeout=config.get("llm_timeout"))


def run_attack(args, on_agent, was_interrupted):
    return _run_attack(args.target, args.allow, args.exclude, args.profile, args.port_scope, args.udp, args.no_web,
                       args.effort, on_agent, was_interrupted, llm_factory=_llm)


def run_local(mode, target, effort, on_agent, was_interrupted, duration=None):
    return _run_local(mode, target, effort, on_agent, was_interrupted, duration, llm_factory=_llm)


def main(argv=None):
    args = None
    agent = None
    out_validated = False
    interrupted = False
    secrets = set()
    engagement = {}
    previous = signal.getsignal(signal.SIGINT)

    def set_agent(a):
        nonlocal agent
        agent = a

    def stop(signum, frame):
        nonlocal interrupted
        interrupted = True
        if agent is not None:
            agent.stop()

    signal.signal(signal.SIGINT, stop)
    result = {"state": "failed", "errors": [], "findings": []}
    try:
        argv = list(sys.argv[1:] if argv is None else argv)
        if "--use-profile" in argv:
            config.load()
            argv = expand_profile(argv, config.get("profiles"))
        args = parser().parse_args(argv)
        is_ledger = args.command in ("diff", "mark", "suppress", "findings", "openapi")
        is_audit = args.command == "scan" and args.mode in ("audit", "defense", "attack")
        if not is_ledger and (not is_audit or args.mode == "attack"):
            args.allow = check_rules(args.allow, "--allow")
        if getattr(args, "out", None):
            out = Path(args.out).resolve()
            if hasattr(args, "journal_root") and out.is_relative_to(Path(args.journal_root).resolve()):
                raise CLIError("--outはRun保存ディレクトリの外を指定してください")
            if getattr(args, "auth_file", None) and out == Path(args.auth_file).resolve():
                raise CLIError("--outと認証ファイルは別にしてください")
        out_validated = True
        if args.command == "openapi":
            result = openapi_list(args.file)
        elif is_ledger:
            result = ledger_command(args)
        elif is_audit:
            def one(target):
                if args.mode == "attack":
                    return run_attack(argparse.Namespace(**{**vars(args), "target": target}),
                                      lambda a: set_agent(a), lambda: interrupted)
                return run_local(args.mode, target, args.effort, lambda a: set_agent(a), lambda: interrupted,
                                 getattr(args, "duration", None))
            if not args.targets_file:
                result = one(args.target)
            else:
                targets = read_targets(args.targets_file, check_target if args.mode == "attack" else check_path)
                results, skipped = [], []
                for t in targets:
                    if interrupted:
                        skipped.append(t)
                        continue
                    try:
                        r = one(t)
                    except CLIError as e:
                        r = {"state": "failed", "errors": [str(e)], "findings": []}
                    r["target"] = t
                    results.append(r)
                result = aggregate(results, skipped)
        elif args.command == "status":
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
                    "profile", "max_requests", "max_pages", "max_llm_calls", "permit_t2",
                    "tls_verify", "tls_ca_bundle", "rate_limit_rps")}
                engagement = read_engagement(args.engagement)
                if args.engagement_id and engagement.get("engagement_id") not in (None, args.engagement_id):
                    raise CLIError("--engagement-idと案件設定のengagement_idが一致しません")
                kw["idor_expectations"] = engagement.get("idor_expectations", [])
                kw["excluded_targets"] = sorted(set(check_rules(args.exclude, "--exclude")) | set(engagement.get("exclude", [])))
                kw["seed_points"] = []
                if args.openapi_op or args.openapi_exclude or args.openapi:
                    if not args.openapi or not args.openapi_op or args.targets_file:
                        raise CLIError("--openapiには--openapi-opと単一の--targetが必要です(全operationの自動選択・バッチ併用はしません)")
                    try:
                        kw["seed_points"] = select_points(list_operations(load_openapi(args.openapi)), args.openapi_op,
                                                          args.target, args.openapi_exclude)
                    except OpenApiError as e:
                        raise CLIError(f"OpenAPIの指定が不正です: {e}")
                if args.targets_file:
                    if auth:
                        raise CLIError("--targets-fileと--auth-fileは併用できません（認証値を他の対象へ送らないため）")
                    targets = read_targets(args.targets_file)
                else:
                    check_target(args.target)
                    targets = [args.target]
            if args.command == "resume":
                check_target(kw["target"])
                targets = [kw["target"]]
            with redirect_stdout(sys.stderr):
                config.load()
                llm = LLMClient(base_url=config.get("llm_base_url"), api_key=config.get("llm_api_key"),
                                model=config.get("llm_model"), timeout=config.get("llm_timeout"))
                results, skipped = run_fuzz_targets(
                    targets, kw, args.command, args.allow, args.journal_root, auth, roles, secrets, args.effort,
                    llm, lambda a: set_agent(a), lambda: interrupted)
                if len(results) == 1 and len(targets) == 1 and not getattr(args, "targets_file", None):
                    result = results[0]
                else:
                    result = aggregate(results, skipped)
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
                    record_ledger(args, engagement, result)
                if args is not None:
                    paths = []
                    if agent is not None and getattr(agent, "last_run_id", None):
                        paths.append(Path(args.journal_root, agent.last_run_id, "cli_result.json"))
                    if getattr(args, "out", None) and out_validated:
                        paths.insert(0, Path(args.out))
                    for path in paths:
                        try:
                            save_json(path, result)
                        except OSError:
                            result.setdefault("errors", []).append("結果JSONの保存に失敗しました")
                            if result["state"] != "cancelled":
                                result["state"] = "failed"
                print(render_markdown(result) if getattr(args, "format", "json") == "md"
                      else json.dumps(result, ensure_ascii=False, allow_nan=False))
        finally:
            signal.signal(signal.SIGINT, previous)
    return exit_code(result, getattr(args, "fail_on", "none") if args else "none")


if __name__ == "__main__":
    sys.exit(main())
