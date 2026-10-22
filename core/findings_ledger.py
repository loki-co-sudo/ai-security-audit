"""P3.2: 案件ごとの追記式所見台帳(JSONL)と差分判定。

reports/engagements/<engagement_id>/events.jsonl に scan_recorded / finding_observed / status_changed / suppressed を追記する。
人の対応status(open/fixed/accepted-risk)と抑制は観測とは別イベントで、差分(diff)は人のstatusを自動更新しない。

「不在」は強い主張なので、NOT_OBSERVED は WEB FUZZ の検査単位(注入点×全カテゴリ)がすべてtestedで、検出器版と認証役割が
一致し、認証が確認できている場合だけ。LLM推論のモード(AUDIT/ATTACK/DEFENSE)、旧coverage、IDOR集約項目は常に UNVERIFIED。
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
import re
import uuid
from datetime import datetime
from urllib.parse import urlsplit

SCHEMA_VERSION = "1"
STATUSES = ("open", "fixed", "accepted-risk")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_FID_RE = re.compile(r"f_[0-9a-f]{16}")
_CONCLUSIVE_AUTH = ("anonymous", "authenticated")
DEFAULT_ROOT = os.path.join("reports", "engagements")


class LedgerError(Exception):
    pass


class LedgerBusy(LedgerError):
    pass


class LedgerCorrupt(LedgerError):
    pass


def validate_engagement_id(eid: str) -> str:
    if not isinstance(eid, str) or not _ID_RE.fullmatch(eid) or ".." in eid:
        raise LedgerError("engagement_idは英数字・._-の64文字以内で、..を含められません")
    return eid


def normalize_location(location: str) -> str:
    """LLM/検出器が書いた位置表記の揺れ(メソッド・origin・query・行番号・空白)を吸収する。"""
    loc = " ".join(str(location or "").split())
    loc = re.sub(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) ", "", loc, flags=re.I)
    m = re.match(r"^(https?://[^\s/]+)?(/[^\s?#]*)(?:\?[^\s#]*)?(?:#\S*)?(?: (.*))?$", loc)
    if m:
        loc = m.group(2) + (f" {m.group(3)}" if m.group(3) else "")
    return re.sub(r":\d+(?:-\d+)?$", "", loc)


def unit_of(location: str) -> str | None:
    """WEB FUZZの検査単位('path param')。解釈できなければ None。"""
    m = re.fullmatch(r"(/\S*) (\S+)", normalize_location(location))
    return f"{m.group(1)} {m.group(2)}" if m else None


def finding_id(engagement_id: str, target: str, rule_id: str, location: str, role: str) -> str:
    origin = urlsplit(target).netloc.lower() if "://" in str(target) else str(target).lower()
    key = "\x1f".join([engagement_id, origin, str(rule_id).strip().upper(), normalize_location(location), role])
    return "f_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _coverage_summary(coverage: list[dict]) -> tuple[list[str], list[str], str]:
    """(全カテゴリtestedの検査単位, 認証context一覧, 認証役割)。粒度が足りないcoverageは単位を空にする。"""
    units: dict[str, list[bool]] = {}
    contexts: set[str] = set()
    for c in coverage or []:
        rule, ref = str(c.get("rule_id", "")), str(c.get("target_ref", ""))
        ctx = c.get("auth_context") or ""
        if ctx:
            contexts.add(ctx)
        if not rule.startswith("WEB_FUZZ_") or rule == "WEB_FUZZ_PROBE" or ref.startswith("("):
            continue
        u = f"{urlsplit(ref).path or '/'} {c.get('parameter', '')}"
        units.setdefault(u, []).append(c.get("status") == "tested" and ctx in _CONCLUSIVE_AUTH)
    role = "authenticated" if "authenticated" in contexts else ("anonymous" if "anonymous" in contexts else "unknown")
    return sorted(u for u, oks in units.items() if oks and all(oks)), sorted(contexts), role


class Ledger:
    def __init__(self, engagement_id: str, root: str = DEFAULT_ROOT, now=None):
        self.engagement_id = validate_engagement_id(engagement_id)
        self.dir = os.path.join(root, self.engagement_id)
        self.path = os.path.join(self.dir, "events.jsonl")
        self._now = now or (lambda: datetime.now().astimezone())

    # ── 入出力 ──
    def read(self) -> tuple[list[dict], list[str]]:
        """(イベント一覧, 警告)。途中行の破損は黙って無視せず LedgerCorrupt。最終行の不完全書き込みは警告付きで無視。"""
        if not os.path.exists(self.path):
            return [], []
        with open(self.path, "rb") as f:
            data = f.read()
        lines = data.split(b"\n")
        tail = lines.pop()                      # 末尾が\nで終わるなら空
        events, warnings, seen = [], [], set()
        for i, raw in enumerate(lines, 1):
            try:
                ev = json.loads(raw.decode("utf-8"))
                assert isinstance(ev, dict)
            except (ValueError, AssertionError):
                raise LedgerCorrupt(f"台帳の{i}行目が壊れています(途中行は自動回復しません)")
            if ev.get("schema_version") != SCHEMA_VERSION:
                raise LedgerCorrupt(f"台帳の{i}行目のschema_versionが未対応です")
            if ev.get("engagement_id") != self.engagement_id:
                raise LedgerCorrupt(f"台帳の{i}行目が別案件のイベントです")
            if ev.get("event_id") in seen:
                warnings.append(f"重複イベントを無視しました: {ev.get('event_id')}")
                continue
            seen.add(ev.get("event_id"))
            events.append(ev)
        if tail.strip():
            try:
                ev = json.loads(tail.decode("utf-8"))
                assert isinstance(ev, dict) and ev.get("event_id") not in seen
                events.append(ev)
                warnings.append("最終行に改行がありませんでした(読み取りは継続)")
            except (ValueError, AssertionError):
                warnings.append("最終行が不完全なため無視しました(次回の追記時に取り除きます)")
        return events, warnings

    def _append(self, events: list[dict]) -> None:
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        lock = os.open(os.path.join(self.dir, "events.lock"), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LedgerBusy("別のプロセスが台帳へ書き込み中です。後でやり直してください")
            self._repair_tail()
            existing = {e["event_id"] for e in self.read()[0]}
            fresh = [e for e in events if e["event_id"] not in existing]
            if not fresh:
                return
            blob = "".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in fresh).encode()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, blob)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(lock)

    def _repair_tail(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "rb") as f:
            data = f.read()
        if not data or data.endswith(b"\n"):
            return
        keep = data[: data.rfind(b"\n") + 1]
        tail = data[len(keep):]
        try:
            ok = isinstance(json.loads(tail.decode("utf-8")), dict)
        except ValueError:
            ok = False
        with open(self.path, "r+b") as f:
            if ok:
                f.seek(0, os.SEEK_END)
                f.write(b"\n")
            else:
                f.truncate(len(keep))
            f.flush()
            os.fsync(f.fileno())

    def _event(self, etype: str, event_id: str | None = None, **body) -> dict:
        return {"schema_version": SCHEMA_VERSION, "event_id": event_id or f"{etype}:{uuid.uuid4().hex}",
                "ts": self._now().isoformat(timespec="seconds"), "type": etype,
                "engagement_id": self.engagement_id, **body}

    # ── 書き込み ──
    def record_scan(self, result: dict) -> dict:
        """ScanResult(dict)を記録する。同じscan_idは冪等(再記録しない)。"""
        sid = str(result.get("scan_id") or "")
        if not sid:
            raise LedgerError("scan_idがありません")
        mode, target = str(result.get("mode", "")), str(result.get("target", ""))
        units, contexts, role = _coverage_summary(result.get("coverage") or [])
        dv = str(result.get("detector_version", ""))
        evs = [self._event("scan_recorded", f"scan:{sid}", scan_id=sid, mode=mode, target=target,
                           state=result.get("state", ""), detector_version=dv, auth_role=role,
                           auth_contexts=contexts, tested_units=units,
                           errors=list(result.get("errors") or [])[:20])]
        ids = []
        for f in result.get("findings") or []:
            fid = finding_id(self.engagement_id, target, f.get("rule_id", ""), f.get("location", ""), role)
            ids.append(fid)
            evs.append(self._event("finding_observed", f"obs:{sid}:{fid}", scan_id=sid, finding_id=fid,
                                   rule_id=f.get("rule_id", ""), location=f.get("location", ""),
                                   unit=unit_of(f.get("location", "")), severity=f.get("severity", ""),
                                   verification_state=f.get("verification_state", ""), auth_role=role,
                                   detector_version=dv, mode=mode))
        self._append(evs)
        return {"scan_id": sid, "finding_ids": sorted(set(ids))}

    def set_status(self, fid: str, status: str, reason: str) -> None:
        if not _FID_RE.fullmatch(fid or ""):
            raise LedgerError("finding_idの形式が不正です")
        if status not in STATUSES:
            raise LedgerError(f"statusは{'/'.join(STATUSES)}のいずれかです")
        if not str(reason or "").strip():
            raise LedgerError("対応statusの変更には理由が必要です")
        if not any(e.get("finding_id") == fid for e in self.read()[0]):
            raise LedgerError("この案件の台帳に存在しないfinding_idです")
        self._append([self._event("status_changed", finding_id=fid, status=status, reason=reason.strip())])

    def suppress(self, fid: str, reason: str, expires_at: str) -> None:
        if not _FID_RE.fullmatch(fid or ""):
            raise LedgerError("finding_idの形式が不正です")
        if not str(reason or "").strip():
            raise LedgerError("抑制には理由が必要です")
        try:
            exp = datetime.fromisoformat(expires_at)
        except (TypeError, ValueError):
            raise LedgerError("抑制には期限(ISO形式)が必要です")
        if exp.tzinfo is None:
            exp = exp.astimezone()
        if exp <= self._now():
            raise LedgerError("抑制の期限は未来にしてください")
        if not any(e.get("finding_id") == fid for e in self.read()[0]):
            raise LedgerError("この案件の台帳に存在しないfinding_idです")
        self._append([self._event("suppressed", finding_id=fid, reason=reason.strip(),
                                  expires_at=exp.isoformat(timespec="seconds"), scope="finding")])

    # ── 読み取り ──
    def _human(self, events: list[dict], fid: str, until_index: int | None = None) -> tuple[str, dict | None]:
        status, supp = "open", None
        now = self._now()
        for i, e in enumerate(events if until_index is None else events[:until_index]):
            if e.get("finding_id") != fid:
                continue
            if e["type"] == "status_changed":
                status = e["status"]
            elif e["type"] == "suppressed" and datetime.fromisoformat(e["expires_at"]) > now:
                supp = e
        return status, supp

    def findings(self, include_suppressed: bool = False) -> dict:
        events, warnings = self.read()
        latest: dict[str, dict] = {}
        for e in events:
            if e["type"] == "finding_observed":
                latest[e["finding_id"]] = e
        out, suppressed = [], 0
        for fid, e in sorted(latest.items()):
            status, supp = self._human(events, fid)
            if supp and not include_suppressed:
                suppressed += 1
                continue
            out.append({"finding_id": fid, "rule_id": e["rule_id"], "location": e["location"], "severity": e["severity"],
                        "last_seen_scan": e["scan_id"], "status": status,
                        "suppressed": bool(supp), **({"suppression_reason": supp["reason"],
                                                     "suppression_expires_at": supp["expires_at"]} if supp else {})})
        return {"findings": out, "suppressed_count": suppressed, "warnings": warnings}

    def report_view(self, result: dict) -> dict:
        """レポート用の読み取り専用ビュー。台帳へは書き込まない。

        findings[i]は result["findings"][i] と同じ並び。diffは、このscanが台帳に記録済みで、
        同じ対象の直前scanがある場合だけ付く(無ければ理由をnoteに残す)。
        """
        events, warnings = self.read()
        sid, target = str(result.get("scan_id") or ""), str(result.get("target", ""))
        role = _coverage_summary(result.get("coverage") or [])[2]
        items = []
        for f in result.get("findings") or []:
            fid = finding_id(self.engagement_id, target, f.get("rule_id", ""), f.get("location", ""), role)
            status, supp = self._human(events, fid)
            row = {"finding_id": fid, "status": status, "suppressed": bool(supp)}
            if supp:
                row.update(suppression_reason=supp["reason"], suppression_expires_at=supp["expires_at"])
            items.append(row)
        view = {"engagement_id": self.engagement_id, "findings": items, "diff": None, "baseline_scan": "",
                "note": "", "warnings": warnings}
        scans = [e for e in events if e["type"] == "scan_recorded" and e["target"] == target]
        ids = [e["scan_id"] for e in scans]
        if sid not in ids:
            view["note"] = "このscanは台帳に未記録のため差分は出していません"
        elif ids.index(sid) == 0:
            view["note"] = "同じ対象の過去scanがないため差分はありません"
        else:
            base = ids[ids.index(sid) - 1]
            view["baseline_scan"] = base
            try:
                view["diff"] = self.diff(base, sid, include_suppressed=True)
            except LedgerError as e:
                view["note"] = f"差分を計算できませんでした: {e}"
        return view

    def diff(self, before_scan: str, after_scan: str, include_suppressed: bool = False) -> dict:
        events, warnings = self.read()
        scans = {e["scan_id"]: (i, e) for i, e in enumerate(events) if e["type"] == "scan_recorded"}
        for s in (before_scan, after_scan):
            if s not in scans:
                raise LedgerError(f"台帳に記録されていないscan_idです: {s}")
        (bi, b), (ai, a) = scans[before_scan], scans[after_scan]
        if b["target"] != a["target"]:
            raise LedgerError("対象が異なるscan同士は比較できません")
        if ai <= bi:
            raise LedgerError("--afterは--beforeより後に記録されたscanを指定してください")
        obs: dict[str, dict[str, dict]] = {}
        for e in events:
            if e["type"] == "finding_observed":
                obs.setdefault(e["scan_id"], {})[e["finding_id"]] = e
        before, after = obs.get(before_scan, {}), obs.get(after_scan, {})
        history = [(i, s) for i, s in scans.values() if i < ai and s["target"] == a["target"]]

        def absent_proof(scan: dict, o: dict) -> str | None:
            """scan で o(過去の所見)が『検査されたが観測されなかった』と言えない理由。言えるなら None。"""
            if o.get("mode") != "WEB FUZZ" or scan["mode"] != "WEB FUZZ":
                return "LLM推論のモードは不在の根拠にならない"
            if not o.get("unit"):
                return "所見の位置を検査単位として解釈できない"
            if not scan.get("detector_version") or scan["detector_version"] != o.get("detector_version"):
                return "検出器版が不明または一致しない"
            if scan["auth_role"] != o["auth_role"] or scan["auth_role"] not in _CONCLUSIVE_AUTH:
                return "認証役割が一致しない、または認証を確認できていない"
            if o["unit"] not in scan.get("tested_units", []):
                return "同じ検査単位が全カテゴリ完了していない(未検査・予算切れ・失敗・旧coverage)"
            return None

        def last_definite(fid: str) -> str | None:
            """ afterより前のscanを順に見て、直近の確定状態(seen=観測 / absent=検査済みで未観測)を返す。"""
            state, ref = None, None
            for _, scan in history:
                seen = obs.get(scan["scan_id"], {}).get(fid)
                if seen:
                    state, ref = "seen", seen
                elif ref is not None and absent_proof(scan, ref) is None:
                    state = "absent"
            return state

        items = []

        def add(fid, state, o, reason=""):
            status, supp = self._human(events, fid, ai + 1)
            row = {"finding_id": fid, "state": state, "rule_id": o["rule_id"], "location": o["location"],
                   "severity": o["severity"], "status": status, "suppressed": bool(supp)}
            if reason:
                row["reason"] = reason
            if supp:
                row["suppression_reason"] = supp["reason"]
            items.append(row)

        for fid, o in sorted(after.items()):
            prior_absent = last_definite(fid) == "absent"
            human_fixed = self._human(events, fid, ai)[0] == "fixed"
            if human_fixed or prior_absent:
                add(fid, "REGRESSED", o, "過去にfixed、または比較可能な再検査で未観測だった後に再検出")
            elif fid in before:
                add(fid, "PERSISTING", o)
            else:
                add(fid, "NEW", o)
        for fid, o in sorted(before.items()):
            if fid in after:
                continue
            why = absent_proof(a, o)
            add(fid, "UNVERIFIED" if why else "NOT_OBSERVED", o, why or "同じ検査単位が正常に再検査され観測されなかった")
        shown = [r for r in items if include_suppressed or not r["suppressed"]]
        return {"before": before_scan, "after": after_scan, "items": shown,
                "suppressed_count": sum(1 for r in items if r["suppressed"]) if not include_suppressed else 0,
                "counts": {s: sum(1 for r in shown if r["state"] == s)
                           for s in ("NEW", "PERSISTING", "NOT_OBSERVED", "REGRESSED", "UNVERIFIED")},
                "warnings": warnings}
