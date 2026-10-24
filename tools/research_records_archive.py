"""評価記録（結果ファイル・凍結条件・使用記録・実行ごとのジャーナルと証拠）を、git管理外の場所へ保全し、復元して検証する。

原本は変更しない（読むだけ）。作るもの（--out-dir 内）: <label>.tar.gz・MANIFEST.sha256（ファイルごとのSHA-256）・RESTORE.md・archive_info.json。
証拠本文・認証情報・個人情報はgitへ入れない（このツールは --out-dir に書くだけで、gitには何も追加しない。--out-dir がリポジトリ内なら拒否する）。
**同じディスク上の複製は、別媒体へのバックアップではない。** 外部サービスへはアップロードしない。

使い方:
  .venv/bin/python3 tools/research_records_archive.py create --label amber --out-dir ~/archives/ai-security-audit/amber \\
      --records-dir reports/stage2_records/<名前> --results testlab/baselines/<結果>.json --extra <ファイル> ...
  .venv/bin/python3 tools/research_records_archive.py verify --out-dir ~/archives/ai-security-audit/amber [--results-name <結果>.json]
"""
from __future__ import annotations
import argparse
import glob
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _inside(path: str, root: str) -> bool:
    p, r = os.path.realpath(path), os.path.realpath(root)
    return p == r or p.startswith(r + os.sep)


def collect(records_dir: str, results: str, extras: list) -> dict:
    """アーカイブに入れる原本の一覧: アーカイブ内の相対パス -> 原本の絶対パス。"""
    files: dict = {}
    base = os.path.basename(os.path.normpath(records_dir))
    for dirpath, _, names in os.walk(records_dir):
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            files[os.path.join("records", base, os.path.relpath(p, records_dir))] = p
    files[os.path.join("results", os.path.basename(results))] = results
    for p in extras:
        files[os.path.join("extra", os.path.relpath(os.path.abspath(p), ROOT) if _inside(p, ROOT) else os.path.basename(p))] = os.path.abspath(p)
    return files


def create(label: str, out_dir: str, records_dir: str, results: str, extras: list) -> dict:
    if _inside(out_dir, ROOT):
        raise SystemExit("エラー: --out-dir はリポジトリの外にしてください（証拠本文をgitに入れないため）")
    if os.path.exists(os.path.join(out_dir, f"{label}.tar.gz")):
        raise SystemExit("エラー: 既にアーカイブがあります。上書きしません（別の --label か --out-dir を使う）")
    files = collect(records_dir, results, extras)
    before = {rel: sha256_file(p) for rel, p in files.items()}
    os.makedirs(out_dir, exist_ok=True)
    arc = os.path.join(out_dir, f"{label}.tar.gz")
    with tarfile.open(arc, "w:gz") as tf:
        for rel, p in sorted(files.items()):
            tf.add(p, arcname=rel, recursive=False)
    after = {rel: sha256_file(p) for rel, p in files.items()}
    if before != after:
        raise SystemExit("エラー: 作成中に原本が変わりました（原本は変更しない前提が崩れた）")
    manifest = os.path.join(out_dir, "MANIFEST.sha256")
    with open(manifest, "w", encoding="utf-8") as f:
        for rel in sorted(before):
            f.write(f"{before[rel]}  {rel}\n")
    info = {"label": label, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "files": len(before), "archive": os.path.basename(arc),
            "archive_sha256": sha256_file(arc), "manifest_sha256": sha256_file(manifest),
            "results_name": os.path.basename(results), "records_name": os.path.basename(os.path.normpath(records_dir)),
            "note": "同じディスク上の複製であり、別媒体へのバックアップではない"}
    with open(os.path.join(out_dir, "archive_info.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=1)
        f.write("\n")
    with open(os.path.join(out_dir, "RESTORE.md"), "w", encoding="utf-8") as f:
        f.write(f"""# 復元手順（{label}）
1. 空のディレクトリを作り、展開する: `mkdir restore && tar -xzf {label}.tar.gz -C restore`
2. ハッシュを確認する: `cd restore && sha256sum -c ../MANIFEST.sha256`（全行 OK であること）
3. アーカイブ自体のハッシュ: `sha256sum {label}.tar.gz` が `archive_info.json` の `archive_sha256` と一致すること
4. 参照証拠の解決まで確認する: `.venv/bin/python3 tools/research_records_archive.py verify --out-dir <このディレクトリ>`
**注意**: この複製は同じディスク上にある。別媒体へのバックアップではない（ディスク故障・誤削除で原本と一緒に失われうる）。
保存先が未設定の外部サービスにはアップロードしない。証拠本文・認証情報を含みうるので、gitに入れない。
""")
    return info


def verify(out_dir: str, results_name: str | None = None) -> dict:
    """別の一時ディレクトリへ展開し、ハッシュ一致と、結果ファイルが参照する証拠・ジャーナルの解決を確認する。"""
    with open(os.path.join(out_dir, "archive_info.json"), encoding="utf-8") as f:
        info = json.load(f)
    problems: list = []
    arc = os.path.join(out_dir, info["archive"])
    if sha256_file(arc) != info["archive_sha256"]:
        problems.append("アーカイブのハッシュが archive_info.json と一致しません")
    if sha256_file(os.path.join(out_dir, "MANIFEST.sha256")) != info["manifest_sha256"]:
        problems.append("MANIFEST.sha256 が archive_info.json と一致しません")
    with open(os.path.join(out_dir, "MANIFEST.sha256"), encoding="utf-8") as f:
        manifest = dict((line.rstrip("\n").split("  ", 1)[1], line.split("  ", 1)[0]) for line in f if line.strip())
    stats = {"files": len(manifest), "hash_mismatch": 0, "missing": 0, "extra_in_archive": 0}
    tmp = tempfile.mkdtemp(prefix="records_verify_")
    try:
        with tarfile.open(arc, "r:gz") as tf:
            for m in tf.getmembers():
                if m.name.startswith(("/", "..")) or ".." in m.name.split("/"):
                    problems.append(f"危険なパス: {m.name}")
            tf.extractall(tmp, filter="data")
        for rel, want in manifest.items():
            p = os.path.join(tmp, rel)
            if not os.path.isfile(p):
                stats["missing"] += 1
                problems.append(f"欠落: {rel}")
            elif sha256_file(p) != want:
                stats["hash_mismatch"] += 1
                problems.append(f"ハッシュ不一致: {rel}")
        present = {os.path.relpath(p, tmp) for p in glob.glob(os.path.join(tmp, "**", "*"), recursive=True) if os.path.isfile(p)}
        stats["extra_in_archive"] = len(present - set(manifest))
        res_path = os.path.join(tmp, "results", results_name or info["results_name"])
        refs = _resolve_references(tmp, info, res_path, problems)
        stats.update(refs)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"ok": not problems, "problems": problems[:50], "n_problems": len(problems), "stats": stats, "info": info}


def _resolve_references(tmp: str, info: dict, res_path: str, problems: list) -> dict:
    """結果ファイルの runs_compact が参照する実行ごとのジャーナルと証拠が、展開した記録の中で解決するか。"""
    out = {"runs": 0, "runs_without_records": 0, "journals_resolved": 0, "evidence_refs": 0, "evidence_resolved": 0,
           "trace_seq_checked": 0, "trace_seq_mismatch": 0}
    with open(res_path, encoding="utf-8") as f:
        res = json.load(f)
    rec_root = os.path.join(tmp, "records", info["records_name"])
    from core.autonomy.journal import replay
    for r in res.get("runs_compact", []):
        out["runs"] += 1
        rec = r.get("records")
        if not rec:
            out["runs_without_records"] += 1
            continue
        sub = os.path.join(rec_root, os.path.basename(rec["dir"]))
        jpath = os.path.join(sub, "j", r["run_id"], "journal.jsonl")
        if not os.path.isfile(jpath):
            problems.append(f"ジャーナルが解決しない: {os.path.basename(rec['dir'])}")
            continue
        out["journals_resolved"] += 1
        ev = replay(r["run_id"], os.path.join(sub, "j")).events
        files = [p for p in glob.glob(os.path.join(sub, "e", "**", "*.json"), recursive=True)]
        for f in r["trace"]["findings"]:
            for eid in [*f["evidence_ids"], f["prior_evidence_id"]]:
                if not eid:
                    continue
                out["evidence_refs"] += 1
                if any(eid in p for p in files):
                    out["evidence_resolved"] += 1
                else:
                    problems.append(f"証拠が解決しない: {os.path.basename(rec['dir'])} {eid}")
            reg = [e["seq"] for e in ev if e["type"] == "hypothesis_registered" and e["hypothesis_id"] == f["hypothesis_id"]]
            pl = [e["seq"] for e in ev if e["type"] == "experiment_planned" and e["exp_id"] == f["probe_exp"]]
            out["trace_seq_checked"] += 1
            if not (reg and pl and reg[0] == f["registered_seq"] and pl[0] == f["probe_planned_seq"]):
                out["trace_seq_mismatch"] += 1
                problems.append(f"traceの順序番号が不一致: {os.path.basename(rec['dir'])}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--label", required=True)
    c.add_argument("--out-dir", required=True)
    c.add_argument("--records-dir", required=True)
    c.add_argument("--results", required=True)
    c.add_argument("--extra", action="append", default=[], help="追加で保全するファイル（凍結条件・使用記録・案件ファイル等）")
    v = sub.add_parser("verify")
    v.add_argument("--out-dir", required=True)
    v.add_argument("--results-name")
    a = ap.parse_args()
    sys.path.insert(0, ROOT)
    if a.cmd == "create":
        print(json.dumps(create(a.label, os.path.expanduser(a.out_dir), a.records_dir, a.results, a.extra), ensure_ascii=False, indent=1))
        return 0
    r = verify(os.path.expanduser(a.out_dir), a.results_name)
    print(json.dumps({k: r[k] for k in ("ok", "n_problems", "stats", "problems")}, ensure_ascii=False, indent=1))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
