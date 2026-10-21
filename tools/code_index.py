"""P4.2: Pythonプロジェクトの索引化(AST)と、LLMへ渡す優先付き文脈の生成。

対象コードは import も実行もしない(ast.parseのみ)。`.venv`・生成物・秘密ファイルは除外し、symlinkは辿らない
(対象root外への逸脱を防ぐ)。ファイル数/サイズ/文脈量には上限があり、超過分・構文エラー・解決できない呼出し・動的importは
「解析済み」にせず、結果(`skipped`/`unresolved`/`omitted`)へ明示する。優先順位は入口→認可→DB操作に関係する関数。
**索引の呼出し解決は名前一致の近似**で、優先付けにだけ使う(脆弱性の有無や到達可能性の主張には使わない)。
"""
from __future__ import annotations
import ast
import fnmatch
import os
from dataclasses import dataclass, field

MAX_FILES = 200
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 2_000_000
DEFAULT_CONTEXT_CHARS = 12_000
_SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", ".env.d", "node_modules", "__pycache__", "build", "dist",
              ".tox", ".mypy_cache", ".pytest_cache", "site-packages", "reports", ".idea", ".vscode"}
_SECRET_FILES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "*.keystore",
                 "secrets*", "credentials*", "config.json", "*.kdbx")
_ENTRY_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "websocket", "api_view", "command", "task"}
_AUTH_WORDS = ("auth", "login", "permission", "require", "authoriz", "jwt", "session", "token", "current_user",
               "is_admin", "csrf", "role", "owner")
_DB_CALLS = {"execute", "executemany", "raw", "query", "cursor", "commit", "filter", "get_or_404", "fetchone", "fetchall"}
_DANGEROUS = {"eval", "exec", "compile", "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen",
              "subprocess.check_output", "pickle.loads", "pickle.load", "yaml.load", "marshal.loads"}
_DYNAMIC = {"getattr", "__import__", "eval", "exec", "importlib.import_module", "import_module"}


@dataclass
class Function:
    file: str
    qualname: str
    start: int
    end: int
    decorators: list[str]
    calls: list[str]
    unresolved: int = 0
    is_entry: bool = False
    auth: bool = False
    db: bool = False
    dangerous: bool = False
    score: int = 0


@dataclass
class ProjectIndex:
    root: str
    files: list[str] = field(default_factory=list)                  # 解析できたファイル(root相対)
    sources: dict[str, str] = field(default_factory=dict)
    functions: list[Function] = field(default_factory=list)
    imports: dict[str, set[str]] = field(default_factory=dict)      # file -> 同一プロジェクト内のimport先file
    cycles: list[list[str]] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)    # (path, 理由)
    limit_hit: bool = False
    dynamic_files: list[str] = field(default_factory=list)          # 動的import/getattr等を含むfile


def _dotted(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _module_name(rel: str) -> str:
    mod = rel[:-3].replace(os.sep, ".")
    return mod[: -len(".__init__")] if mod.endswith(".__init__") else mod


class _FuncVisitor(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel, self.stack, self.funcs = rel, [], []

    def _visit_def(self, node):
        qual = ".".join([*self.stack, node.name])
        decs = [d for d in (_dotted(x.func if isinstance(x, ast.Call) else x) for x in node.decorator_list) if d]
        calls, unresolved = [], 0
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                name = _dotted(sub.func)
                if name is None:
                    unresolved += 1
                else:
                    calls.append(name)
                    if name in _DYNAMIC:
                        unresolved += 1
        low = " ".join([node.name, *decs, *calls]).lower()
        fn = Function(
            file=self.rel, qualname=qual, start=node.lineno, end=getattr(node, "end_lineno", node.lineno),
            decorators=decs, calls=calls, unresolved=unresolved,
            is_entry=any(d.split(".")[-1] in _ENTRY_DECORATORS for d in decs),
            auth=any(w in low for w in _AUTH_WORDS),
            db=any(c.split(".")[-1] in _DB_CALLS for c in calls),
            dangerous=any(c in _DANGEROUS for c in calls))
        self.funcs.append(fn)
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = _visit_def

    def visit_ClassDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()


def _is_secret(name: str) -> bool:
    return any(fnmatch.fnmatch(name.lower(), pat) for pat in _SECRET_FILES)


def build_index(root: str, *, max_files: int = MAX_FILES, max_file_bytes: int = MAX_FILE_BYTES,
                max_total_bytes: int = MAX_TOTAL_BYTES) -> ProjectIndex:
    root_real = os.path.realpath(root)
    if not os.path.isdir(root_real):
        raise NotADirectoryError(root)
    idx = ProjectIndex(root=root_real)
    total = 0
    candidates: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_real, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                idx.skipped.append((os.path.relpath(full, root_real), "symlink(辿らない)"))
            elif d in _SKIP_DIRS or d.endswith(".egg-info"):
                continue
            else:
                keep.append(d)
        dirnames[:] = keep
        for fname in sorted(filenames):
            if not fname.endswith(".py") and not _is_secret(fname):
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root_real)
            if _is_secret(fname):
                idx.skipped.append((rel, "秘密ファイルの可能性(除外)"))
            elif os.path.islink(full):
                idx.skipped.append((rel, "symlink(辿らない)"))
            else:
                candidates.append(rel)
    mod_to_file: dict[str, str] = {}
    trees: dict[str, ast.AST] = {}
    for rel in candidates:
        if len(idx.files) >= max_files:
            idx.skipped.append((rel, f"ファイル数上限({max_files})"))
            idx.limit_hit = True
            continue
        full = os.path.join(root_real, rel)
        try:
            size = os.path.getsize(full)
        except OSError:
            idx.skipped.append((rel, "読めない"))
            continue
        if size > max_file_bytes:
            idx.skipped.append((rel, f"ファイルサイズ上限({max_file_bytes}B)"))
            idx.limit_hit = True
            continue
        if total + size > max_total_bytes:
            idx.skipped.append((rel, f"合計サイズ上限({max_total_bytes}B)"))
            idx.limit_hit = True
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
            tree = ast.parse(src, filename=rel)          # 構文解析のみ。対象コードは実行・importしない
        except (SyntaxError, ValueError, OSError, RecursionError) as e:
            idx.skipped.append((rel, f"解析不能({type(e).__name__})"))
            continue
        total += size
        idx.files.append(rel)
        idx.sources[rel] = src
        trees[rel] = tree
        mod_to_file[_module_name(rel)] = rel
        v = _FuncVisitor(rel)
        v.visit(tree)
        idx.functions += v.funcs
        if any(f.unresolved for f in v.funcs) or any(
                isinstance(n, ast.Call) and _dotted(n.func) in _DYNAMIC for n in ast.walk(tree)):
            idx.dynamic_files.append(rel)
    for rel, tree in trees.items():
        pkg = _module_name(rel).rsplit(".", 1)[0] if "." in _module_name(rel) else ""
        deps: set[str] = set()
        for n in ast.walk(tree):
            names: list[str] = []
            if isinstance(n, ast.Import):
                names = [a.name for a in n.names]
            elif isinstance(n, ast.ImportFrom):
                base = n.module or ""
                if n.level:
                    parts = (_module_name(rel) if rel.endswith("__init__.py") else pkg).split(".") if (rel.endswith("__init__.py") or pkg) else []
                    parts = parts[: max(0, len(parts) - (n.level - 1))]
                    base = ".".join([*parts, *([base] if base else [])])
                names = [base, *[f"{base}.{a.name}" if base else a.name for a in n.names]]
            for name in names:
                tgt = mod_to_file.get(name)
                if tgt and tgt != rel:
                    deps.add(tgt)
        idx.imports[rel] = deps
    idx.cycles = _cycles(idx.imports)
    _score(idx)
    return idx


def _cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """強連結成分(サイズ2以上)を循環importとして返す(反復版Tarjan。再帰上限に依存しない)。"""
    index, low, on, stack, out, counter = {}, {}, set(), [], [], [0]
    for start in sorted(graph):
        if start in index:
            continue
        work = [(start, iter(sorted(graph.get(start, ()))))]
        index[start] = low[start] = counter[0]
        counter[0] += 1
        stack.append(start)
        on.add(start)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in graph:
                    continue
                if nxt not in index:
                    index[nxt] = low[nxt] = counter[0]
                    counter[0] += 1
                    stack.append(nxt)
                    on.add(nxt)
                    work.append((nxt, iter(sorted(graph.get(nxt, ())))))
                    advanced = True
                    break
                if nxt in on:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                if len(comp) > 1:
                    out.append(sorted(comp))
    return sorted(out)


def _score(idx: ProjectIndex) -> None:
    """入口→認可→DB操作に関係する関数を優先。入口から名前一致で辿れる関数は+1(近似・優先付け専用)。"""
    by_name: dict[str, list[Function]] = {}
    for f in idx.functions:
        by_name.setdefault(f.qualname.rsplit(".", 1)[-1], []).append(f)
    reach: set[int] = set()
    frontier = [f for f in idx.functions if f.is_entry]
    while frontier:
        cur = frontier.pop()
        for c in cur.calls:
            for cand in by_name.get(c.rsplit(".", 1)[-1], []):
                if id(cand) not in reach and (cand.file == cur.file or cand.file in idx.imports.get(cur.file, ())):
                    reach.add(id(cand))
                    frontier.append(cand)
    for f in idx.functions:
        f.score = (3 if f.is_entry else 0) + (2 if f.auth else 0) + (3 if f.db else 0) + (2 if f.dangerous else 0) \
            + (1 if id(f) in reach else 0)


@dataclass
class ProjectContext:
    text: str
    included: list[tuple[str, str, int, int]]       # (file, qualname, start, end)
    omitted: list[tuple[str, str, int]]              # (file, qualname, start) 文脈量の上限で入らなかった関数
    files_without_functions: list[str]
    index: ProjectIndex


def render_context(idx: ProjectIndex, budget_chars: int = DEFAULT_CONTEXT_CHARS) -> ProjectContext:
    """優先度の高い関数から、ファイル名・実際の行番号つきで文脈を組み立てる。入らなかった箇所は一覧で明示する。"""
    ranked = sorted((f for f in idx.functions if f.score > 0), key=lambda f: (-f.score, f.file, f.start))
    nested = set()
    for a in idx.functions:                                    # 外側の関数に含まれる内側の関数は重複させない
        for b in idx.functions:
            if a is not b and a.file == b.file and a.start <= b.start and b.end <= a.end and (a.start, a.end) != (b.start, b.end):
                nested.add(id(b))
    chosen, used = [], 0
    omitted: list[tuple[str, str, int]] = []
    for f in ranked:
        if id(f) in nested:
            continue
        lines = idx.sources[f.file].splitlines()[f.start - 1: f.end]
        body = "\n".join(f"{f.start + i}| {ln}" for i, ln in enumerate(lines))
        block = f"### {f.file}:{f.start}-{f.end}  {f.qualname}  [score={f.score}]\n{body}\n"
        if used + len(block) > budget_chars:
            omitted.append((f.file, f.qualname, f.start))
            continue
        used += len(block)
        chosen.append((f, block))
    parts = [b for _, b in sorted(chosen, key=lambda t: (t[0].file, t[0].start))]
    text = "\n".join(parts)
    notes = []
    if omitted:
        notes.append("Omitted (context budget): " + ", ".join(f"{p}:{ln} {q}" for p, q, ln in omitted[:30]))
    if idx.skipped:
        notes.append("Not analyzed files: " + ", ".join(f"{p} ({r})" for p, r in idx.skipped[:30]))
    if idx.dynamic_files:
        notes.append("Dynamic import/getattr/eval present (calls not resolved): " + ", ".join(idx.dynamic_files[:20]))
    if idx.cycles:
        notes.append("Circular imports: " + "; ".join(" <-> ".join(c) for c in idx.cycles[:10]))
    if notes:
        text += "\n## Analysis limits (do not assume omitted code is safe)\n" + "\n".join(notes) + "\n"
    with_funcs = {f.file for f in idx.functions}
    return ProjectContext(text=text, included=[(f.file, f.qualname, f.start, f.end) for f, _ in chosen],
                          omitted=omitted, files_without_functions=[p for p in idx.files if p not in with_funcs],
                          index=idx)
