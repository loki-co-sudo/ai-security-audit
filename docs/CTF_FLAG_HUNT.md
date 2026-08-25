# ATTACK MODE — CTF Flag Hunt モード（実装設計）

> ステータス: **設計（実装用指示書）** — 本ドキュメントは実装前の設計指針です。
> スコープ: ATTACK MODE のみ。他モード（CODE AUDIT / WEB FUZZ / DEFENSE）は変更しない。

本ドキュメントは、`gui/panels/attack_panel.py`・`agents/recon_agent.py`・`tools/web_prober.py`・
`core/settings.py` など、リポジトリに実在するシンボルへ接地した「実装可能な」設計です。
一般的な CTF 解説ではなく、このコードベースへ差し込む具体的手順を書きます。

---

## 1. 背景と方針

既存の ATTACK MODE は「認可された recon → AI 攻撃仮説 → PoC 生成（ローカル生成・送信なし）」の
フローを `ReconAgent.run()` で実行します。本機能はこのフローに **CTF のフラグ検出** を
追加するものです。安全ポリシー（`EXPLOIT_TRANSMISSION_ENABLED = False`）を一切弱めません。

### 1.1 「フラグを取得する」の定義（法的に範囲限定）

この機能における「フラグを取得する」は、**攻撃の実行ではなく、「認可された応答から既に返って
きた情報を検出・抽出する」** ことを意味します。

| 検出／抽出（実装する） | 攻撃的な奪取（実装しない） |
|---|---|
| 認可済み recon（Step5 の Web プローブが返す HTTP ボディ・ヘッダー・`found_paths`）の文字列から、フラグ形式（`flag{...}` / `ctf{...}` / 32〜64 桁 hex・base64 など）を**ローカル正規表現で検出**して表示・保存 | 送信を伴うペイロード（SQLi・XSS・LFI 送信） |
| スコープ内の既知パス（`/flag.txt` 等）への読み取りは、既存 `WebProber` 配下の本物の **GET 読み取り**に限定 | RCE 注入・ブルートフォース・認証回避・C2 |

つまり「フラグは**認可な応答の検出**によって得るが、**要素への攻撃送信で奪取はしない**」という
検出指向・法的に範囲限定の設計で、既存の `EXPLOIT_TRANSMISSION_ENABLED=False` と
`_assert_no_transmission()` を守り続けます。

---

## 2. トグル UX と既定値（default-off）

- **トグル**: `gui/panels/attack_panel.py` のオプションバーに `CTF Flag Hunt` チェックボックスを追加。
- **既定値**: `self._ctf = tk.BooleanVar(value=False)` — **既定オフ**。
- **オフ（既定）**: `_launch_scan(target)` は `ctf_mode=False` を渡し、`ReconAgent.run` の新引数
  `ctf_mode: bool = False` は既定オフで従来と完全に同一挙動（後方互換）。
- **オン**: `ctf_mode=True` が渡され、フラグ検出回路だけが動作する。`generate_exploit`（PoC生成）とは
  **独立** — CTF はフラグ検出のみで、攻撃コード生成は従来の PoC トグルに従う。

### 2.1 既存設定（スキャン / PoC / スコープ）との合成

| 設定 | 合成ルール |
|---|---|
| スコープ（`allowed_targets` / `scope_mode` warn|block） | **変更なし**。`run()` 冒頭の `self._check_scope(target)` と `scope_guard.in_scope()` をそのまま通す。フラグ抽出はスコープ内レスポンスのみ |
| スキャンプロファイル（`intensity` = stealth/passive/.../bounty） | **変更なし**。フラグ検出は `prober.probe()` が既に作動させる認可GETの結果のみを見る。追加パス探索も `SENSITIVE_PATHS` / `WebProber` の profile 連動設定を再利用（新規スキャン機構なし） |
| 推論エフォート（`_effort()` / `_verify_findings()`） | **変更なし**。フラグ検出は決定的（正規表現＋既存 LLM 解析の添付）で、effort と独立 |
| PoC 生成トグル | 独立。CTF は検出のみで攻撃コード生成を誘発しない |
| レポート保存 | 結果は既存 `_save_poc` / `_save_investigation` のシグネチャを再利用し `reports/` へ保存（送信なし） |

---

## 3. 実装差分（ファイル単位）

### ① `agents/recon_agent.py`

1. **`run()` シグネチャに `ctf_mode: bool = False` を追加**（末尾、既存引数の後に）。
   ```python
   def run(self, target: str, scan_web: bool = True, intensity: str = DEFAULT_SCAN_PROFILE,
           generate_exploit: bool = True, port_scope: str = "common",
           scan_udp: bool = False, ctf_mode: bool = False) -> None:
   ```
2. **フラグ検出ヘルパー**（モジュール関数orメソッド）を追加。
   ```python
   FLAG_RE = re.compile(r"(?i)(?:flag|ctf)\{[^}]{1,256}\}")

   def _detect_flags(*chunks: str) -> list[str]:
       hits = []
       seen = set()
       for c in chunks:
           if not c:
               continue
           for m in FLAG_RE.findall(c):
               if m not in seen:
                   seen.add(m); hits.append(m)
       return hits
   ```
   - フラグ候補は `hex`（32〜64桁）や `base64` も対象にできるよう、任意の抽出を拡張可（初期は `{}` 形式）。
   - これは `EXPLOIT_TRANSMISSION_ENABLED` や `_assert_no_transmission()` に**関与しない、純粋な検出**。
3. **組み込み箇所**（Step5 の probe 後、または Step7 の後に）:
   - `recon_data["flags"]` にフラグ候補を保存。
   - アスし、`FLAG FOUND` を `_out(..., "green")` でステータス表示し、`status` を更新。
   - 最終ステップ（Step9）のレポート body にフラグ節を追記。
   - **この 3 箇所すべて、既に取得済みの応答にのみ作用**。新規の発見スキャン・攻撃送信経路を追加しない。

### ② `gui/panels/attack_panel.py`

- オプションバーに、Web Probe チェックボックスの直後に `CTF Flag Hunt` チェックボックスを追加。
  ```python
  self._ctf = tk.BooleanVar(value=False)
  ctk.CTkCheckBox(
      obar, text="CTF Flag Hunt", variable=self._ctf,
      font=ctk.CTkFont("Segoe UI", 10), text_color=TEXT_DIM,
      fg_color=GREEN, hover_color="#00C866",
      checkbox_width=16, checkbox_height=16,
  ).pack(side="left", padx=8)
  ```
- `_launch_scan(target)` の `self._agent.start(...)` 呼び出しへ `ctf_mode=self._ctf.get()` を追加。

### ③ `core/settings.py`（設定の永続化を望む場合のみ）

- `DEFAULT_CTF_MODE = False`（定数）を定義。
- 設定ダイアログで `config.get("ctf_mode", False)` を参照し `config.json` に保存（トグルはセッション内
  ステートに留めても可。どちらも既定はオフのまま）。

### ④ `tools/web_prober.py`（フラグ検出対象を広げるための最小追加。レビューで発覚し追記）

- `WebProber.probe()` に `capture_body: bool = False` を追加。**既定 False** では
  `result["body"]` は従来どおり `None` のまま（追加コスト・挙動変化ゼロ）。
- `agents/recon_agent.py` の呼び出し（`prober.probe(base_url, on_progress=self._log,
  capture_body=ctf_mode)`）で、`ctf_mode=True` のときだけ `True` を渡す。ONのときのみ
  `resp.text[:200000]` を `result["body"]` に保存し、`_detect_and_report_flags` の走査対象に含める
  （既存の LLM 解析用ローカル変数 `body`（50000 文字）とは独立。LLM プロンプト
  `_build_recon_summary()` はこの `body` フィールドを参照しないため、CTF フラグ検出以外の
  用途（LLM コスト・レポート出力）には影響しない）。
- **AC1（既定オフ時は完全に同一の挙動）を確実に満たすための変更**。当初の実装では
  `capture_body` 分岐がなく `result["body"]` を常時保存していたため、`ctf_mode=False`
  でもメモリ使用量が増える差分があった（実害はなし・LLM プロンプトにもレポートにも
  混入しないことは確認済みだが、AC1 の文言に厳密には反していたため是正）。

> 変更は本質的に上記① ②③④のみ。新規ファイル・新規モジュール・GUI 再設計は不要。

---

## 4. データフロー

```
AttackPanel._start_scan()
  └─ _launch_scan(target) ──>  self._agent.start(..., ctf_mode=self._ctf.get())
         └─ ReconAgent.run(target, ..., ctf_mode=False)          # 新引数 (default False)
              ├─ 既存 recon / probe を実行（スコープ内・既存通り）
              ├─ ctf_mode が True のとき:
              │   recon_data["web"]（ヘッダー・found_paths・ボディ断片）を集約
              │   → _detect_flags(...) ローカル regex
              │   → 見つかれば 🔑 FLAG FOUND を UI に出力・recon_data["flags"] 保存
              │   → (任意) 検出されたフラグを LLM に添付し形式確認（stream ではなくローカル）
              └─ 既存 Step7/8/9 は ctf_mode に依存せず従来どおり（フラグ検出結果を Step9 の body に追記）
```

---

## 5. 受け入れチェック（AC）

1. **既定オフ**: 起動直後 `ctf_mode` が `False` で、従来の ATTACK MODE 実行が完全に同一の
   出力・動作・ファイル生成をすること（CTF 処理による遅延・表示増がない）。
2. **トグル ON**: CTF をオンにし、検証用 `testlab/vuln_server.py`（用意された flag プレースホルダ）
   をターゲットに実行 → UI に `🔑 FLAG FOUND` とフラグ文字列が表示される。
3. **抽出のみ・送信しない**: フラグ検出フェーズでは、対象への新規スキャン・攻撃リクエストが
   発生しないことを（参照側の監視orログ）で確認。
4. **スコープガード維持**: `allowed_targets` でスコープ外 → `_check_scope` / `in_scope` が従来どおり
   warn/block し、フラグ検出が起きない。
5. **安全フラグ不變**: git diff で `EXPLOIT_TRANSMISSION_ENABLED` と `_assert_no_transmission()` の
   本文が不変であること（変更ゼロ）。
6. **回帰**: `tools/run_selftest.py`（非 LLM 回帰）がグリーン。

---

## 6. 実装禁止リスト（CONSTRAINTS の明示）

- 検出に留め、EXPLOIT 送信 / RCE / ブルートフォース / C2 経路は**追加しない**。
- `EXPLOIT_TRANSMISSION_ENABLED` は変更しない。
- `scope_guard` / `scope_mode`（warn|block）は変更しない。
- ATTACK MODE 以外のモード（CODE AUDIT / WEB FUZZ / DEFENSE）は再設計しない。