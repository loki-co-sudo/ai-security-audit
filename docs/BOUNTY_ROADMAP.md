# バグバウンティ対応ロードマップ

> 本書は、本ツールを合法なバグバウンティ（Bug Bounty）活動で実戦利用できるようにするための
> 設計とロードマップをまとめたもの。関連: [DESIGN.md](DESIGN.md) / [AGENT_ARCHITECTURE.md](AGENT_ARCHITECTURE.md) /
> [../AGENTS.md](../AGENTS.md)。実装済み機能を実際に使う際の具体的な操作フローは
> [BOUNTY_WEBFUZZ_WORKFLOW.md](BOUNTY_WEBFUZZ_WORKFLOW.md) を参照。
>
> 本書はロードマップとして先に作成され、advisorレビュー（2026-08-16）を経て
> Phase A〜D を実装済み。実装時は [CLAUDE.md](../CLAUDE.md) の開発ループ
> （変更→`tools/run_selftest.py`→修正）に従った。

> 2026-09-05整理: 本書は実装済みPhase A〜Dの設計経緯を保存する文書。
> 今後の実装順序・除外リスト・レート・IDOR品質改善は [PRACTICAL_ROADMAP.md](PRACTICAL_ROADMAP.md) を正とする。
> 以下の「不足」は策定当時の背景であり、現在の未実装一覧ではない。

## 1. 背景・方針

バグバウンティで求められる要件（合法な対象範囲のみへのアクセス・非破壊・プログラム側のレート制限の尊重・
提出しやすいレポート形式）と、本ツールの既存ポリシー（検出のみ・PoC送信なし・非DoS・同一オリジン限定・
ローカル保存）は方向性として矛盾しない。ただし現状は以下の3点が不足している。

1. **対象範囲（Scope）を機械的に強制する仕組みがない** — ATTACK MODE の認可チェックボックスは
   v2.1 で専門家向けUXのため廃止済み（[AGENTS.md](../AGENTS.md) §3）。復活はさせない方針だが、
   誤ってスコープ外を叩いてしまうリスクへの手当ては別途必要。
2. **資産発見（サブドメイン列挙）の手段がない** — ATTACK MODE はポートスキャン・Web列挙止まりで、
   バグバウンティの初手である「対象ドメイン配下にどんな資産があるか」を洗い出す工程がない。
3. **バグバウンティで評価されやすい脆弱性クラス（IDOR等のアクセス制御不備）の検出手段がない** —
   WEB FUZZ は SQLI/XSS/TRAVERSAL/SSTI のペイロード注入型検出のみ。

### 設計方針: 新モードは作らない

上記3点はいずれも特定モード固有の機能ではなく、**既存モード（ATTACK MODE / WEB FUZZ）を横断する改善**
である。新しいタブ（5つ目のモード）を追加すると GUI・EventBus・パネルの新規実装コストがかかる割に、
中身は既存の `recon_agent.py` / `fuzz_agent.py` の再利用が大半になる。よって：

- **スコープガード** → 全モード共通の安全レイヤーとして `core/` に新規実装し、`BaseAgent` から使う
- **サブドメイン列挙** → ATTACK MODE の「Phase 0」として `recon_agent.py` に追加
- **IDOR検出** → WEB FUZZ の検出カテゴリの1つとして `web_fuzzer.py` に追加
- **レポート形式** → 全モード共通の `report_generator.py` / `export_util.py` に出力形式を追加

新モード（5つ目のタブ）は作らない。

---

## 2. 実装ファイルと責務（完了後の姿）

| ファイル | 変更内容 |
|---|---|
| `core/scope_guard.py`（新規） | 対象がスコープ内かを判定する純粋関数 `in_scope()` |
| `core/config.py` | `allowed_targets` / `scope_mode` のデフォルト値・バリデータ追加 |
| `agents/base_agent.py` | `_check_scope(target)` ヘルパー追加 |
| `agents/recon_agent.py` | `run()` 冒頭でスコープチェック、Phase 0（サブドメイン列挙）追加 |
| `agents/fuzz_agent.py` | `run()` 冒頭でスコープチェック、IDOR比較フェーズ追加（第2セッション設定時のみ） |
| `tools/subdomain_enum.py`（新規） | `crt.sh` への受動照会でサブドメインを列挙 |
| `tools/web_fuzzer.py` | 第2認証セッション対応、`_detect_idor()` 追加 |
| `core/settings.py` | `SCAN_PROFILES["bounty"]` 追加 |
| `gui/dialogs/settings_dialog.py` | SCOPE 設定欄（許可リスト・scope_mode）追加 |
| `gui/panels/fuzz_panel.py` | 第2セッション（IDOR比較用）の任意入力欄追加 |
| `tools/report_generator.py` / `gui/export_util.py` | バウンティ提出用 Markdown 出力追加 |

---

## 3. フェーズ詳細

### Phase A（最優先）— スコープガード

**目的**: 設定した許可リストの範囲外を誤って対象にしたとき、警告または実行ブロックする。

**実装**:

`core/scope_guard.py`
```python
def in_scope(target: str, allowed: list[str]) -> tuple[bool, str]:
    """allowed が空なら常に (True, "")（後方互換・制限なし）。
    ドメインは完全一致 or "*.example.com" 形式の接尾辞一致。
    CIDR ("/" を含む) は target がIPリテラルの場合のみ判定する
    （DNS解決は行わない = 副作用のない純粋な文字列/IP判定に留める）。
    """
```

`core/config.py` の `_DEFAULTS` に追加:
```python
"allowed_targets": [],   # 空 = 制限なし（既存インストールとの後方互換）
"scope_mode": "warn",    # "warn" | "block"
```
`_VALIDATORS` に `scope_mode in ("warn", "block")` のチェックを追加（既存の `_validate_effort` と同じ形）。

`agents/base_agent.py` に追加:
```python
def _check_scope(self, target: str) -> bool:
    """範囲外なら scope_mode に応じて警告 or ブロックする。呼び出し元は
    False が返ったら即 return すること（block時は _done(error=True) 済み）。"""
```

`agents/recon_agent.py` / `agents/fuzz_agent.py` の `run()` 冒頭、`is_stopped()` チェックの直後に
`if not self._check_scope(target): return` を追加。

**重要な設計判断**: v2.1 で廃止した「実行前の確認チェックボックス」の復活ではない。あれは
「毎回人間に手動確認させるUX」で、専門家向けUXの後退として廃止された。今回のスコープガードは
**事前に定義した許可リストに対する機械的な照合**であり、性質が異なる（`config.json` に一度設定すれば
以後は自動判定）。`allowed_targets` が空の既定状態では従来と完全に同一挙動（無効）。

**設定UI**: `settings_dialog.py` に SCOPE セクションを追加。許可リストは複数行テキスト入力
（1行1ルール）、`scope_mode` はセグメントコントロール（warn/block）。

**advisorレビュー指摘（2026-08-16・反映済み）**:
- `allowed_targets` 空リスト＝無効という後方互換デフォルトは維持するが、初学者が
  「設定を忘れて無防備になる」false sense of security を防ぐため、SCOPE セクションに
  「空のままだと全対象が許可扱いになります（既存動作との後方互換のため）。バグバウンティ
  利用では対象範囲の設定を強く推奨します」という警告文言を常時表示する（`allowed_targets`
  が空の間、scope_mode の選択に関わらず表示）。
- `core/scope_guard.py` の v1 は許可リスト（allow-list）への一致判定のみに対応し、
  「全体は対象だが特定のサブドメインは対象外」のような除外リスト（deny-list）表現には
  非対応。実際のバグバウンティのスコープは包含と除外が混在するケースが多いため、
  除外が必要な場合は allowed_targets に個別のホスト名を列挙する運用で回避する
  （将来検討）。

**テスト**: `tools/run_selftest.py` に非LLMの新規項目を追加（既存の 2b〜2d に続く番号）。
- 空リスト → 常に True
- 完全一致・ワイルドカード一致・CIDR一致（IPリテラル） のポジティブケース
- 不一致のネガティブケース
- ドメイン文字列に対するCIDRルール（判定不能→範囲外扱い）のようなエッジケース

---

### Phase B — ATTACK MODE にサブドメイン列挙を追加

**目的**: バグバウンティの初手である資産発見を、受動的（対象への追加パケット送信なし）に行う。

**実装**:

`tools/subdomain_enum.py`（新規）
```python
def query_crtsh(domain: str, timeout: float = 10.0) -> list[str]:
    """crt.sh（証明書透明化ログ）への単発GETのみ。
    ネットワーク失敗・非200・JSON異常はサイレントに [] を返す
    （tools/cve_client.py の「サイレント失敗」方針を踏襲）。"""
```

`agents/recon_agent.py`:
- `STEPS` の先頭に `"サブドメイン列挙中（crt.sh・受動）"` を追加し、既存 Phase 1〜8 の
  `self._step(idx, ...)` の idx を +1 する
- Phase 0 で `subdomain_enum.query_crtsh(target)` を呼び、結果を `_check_scope()` で
  フィルタする。**スコープ外と判定された発見サブドメインはサイレントに捨てず、
  「発見したがスコープ外のため除外」として OUTPUT に可視化する**
  （`_verify_findings()` の除外分可視化と同じ思想。[AGENT_ARCHITECTURE.md](AGENT_ARCHITECTURE.md) §5.3 参照）

**v1のスコープ制限（意図的）**: 発見したサブドメインを**自動的に後続フェーズ（ポートスキャン等）へ
展開しない**。あくまで一覧を提示・レポートに含めるだけに留める。理由: エージェントが1つの許可対象から
自動的に多数のホストへ展開すると、ユーザーの把握しないまま影響範囲（blast radius）が広がる。
複数ホストへの展開は将来の別イテレーションとし、まずは可視化のみ実装する。

`core/settings.py` に `SCAN_PROFILES["bounty"]` を追加。既存の `stealth` 等が「検知回避」目的なのに対し、
`bounty` は「対象インフラへの配慮（レート制限順守）」が目的という**思想の違い**をコメントで明記する
（許可された診断でジッターを入れる理由が「隠れるため」ではなく「負荷を分散するため」であることを
コード上でも区別する）。

**テスト**: `crt.sh` 相当のレスポンスをローカルモックで用意し（既存の PDF/WebFuzzer 系テストが使う
モックサーバ方式を踏襲）、パース・重複排除・スコープフィルタ後の可視化ログを検証する。

**advisorレビュー指摘（2026-08-16・反映済み）**: crt.sh は過去に発行された証明書の記録であり、
発見したサブドメインが現在も対象組織の管理下にあるとは限らない（dangling subdomain の可能性）。
`recon_agent.py` の出力に「発見した資産が現在も対象組織の管理下にあるとは限りません（証明書
発行履歴に基づくため）。生存確認・所有確認は別途行ってください」という注記を含める。

---

### Phase C — WEB FUZZ に IDOR / アクセス制御不備の検出を追加

**目的**: バグバウンティで報奨金が出やすい脆弱性クラスの筆頭である IDOR
（Insecure Direct Object Reference＝安全でない直接オブジェクト参照）を検出可能にする。

**実装**:

`tools/web_fuzzer.py`:
- `WebFuzzer.__init__` に `auth_b: dict | None = None`（第2アカウントの認証情報）を追加
- 既存の `authenticate()` を `_authenticate_session(session, auth)` に抽出し、
  プライマリセッション（`self.session`）とセカンダリセッション（`self.session_b`）の両方で使い回す
- 新規 `_detect_idor(points) -> list[dict]`: クロールで発見した「オブジェクトID風パラメータを含むURL」
  （数値ID・UUIDパターン）に対し、セッションAで取得した内容をセッションBから**同一URLへのGETのみ**で
  再取得し、セッションBが本来アクセス権を持たないはずのリソースを取得できてしまうかを比較する

**安全境界（重要・既存ポリシーを変えない）**: IDOR比較は **GET 等の非破壊メソッドに限定**する。
POST/PUT/DELETE のような書き込み系リクエストを使った横断アクセス確認は対象外とする
（データ改変のリスクがあるため、既存の「検出のみ・エクスプロイトなし」境界を厳守）。

`agents/fuzz_agent.py`:
- `STEPS` に `"認可チェック中（別セッション比較・第2アカウント設定時のみ）"` を追加
- `auth_b` が設定されている場合のみこのフェーズを実行し、観測結果を既存の AI トリアージ
  （Phase 4相当）に追加のエビデンスとして渡す。判定はこれまで通り LLM に委ねる
  （決定論的な断定はしない＝誤検知を人間が確認できる形を維持）

`gui/panels/fuzz_panel.py`: 「第2セッション（IDOR比較用・任意）」の折りたたみセクションを追加。
未設定なら従来通り IDOR チェックはスキップされる（後方互換）。

**テスト**: 2アカウント構成のローカルモックサーバ（`/resource/1` はアカウントAのみ閲覧可、
アカウントBからは403のはずが200になる、というシナリオ）を用意し検出を検証する。

**advisorレビュー指摘（2026-08-16・反映済み）**:
- `gui/panels/fuzz_panel.py` の第2セッション（IDOR比較用）入力欄の近くに、「複数アカウント
  使用は対象プログラムの規約（Rules of Engagement）で許可されているか確認してください」と
  いう注記を表示する。コードの安全性とは別軸の、プログラム規約遵守についての注意喚起。
- `_detect_idor()` の docstring に「GET等の非破壊メソッドへの限定は原則であり、サーバ側の
  実装次第（副作用のあるGETエンドポイント等）では100%の安全性を保証するものではない」と
  明記する。

---

### Phase D — レポート出力のバグバウンティ提出用 Markdown 対応

**目的**: HackerOne / Bugcrowd 等への提出にそのまま使える形式でエクスポートする。

**実装**:
- `tools/report_generator.py` に `generate_markdown(findings, meta) -> str` を追加。
  既存の `---VULN_START/END---` パーサ（HTML/PDF と共通）をそのまま再利用し、
  レンダラーだけ増やす。テンプレートは Summary / Steps to Reproduce / Impact / Suggested Fix の4項目
- `gui/export_util.py` に Markdown 出力ヘルパーを追加し、既存の「📊 HTML」「📄 PDF」ボタンと並べて
  「📝 MD」ボタンを4パネル共通で追加

**テスト**: 既存の HTML/PDF エクスポートテストと同様、サンプル findings からの生成結果に
4項目の見出しが含まれることを確認する。

---

## 4. 優先順位の理由

Phase A は「バグバウンティに限らず安全側の話」なので最優先。B以降は実利用での効果が大きい順
（B: 入口の広さ → C: 報奨金の出やすさ → D: 提出の手間削減）。

## 5. 触ってはいけない不変条件（セキュリティ）

このロードマップのどのフェーズも、[AGENTS.md](../AGENTS.md) §3 の安全境界
（検出のみ・PoC送信なし・非DoS・同一オリジン限定・ローカル保存）を変更しない。
特に Phase C の IDOR 検出は「別セッションからの読み取り比較」に限定し、書き込み系メソッドを使わない。
Phase B のサブドメイン発見は受動照会のみで、発見した資産への自動展開は行わない（v1時点）。

## 6. 検証

各フェーズ実装後は必ず:
```bash
.venv/bin/python3 tools/run_selftest.py
```
を実行し、既存項目の回帰がないこと、追加したテスト項目がPASSすることを確認する。
新規テストは可能な限り非LLM・非ネットワーク（モック使用）にし、`SELFTEST_NON_LLM_ONLY=1` でも
CI上で回せるようにする。

**advisorレビュー指摘（2026-08-16・反映済み）**: Phase A/B/C はいずれも、新設定が
未設定・デフォルトのままなら既存の非バグバウンティ利用者への挙動が完全に従来通りである
ことを確認する後方互換テストを含める（`allowed_targets` 未設定時は `_check_scope` が
常に許可を返す／`auth_b` 未設定時は `_detect_idor` が常に空リストを返す、等）。

## 7. 将来検討（本ロードマップの範囲外）

以下は当時の候補。現在の配置は [実践運用計画](PRACTICAL_ROADMAP.md) のP0.2/P3.1/§9を参照し、本節から独立に実装を開始しない。

- Phase B で発見したサブドメインへの自動展開（複数ホストへのスキャン拡張）— blast radius の
  観点から、ユーザーが明示的に選択したホストのみに展開する UI が別途必要
- バグバウンティプログラムごとのレート制限値（プログラムが公表する上限）を `config.json` に
  持たせ、`bounty` プロファイルへ反映する仕組み
- `scope_guard.py` の除外リスト（deny-list）対応（Phase A参照）
- 重複報告チェック（既に他の研究者が報告済みかどうかの確認）は HackerOne/Bugcrowd 等の
  プラットフォームAPI連携が必要な大きな話であり、v1では意図的に対象外とする
  （advisorレビュー指摘・2026-08-16）
