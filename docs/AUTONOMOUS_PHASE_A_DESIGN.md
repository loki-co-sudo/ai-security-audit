# Phase A 詳細設計: 行動境界と Run Journal（WEB FUZZ のみ）

作成: 2026-10-21。状態: **提案（未承認・未実装）**。上位設計: [AUTONOMOUS_PLATFORM_DESIGN.md](AUTONOMOUS_PLATFORM_DESIGN.md) §8 Phase A。
本書のクラス名・関数名・ファイルはすべて**新規の設計案**で、現時点では存在しない。既存の名称（`WebFuzzer`、`HttpTransport`、`FuzzAgent` 等）は実コードで確認済み。

## 1. 目的とスコープ

**目的**: LLMによる計画を一切入れずに、「型付き Action → Policy Gate → 既存の送信口 → Run Journal」という
自律化の骨格を、WEB FUZZの現行動作と**等価な形**で通す。後続Phaseで入るPlannerが、すでに検証済みの境界の上に載るようにする。

**やること**
- WEB FUZZの7ステップを capability（名前付きの実行単位）として切り出し、固定の計画（スクリプト化計画）で実行する。
- 全てのActionをGateが実行**前**に判定し、判断と結果を追記式ジャーナルに残す。
- ジャーナルの再生で、タスクの状態が再構築できることを示す（再開機能そのものはPhase B）。

**やらないこと（非目標）**
- LLMによる計画・タスク選択（Phase C）。ここでのLLM呼び出しは現行と同じ（FASTのプローブ生成、STRONGのトリアージ）で、選択権限を持たない。
- 再開の実行、CLI、案件プロファイル永続化（Phase B / P3.1 / P3.2）。
- Recon・AUDIT・DEFENSEの変更（Phase E以降）。CTF能動探索には触れない。
- 既存GUIのWEB FUZZ経路の置き換え。新経路は別エントリとし、等価性が確認できるまで既定にしない。
- 新規の外部依存ライブラリ（標準ライブラリのみ）。

## 2. 現行コードの切り出し点（確認済み）

`agents/fuzz_agent.py` の `FuzzAgent.run()`（約200行）の構造と、切り出す単位:

| 現行の処理 | 呼び出し | capability名（案） | 副作用クラス | 備考 |
|---|---|---|---|---|
| スコープ確認 | `_check_scope()` | （Gateに吸収） | — | 既存の `scope_mode=warn` 既定は自律経路では使わない（§4.1） |
| 認証（A/B） | `fuzzer.authenticate()` / `authenticate_b()` | `web.authenticate`（役割 a / b ごとに別Action） | **T3（認証情報の送信）** | 「認証設定」（プロファイルの認証参照）と「そのActionへの承認」は**別契約**。承認は §11.2 の `ApprovalGrant` が無ければ実行しない |
| クロール・注入点検出 | `fuzzer.crawl(base_url)` | `web.crawl` | T1 | 結果: `injection_points` を `Asset`相当の記録へ |
| プローブ生成 | `self._gen_probes(points)`（FAST） | `llm.gen_probes` | T0 | 送信なし。LLM呼出は予算台帳に計上 |
| ファジング（GET） | `fuzzer.fuzz(get_points, probes)`（呼び出し側でGET注入点だけに絞る。`WebFuzzer`は変更しない） | `web.fuzz_get_points` | T1（`mutating=False`） | 内部でThreadPoolExecutor。**1回の実行をActionにする**。GETであることは副作用がない保証ではない（§11.1） |
| ファジング（POST） | （Phase Aでは実行しない） | `web.fuzz_post_points`（Phase Aでは登録のみ・実行不可） | **T3** | POST注入点は coverage に `skipped`（理由 `post_requires_approval`）で記録し送信しない。送信する場合は個別承認（§11.2） |
| 認可チェック | `idor_skip_reason()` → `fuzzer._detect_idor(points)` | `web.idor_compare` | T2（GET限定） | 認証状態が不明ならskipし理由を記録（既存挙動を保存） |
| 証拠保存 | `_save_evidence(...)` | `evidence.save` | T0 | `save_evidence` 設定時のみ |
| AIトリアージ＋検証パス | `_stream_llm` / `_verify_findings` | `llm.triage` | T0 | STRONG。マスク済みサマリーのみ入力 |
| 結果確定 | `_findings_from_markers` / `_finish` | （capabilityにしない。Runnerの終了処理 `close_run` → `_finalize`） | — | `_finalize()`（RESULT→DONEを一度だけ）の契約を保つ。終了処理は通常Actionから独立（§11.6）。実装では現行の `_build_coverage` / `_determine_state` は使わず、検査実績（`fuzz_log`）に基づく新しい組み立てを用いる |

**切り出しの方針（strangler）**: `FuzzAgent` の既存メソッドは変更せず、capability側から**呼び出す**。重複するのは制御フロー
（`if self.is_stopped(): return` の列）だけで、これをRunnerが担う。既存メソッド内部の挙動（`_fuzz_point`、`_detect` 等）は変えない。

**要確認事項（実装前に調べる）**: `fuzzer._req_count`（プライベート属性）への直接参照が `run()` にある。capabilityの結果にリクエスト数を載せる際は、
`WebFuzzer` 側に公開プロパティを足すかを実装時に判断する（挙動不変の最小変更に限る）。

## 3. 追加するモジュールとデータ契約（案）

配置: `core/autonomy/`（新規ディレクトリ）。標準ライブラリの dataclass/Enum のみ。命名は既存の規約（クラスPascalCase、メソッドsnake_case）に従う。

```
core/autonomy/
  __init__.py
  actions.py       # CapabilitySpec, Action, ActionResult, SideEffect
  policy_gate.py   # PolicyGate, GateDecision
  journal.py       # RunJournal（追記・再生・破損末尾の回復）
  budget.py        # BudgetLedger
  task_graph.py    # Task, TaskState, TaskGraph（Phase Aは直線＋依存のみ）
  runner.py        # ScriptedRunner（固定計画を実行）
agents/
  fuzz_capabilities.py   # 上表のcapabilityをFuzzAgent/WebFuzzer上に定義
```

### 3.1 主要型

```python
class SideEffect(str, Enum):      # 副作用クラス（上位設計 §6.1）
    T0_LOCAL = "T0"
    T1_OBSERVE = "T1"
    T2_DIFFERENTIAL = "T2"
    T3_NEEDS_APPROVAL = "T3"

@dataclass(frozen=True)
class CapabilitySpec:
    name: str                      # "web.crawl" など。レジストリのキー
    side_effect: SideEffect
    mutating: bool                 # Trueのcapabilityは T3 以外に宣言できない（登録時に検証）
    args_schema: dict              # 引数名→型/制約（標準ライブラリで検証）
    max_requests: int | None       # このActionが消費し得る送信数の上限（None=送信しない）
    uses_llm: str | None           # "strong" | "fast" | None

@dataclass(frozen=True)
class Action:
    action_id: str
    task_id: str
    capability: str
    args: dict                     # 秘密値を含めない（認証値は参照名のみ）
    dedupe_key: str                # hash(capability, 正規化args, 認証context, origin)

@dataclass
class GateDecision:
    verdict: str                   # "allow" | "deny" | "needs_approval"
    reason_codes: list[str]        # 例: ["scope.out_of_scope", "budget.requests_exhausted"]
    detail: str
```

`ActionResult` は `status`（done/failed/skipped）、構造化された結果の**要約**、`evidence_ids`、実測の送信数、LLM使用量（取得不能は `unknown`）を持つ。
対象由来の生テキストは結果要約に含めず、証拠ID経由で参照する。

### 3.2 Run Journal のイベント（JSONL、1行1イベント）

共通フィールド: `event_id`, `schema_version`, `run_id`, `seq`（単調増加）, `ts`, `type`, `prev_hash`（任意・改ざん検出の補助。匿名化や完全性保証ではない）。

| type | 追加フィールド | 書込みタイミング |
|---|---|---|
| `run_started` | `profile_hash`, `mode`, `target`, `budget`, `engine_version` | 開始時（秘密値は含めない） |
| `task_added` | `task_id`, `capability`, `depends_on`, `dedupe_key` | 計画確定時 |
| `gate_decision` | `action_id`, `verdict`, `reason_codes`, `args_hash` | **実行の前**。書込み失敗なら実行しない |
| `action_started` / `action_finished` | `action_id`, `status`, `requests_used`, `llm_usage`, `evidence_ids`, `summary` | 実行前後 |
| `task_state` | `task_id`, `state` | 状態遷移 |
| `run_finished` | `scan_id`, `state`（completed/partial/failed/cancelled）, `errors` | 最終化時（`_finalize` と同じ契約） |

保存先: `reports/runs/<run_id>/journal.jsonl`（`reports/` は gitignore 済み・ローカル保存のみ）。`run_id` は `scan_id` と別に持ち、`run_finished` で対応づける。
`run_id` はパスに使うため生成形式で検証する（`EvidenceStore` のID検証と同じ方式で、任意パスを拒否）。
**P3.2 の `events.jsonl` と排他・破損末尾回復のルールを共有する**ため、実装は「追記・再生・回復」を `journal.py` の小さな共通部品として書き、P3.2が同じ部品を使えるようにする。

### 3.3 Policy Gate（Phase Aで実装する検査の部分集合）

上位設計 §6.2 のうち、Phase Aで実装・テストするもの:

1. **スコープ**: ターゲットのoriginが `allowed` に含まれ `excluded` に含まれない。**自律経路では空の許可リストを `deny`**（`scope.empty_allowlist`）。`normalize_origin()` を再利用。
2. **カタログ**: 未登録capabilityは `deny`（`capability.unknown`）。
3. **副作用クラス**: T0/T1はプロファイルが許可していれば `allow`。T3は**有効な `ApprovalGrant`（§11.2）がある場合のみ `allow`**。なければ `needs_approval`（Phase Aには承認UIがないため実行せず記録）、期限切れ・引数不一致・再利用は `deny`。`mutating=True` のcapabilityをT3以外で登録しようとしたら登録時エラー。
4. **予算**（§11.3）: Runの残リクエストが0なら `deny`（`budget.requests_exhausted`）。残量が正なら開始を許可し、**Action単位の上限で丸ごと拒否しない**（旧経路は残予算まで進むため）。**実送信の計数は引き続き `HttpTransport` が正**で、Gateは二重計数せず実測消費をジャーナルへ記録する。
5. **重複**: 同じ `dedupe_key` が `done` または `running` なら `deny`（`dedupe.already_done`）。
6. **fail closed**: `gate_decision` のジャーナル書込みに失敗したら `deny` 扱いで実行しない。

Phase Aで**実装しない**もの（後続Phase）: 承認キュー、引数中URLの再検査（Plannerが引数を作らないため。Phase Cで必須化）、再計画上限。

### 3.4 ScriptedRunner

固定のタスク列（`authenticate → crawl → gen_probes → fuzz_points → idor_compare → save_evidence → triage → finalize`）を、依存順に実行する。
各タスク前に `is_stopped()` を確認し、STOP時は残りを `skipped` とし、`cancelled` で最終化する（現行の `_safe_run` の契約と同じ）。終了処理は通常Actionと独立し、`finally` で保証する（§11.6）。
注入点なしの場合は現行どおり、以降のタスクを `skipped`（理由: `no_injection_points`）として最終化する。これは現行の `_finish(0, ...)` の早期終了と等価な結果にする。

## 4. 既存機能への影響と互換性

| 項目 | 影響 |
|---|---|
| 既存GUIのWEB FUZZ | 変更なし。新経路は別エントリ（ランナー関数）で、`gui/` は触らない |
| `FuzzAgent.run()` | 変更しない。capabilityは既存メソッドを呼ぶだけ |
| `WebFuzzer` / `HttpTransport` | 原則変更なし。公開プロパティ追加等の最小変更が必要になった場合は、その変更だけで既存selftestが全通過することを条件にする |
| `config.json` | 新設定は追加しない（Phase Aは設定ファイルを増やさず、Runnerの引数で受ける） |
| AGENTS.md §2 のディレクトリ構成 | **実ファイルが存在してから**追記する |
| 新トグルの扱い | 新経路は既定でOFF（既存エントリが従来動作）。OFF時に従来動作が完全に元通りであることはテストで固定 |

### 4.1 既存の `scope_mode=warn` / 空 `allowed_targets` との関係

既存GUI経路は後方互換のため「空リスト＝全許可、warn」のまま。新経路（自律ランナー）は**別の要件**として空の許可リストを拒否する。
これは既存の安全機構の弱体化ではなく、新規機能の要件の設定であり、旧動作を残すOFFトグルを新経路に付けない。

## 5. 安全上の注意

- Gateは**検査を足すだけ**で、`HttpTransport` の既存検査（同一origin、予算、レート、リダイレクト、STOP、応答上限）を置き換えない・迂回しない。capabilityが `requests` を直接呼んではならない（テストで機械的に確認: `agents/fuzz_capabilities.py` と `core/autonomy/` に `requests.` の直接呼出がないこと）。
- ジャーナルとLLM入力に認証値を入れない。`args` は参照名のみ、`summary` は `redaction` 通過済みの文字列のみ。
- ジャーナルはローカル保存のみ（外部送信なし）。容量・件数に上限を設ける。**超過は省略ではなく `JournalFull` で拒否する（fail closed）**: 監査記録を黙って欠落させるより、記録できない判断を実行しない方が安全なため。`run_finished` のみ上限の対象外で、上限到達後も終了を記録できる。
- 「検出のみ・非エクスプロイト・同一オリジン・リクエスト上限」の既存境界を緩めない。

## 6. テスト方針（すべて実LLM・外部ネットワーク不要）

`tools/run_selftest.py` に統合する新規テスト（既存の `test_*` 関数の流儀に合わせる）。基準サーバーは `testlab/vuln_server.py` またはテスト内の `http.server` を `127.0.0.1` の空きポートで起動する。LLMはモック。

| # | 内容 | 判定 |
|---|---|---|
| A1 | **等価性**: 同一fixture・同一モックLLMで、従来経路とScriptedRunnerの `ScanResult`（findingsの`rule_id`/`location`/severity、coverage、state、errorsの種別、実送信数）が一致 | 一致。差があれば理由を説明できること |
| A2 | **範囲外canary**: 外部action/別origin/別portを含むページを返す基準サーバーと、受信を記録する別originサーバー | 別originの受信が0 |
| A3 | 空の許可リストで開始 | `deny`、送信0、`run_finished.state=failed`、理由がジャーナルに残る |
| A4 | 未登録capabilityのAction | `deny`、実行されない |
| A5 | 同じ `dedupe_key` を2回投入 | 2回目は`deny`、送信数は1回分 |
| A6 | ジャーナル書込み失敗（読取専用ディレクトリ等） | 実行されない（fail closed）、エラーが最終結果に載る |
| A7 | STOP（実行中・待機中） | 新しい送信が始まらない、残りタスクが`skipped`、`cancelled`、DONEは一度だけ |
| A8 | 予算N（0を含む） | 実送信がN以下、0なら認証も送らない（P0.1の条件を維持） |
| A9 | **ジャーナル再生**: 途中で打ち切ったジャーナルから、タスクグラフが同じ状態に再構築される | 状態一致。末尾の部分行は警告付きで回復、途中行の破損は失敗 |
| A10 | 機密非漏えい: 固定ダミーのCookie/パスワード | ジャーナル・結果要約・LLMモックの受信内容のいずれにも現れない |
| A11 | 新経路OFFの既存動作: 既存経路のselftest全項目が従来どおり | 既存の `SELFTEST_NON_LLM_ONLY=1` 結果が退行しない（外部ネットワーク項目の失敗は従来と分けて報告） |
| A12 | 静的検査: `core/autonomy/`・`agents/fuzz_capabilities.py` に送信の直接呼出（`requests.`、`urllib`、`socket`）がない | なし |

## 7. 完了条件

1. A1〜A12が通る（外部ネットワーク項目の失敗は今回の変更と分けて報告し、黙って省略しない）。
2. 既存のselftestが退行していない（`SELFTEST_NON_LLM_ONLY=1`）。実LLM系は未疎通なら「未検証」と明記。
3. ジャーナルを人間が読んで、各Actionの実行/拒否の理由を追跡できること（サンプルを1件、ドキュメントに載せる）。
4. 実装後に AGENTS.md §2（ディレクトリ構成）・§4、PRACTICAL_ROADMAP の状態、IMPLEMENTATION_LOG.md を同期（実装完了後にのみ行う）。
5. 「自律的になった」とは主張しない。Phase Aは自律性ゼロの骨格であり、効果は等価性と安全試験でのみ主張する。

## 8. 実装の小分け（レビュー可能な単位）

> 2026-10-21改訂: 実際の着手順序は [AUTONOMOUS_IMPLEMENTATION_PLAN.md](AUTONOMOUS_IMPLEMENTATION_PLAN.md) §2 を正とする（特性化試験とcoverage事実化を前倒し）。下表は部品の分割の目安。

| 単位 | 内容 | この単位で確認すること |
|---|---|---|
| A1 | `journal.py`（追記・再生・回復・容量上限）と単体テスト | A9, A6 |
| A2 | `actions.py` / `policy_gate.py` / `budget.py` と単体テスト | A3〜A5, A8の一部 |
| A3 | `fuzz_capabilities.py`（既存メソッドを呼ぶだけの薄い層） | A12 |
| A4 | `runner.py`（スクリプト化計画、STOP、最終化） | A7, A8 |
| A5 | 等価性・安全試験（A1, A2, A10, A11）をselftestへ統合 | 全体 |

## 9. リスクと未決事項

| リスク | 対応案 |
|---|---|
| 等価性が取れない（`ThreadPoolExecutor`による出力順の違い等） | 比較は順序非依存の集合比較で行う。順序依存の差は別に記録して説明する |
| `FuzzAgent.run()` の描画/ログ出力がcapability化で変わる | Phase Aは画面出力の同一性を要件にしない（所見・coverage・stateの同一性を要件にする）。GUI統合は等価性確認後に別判断 |
| `fuzzer.fuzz()` を1 Actionにすると、途中のSTOPに粗い | Phase Aでは `HttpTransport` の既存STOP対応に委ねる（粒度の細分化はPhase C） |
| ジャーナルが監査ログと再開用状態を兼ねることによる肥大 | 容量・件数上限と省略理由の記録。LLM全文は既定で保存しない |
| P3.2 の台帳設計と二重実装になる | `journal.py` の共通部品をP3.2が再利用する。着手前にP3.2側のスキーマ（event_id/schema_version）と合意する |

**決定済み（2026-10-21）**: 上位設計 §9 #1〜#3（P2.1と並行可、ジャーナルは同一スキーマ・別ファイル、LLM全文は既定で保存しない）。

## 10. 調査レポート反映による補足（2026-10-21）

詳細と判断理由は [AUTONOMOUS_PLATFORM_DESIGN.md](AUTONOMOUS_PLATFORM_DESIGN.md) §2.4。Phase Aへの影響のみ記す。

- **ジャーナルは監査記録、実行状態の永続化は別**: Phase AのRun Journalは判断・実行の追記式記録として実装する。Phase B（再開）で実行状態をSQLite（WAL）に置くかは上位設計 §9 #7 で決定済み（SQLite WAL、監査記録はJSONL。本Phaseでは未実装）。どちらでもA9（ジャーナル再生の整合）は監査記録の整合試験として有効。
- **`exhausted` 状態の追加**: `TaskState` に `exhausted`（上限到達）を設け、`done` と区別する。coverageでは `tested` に数えない。試験A8（予算N）で、予算切れのタスクが `exhausted` になり、結果が `partial` になることを確認する。
- **承認のタイムアウトは常に deny**: 承認が無いT3は `needs_approval` として記録して実行しない。期限切れの承認は `deny`。承認の契約は §11.2（以前の「T3は常に実行拒否」という記述は撤回し、§11.2に一本化した）。
- **Assetの `candidate`/`authorized` 区別**: `web.crawl` が見つけた外部originの資産は `candidate` として記録するだけで、送信対象にしない。A2（範囲外canary）で、candidateへの送信が0であることを確認する。
- **未決事項の追加**: 送信直前の解決先IP再検査（上位設計 §9 #8（Phase Cの前に独立した変更単位。Phase Aには含めない））。Phase Aで扱うなら `HttpTransport` への変更が必要になり、「`HttpTransport` は原則変更なし」の前提が崩れるため、実装前に別の変更単位として決める。

## 11. 契約の確定（実装計画レビュー反映・2026-10-21）

実装計画のレビュー6点を既存コードと照合し、いずれも妥当と判断した（根拠は各項）。A2以降の判断基準になる契約をここで固定する。

### 11.1 副作用クラスと POST（レビュー1）

- 確認: `WebFuzzer._send()` は `method == "POST"` なら `data=fields` で送信し（`tools/web_fuzzer.py` の `_send`）、注入点の `method` はフォームの `method` 属性由来。つまりPOSTフォームの注入点が実際に送信される。上位設計 §6.1 はPOSTをT3（個別承認）としており、`web.fuzz_points` を一律T1とした旧記述は宣言と動作が食い違っていた。
- 契約: 新経路の `web.fuzz_get_points` は**GET注入点だけ**を対象にする（呼び出し側で絞る。`WebFuzzer`は変更しない）。POST注入点はcoverageに `skipped`（`post_requires_approval`）で残し、送信しない。
- GETは副作用なしの保証ではない（`/logout?` のような例がある）。T1は「プロファイルで読み取り検査を許可した」場合のみ自動実行し、残余リスクをレポートに明記する。
- 既存のGUI経路はPOSTも送信する。これは**変更しない**。新経路との差は意図的な差として期待値に固定する（§11.5）。

### 11.2 承認（ApprovalGrant）の契約（レビュー2）

- 確認: 旧記述は §2表（開始時の明示設定で認証を許可）、§3.3（設定があれば`allow`）、§10（T3は常に拒否）の3箇所で食い違っていた。
- 契約: **認証設定**（プロファイルの認証参照: どの役割にどの資格情報か）と**承認**（そのActionを実行してよい）は別。承認は `ApprovalGrant` で表す。
  - 項目: `grant_id`、`capability`、`args_hash`（対象origin・メソッド・認証参照名・役割a/bを含む正規化引数のハッシュ）、`expires_at`、`single_use`（常にTrue）、`issued_by`。
  - Runnerの開始引数としてユーザーが明示的に渡す。LLMや他エージェントは発行できない。時計は注入可能（試験用）。
  - Gateは、`args_hash` 一致・未失効・未使用を検査し、`approval_consumed` イベントを**実行前に**書く。書けなければ実行しない。
  - 理由コード: `approval.missing`（needs_approval）、`approval.expired`、`approval.args_mismatch`、`approval.reused`（いずれもdeny）。
  - A認証とB認証は別Action・別Grant。片方の承認でもう片方は実行されない。
- 受け入れ条件: 未承認・期限切れ・引数変更・再利用・A/B取り違えがすべて拒否され、承認通りの場合のみ実行される。

### 11.3 予算の三層とcoverageの事実化（レビュー3）

- 確認: `FuzzAgent._build_coverage()` は検出された注入点を一律 `tested` にする（docstringも「全プローブ完遂の保証ではない」と認めている）。`WebFuzzer.fuzz()` の返り値は異常一覧だけで、`_fuzz_point` は予算切れで `[]` を返すため、「検査して異常なし」と「予算不足で未実施」を区別できない。また、旧記述の「Actionの `max_requests` が残量を超えたら丸ごと拒否」は、残予算まで進む旧経路と非等価。
- 契約（三層）:
  1. **Run予算**: `HttpTransport` の `max_requests`。送信の唯一の真実。
  2. **Action上限**: `CapabilitySpec.max_requests` は**情報用**（Phase Aでは拒否に使わない）。強制する場合は transport 側の下位予算が必要で、Phase C以降で別途設計する。
  3. **実測消費**: Action前後の transport 計数の差をジャーナルへ記録。
  - Gateの予算判定は「Run残が0なら拒否、正なら開始許可」のみ。
- 検査実績の最小変更（独立コミット）: `WebFuzzer` に、検査単位（注入点×カテゴリ）ごとの実行記録を貯める**追加のみ**の仕組みを入れる（返り値・既存挙動は不変、スレッドセーフ）。項目: 対象・メソッド・パラメータ・カテゴリ・計画プローブ数・実送信数・状態（`completed` / `exhausted` / `stopped` / `not_started` / `transport_error`）・理由。同カテゴリで最初の兆候が出て打ち切った場合は `completed`（理由 `first_signal`）。
- coverage: `completed` のみ `tested`。他は `skipped`（理由に状態名）または `failed`。旧 `_build_coverage` は旧経路用に残す。
- 受け入れ条件: 予算0、途中枯渇、ちょうど完遂（予算＝必要数）の3ケースで実施済みと未実施が正しく区別される。

### 11.4 結果不明（unknown_outcome）と再開（レビュー4）

- 確認: 実行状態をSQLite、監査をJSONLに分ける決定（上位設計 §9 #7）の下では、「送信先が処理した直後・ローカル完了記録の前」に停止すると、ローカル記録だけでは実行済みか判別できない。再開試験の「二重実行なし」だけでは足りない。
- 契約: `action_started` を送信**前**に必ず記録する（write-ahead）。再生で `action_started` があり `action_finished` が無いタスクは `unknown_outcome` とし、**自動再実行しない**（既定）。予算は不明分を巻き戻さない（開始時点の予約を消費済みとして扱う）。再実行は新しいActionとして、Gateを通し直し、必要なら承認を得る。
- A2: `TaskState` に `unknown_outcome` を含める（型と再生時の判定のみ）。回復処理（SQLiteとJSONLの突合）は **Phase B**。そのとき両ストアに**共通の `event_id`** を持たせ、片側だけ保存された場合の照合手順を定義する。
- Phase Bの受け入れ条件: 送信直後／結果保存直前／監査追記直前で停止させ、不明状態の保持・予算の非巻き戻し・無断再送なしを検証。

### 11.5 等価性は先に・逐次に（レビュー5）

- 確認: 旧計画は「順5で初めて既存経路と比較」だった。POST・coverageの問題はcapability境界に関わるため、最後に発見するとA2〜A4に戻る。
- 契約: A2より前に、現行経路の**特性化試験（characterization）**を作る。固定fixture（GET/POSTフォーム・認証あり/なし）をローカルサーバーに用意し、モックLLMで現行経路を実行して基準を取る。capabilityを1つ足すたびに同じ装置で比較する。
- 比較の仕方: 所見・coverage・stateに加え、**サーバー側で観測した (メソッド, パス, クエリ/本文) の回数（多重集合）**を比較する。集合化は二重送信・二重所見を隠すため使わない。
- 非決定性の扱い: 予算が途中で枯渇する場合は、ThreadPoolExecutorの競合でどの注入点が消費するかが変わる。このケースは多重集合の一致を要求せず、「総送信数 ≤ 予算」と「未実施の分類」だけを検査する。多重集合比較は予算が拘束しないケースで行う。
- 意図的な差は期待値として事前に固定する（例: 新経路のPOST受信は0、旧経路のPOST数は特性化試験で記録）。

### 11.6 終了処理の独立（レビュー6）

- 確認: `core/autonomy/journal.py` は書込み失敗後に writer を使用不能にする（`_broken`）。固定計画の末尾に `report.finalize` を置くだけだと、監査記録の失敗で終了できなくなり得る。
- 契約: Runnerは `finally` で次を**この順**に行う。(1) 新規送信を止める（stop）。(2) 監査の `run_finished` を試みる（失敗は握りつぶさず `errors` に追加）。(3) `ScanResult` を確定し RESULT→DONE を**一度だけ**通知する。監査記録が書けなくても(3)は必ず通る。
- 失敗点ごとの挙動: Gate判断の記録に失敗→そのActionは実行せず、以降の送信を止める／`action_started` 記録に失敗→実行しない／送信後に `action_finished` を書けない→結果はメモリ上にあるが `unknown_outcome` 相当として扱い、以降の送信を止める／`run_finished` に失敗→errorsへ反映。いずれも最終状態は `partial` か `failed`（`completed` にしない）。
- `run_finished` の容量上限除外は無制限ではなく、**一度だけ・1件16KBまで・書いた後は終端**とした（`journal.py` 実装済み）。
- 受け入れ条件: 上記の各失敗点で、新規送信の停止と最終結果へのエラー反映、DONEの一度きりを確認する。

## 12. 実装上の注意の反映（2026-10-21）

別のレビュー（実装上の注意6点）を既存コードと照合し、妥当と判断して取り込んだ。上位設計への反映先と合わせて記す。

| 注意 | 判断 | 反映 |
|---|---|---|
| 最初の到達点を「一本の診断が最後まで通ること」に絞る | 妥当（Phase Aの方向と一致。到達点を明文化） | 実装計画 §2.1 のM1。合格条件に「所見から証拠・Action・Gate判断まで辿れる」を追加 |
| Plannerは決定論的な優先順位方式にも勝てるか比較する | 妥当。さらに、決定論の優先順位は状態機械の `FALLBACK_PLAN` として元々必要で、実装コストが小さい | 上位設計 §7.3（3方式比較）、Phase CをC0／C1に分割。LLM Plannerを既定にする条件を「C0に対する測定された改善」とした。fixtureが小さいうちは優劣を主張しない |
| FactとHypothesisの区別を保存時の規則にする | 妥当。確認: 現行の `corroborated` は検証パス（同じ材料のLLM再レビュー）で付く。新経路では観測に基づく規則とし、経路間で意味が違うことを明記 | 上位設計 §3.6（登録主体・必須項目・支持の数え方・昇格規則・既存実装との差）。実装はFact Store（Phase B以降）。Phase Aでは行わない |
| 証拠の版管理を最小限だけ前倒しする | 妥当。確認: 現行の証拠は内容ハッシュ・Action ID・マスキング版・切り詰め印を持たず、本文は黙って切り詰められる | 上位設計 §3.7、実装計画 順3b（追加のみの独立コミット） |
| 「進捗」と「完了」をLLMの文章量から切り離す | 妥当。旧 `no_progress_counter` は「新規Fact/Hypothesis更新」で、言い換えやID発行でリセットされ得た | 上位設計 §5.1（進捗に数える3つの変化）、§5.2（`end_reason`）。Phase Aは `run_finished` の `end_reason` と `errors` への記載のみ。`ScanResult` への追加は別途 |
| LLM予算を呼出前に制限する | 妥当。確認: `LLMClient.stream/complete` は `max_tokens` を渡さず使用量も捨てている。そのため出力上限と実使用量の記録には `LLMClient` への追加が必要 | 上位設計 §5.1、実装計画 順5b。Phase Aの範囲は呼出回数・入力サイズ・期限・再試行。トークン上限と実コストは取得できる範囲だけ（取得不能は `unknown`） |

注意点: 順3のfixtureを P2.1 と共用する（二重に作らない）。ただし P2.1 の本体（`benchmark.py`・集計器・基準値の保存）はM1の後で良い。

## 13. 実装で確定した現行経路との意図的な差（2026-10-22、`tools/test_fuzz_autonomy.py` で固定）

新経路 `agents/fuzz_capabilities.py: AutonomousFuzzAgent` と現行 `FuzzAgent` の差。これ以外（予算が拘束しない場合の
送信先・メソッド・回数の多重集合、異常、所見）は一致することを試験で確認している。

| 差 | 現行 | 新経路 | 理由 |
|---|---|---|---|
| POST注入点 | 送信する | 送信しない。coverage=`skipped:post_requires_approval`、状態=`partial` | T3（§11.1） |
| coverage | 注入点ごとに一律 `tested` | 注入点×カテゴリの実績。未実施は `skipped`（理由付き） | §11.3 |
| ファジングが1件も実行できなかった場合 | トリアージ（LLM）を実行 | 実行しない（観測が無く、LLMに「異常なし」と言わせないため） | 無意味なLLM費用と誤解を避ける |
| 到達できない対象（ページ0件） | 注入点なしの扱いで `completed` | `failed`（理由付き） | 未到達を完了にしない |
| 許可対象 | `config.json` のscope設定（空=全許可） | 呼び出し引数で明示必須（空=Gateが拒否） | 自律実行の要件（§4.1） |
| 認証 | 対応 | 未対応（指定されたら `failed`。黙って無視しない） | 承認の契約を接続するまで実行しない |
