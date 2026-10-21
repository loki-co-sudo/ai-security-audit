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
| 認証（A/B） | `fuzzer.authenticate()` / `authenticate_b()` | `web.authenticate` | **T3相当（認証情報の送信）** | Phase Aではプロファイルで明示された認証のみ許可。Planner不在なので承認は「実行開始時の明示設定」で代替し、ジャーナルに記録 |
| クロール・注入点検出 | `fuzzer.crawl(base_url)` | `web.crawl` | T1 | 結果: `injection_points` を `Asset`相当の記録へ |
| プローブ生成 | `self._gen_probes(points)`（FAST） | `llm.gen_probes` | T0 | 送信なし。LLM呼出は予算台帳に計上 |
| ファジング | `fuzzer.fuzz(points, probes)` | `web.fuzz_points` | T1 | 内部でThreadPoolExecutor。**1回の実行をActionにする**（注入点単位への分割はPhase C以降） |
| 認可チェック | `idor_skip_reason()` → `fuzzer._detect_idor(points)` | `web.idor_compare` | T2（GET限定） | 認証状態が不明ならskipし理由を記録（既存挙動を保存） |
| 証拠保存 | `_save_evidence(...)` | `evidence.save` | T0 | `save_evidence` 設定時のみ |
| AIトリアージ＋検証パス | `_stream_llm` / `_verify_findings` | `llm.triage` | T0 | STRONG。マスク済みサマリーのみ入力 |
| 結果確定 | `_findings_from_markers` / `_build_coverage` / `_determine_state` / `_finish` | `report.finalize` | T0 | `_finalize()`（RESULT→DONEを一度だけ）の契約を保つ |

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
3. **副作用クラス**: T3は、プロファイルに明示された承認事項（認証の使用）がある場合のみ `allow`、なければ `needs_approval`（Phase Aには承認UIがないため、結果は実行拒否として記録）。
4. **予算**: `BudgetLedger` のリクエスト・時間の残量。タスクの `max_requests` が残量を超えるなら `deny`。**実送信の計数は引き続き `HttpTransport` が正**（Gateは二重計数せず、実測値をジャーナルへ記録する）。
5. **重複**: 同じ `dedupe_key` が `done` または `running` なら `deny`（`dedupe.already_done`）。
6. **fail closed**: `gate_decision` のジャーナル書込みに失敗したら `deny` 扱いで実行しない。

Phase Aで**実装しない**もの（後続Phase）: 承認キュー、引数中URLの再検査（Plannerが引数を作らないため。Phase Cで必須化）、再計画上限。

### 3.4 ScriptedRunner

固定のタスク列（`authenticate → crawl → gen_probes → fuzz_points → idor_compare → save_evidence → triage → finalize`）を、依存順に実行する。
各タスク前に `is_stopped()` を確認し、STOP時は残りを `skipped` とし、`cancelled` で最終化する（現行の `_safe_run` の契約と同じ）。
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
- ジャーナルはローカル保存のみ（外部送信なし）。容量・件数に上限を設け、超過は省略理由を記録（`EvidenceStore` と同じ方針）。
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
- **承認のタイムアウトは常に deny**: Phase Aには承認UIがないため、T3は常に実行拒否として記録されるが、「承認待ち→期限切れ→deny」の遷移型だけは先に定義する（後から`allow`を設定可能にしない）。
- **Assetの `candidate`/`authorized` 区別**: `web.crawl` が見つけた外部originの資産は `candidate` として記録するだけで、送信対象にしない。A2（範囲外canary）で、candidateへの送信が0であることを確認する。
- **未決事項の追加**: 送信直前の解決先IP再検査（上位設計 §9 #8（Phase Cの前に独立した変更単位。Phase Aには含めない））。Phase Aで扱うなら `HttpTransport` への変更が必要になり、「`HttpTransport` は原則変更なし」の前提が崩れるため、実装前に別の変更単位として決める。
