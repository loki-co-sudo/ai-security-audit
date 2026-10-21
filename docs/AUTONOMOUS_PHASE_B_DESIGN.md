# Phase B 詳細設計: 実行状態の永続化・中断からの再開・ヘッドレス実行

作成: 2026-10-22。状態: **B1〜B3 実装済み（2026-10-22）／B4（CLI）未実装**。上位設計: [AUTONOMOUS_PLATFORM_DESIGN.md](AUTONOMOUS_PLATFORM_DESIGN.md) §5.3 / §8 Phase B、
決定済み事項: 同 §9（#7 実行状態はSQLite WAL・監査記録はJSONL）、[AUTONOMOUS_PHASE_A_DESIGN.md](AUTONOMOUS_PHASE_A_DESIGN.md) §11.4（結果不明と再開）。
進捗は [AUTONOMOUS_IMPLEMENTATION_PLAN.md](AUTONOMOUS_IMPLEMENTATION_PLAN.md) が正本。

## 1. 解決する問題

Phase Aの新経路は、プロセスが落ちると途中結果（クロールで見つけた注入点、生成したプローブ、観測した異常）を失い、
ジャーナル（監査記録）から分かるのは「どのActionが開始・完了したか」だけで、後続タスクの入力を復元できない。
再開には、(1) 完了済みタスクの**出力**を持つ状態ストア、(2) 監査記録とのずれを定義どおりに直す手順、
(3) 二重実行・予算の巻き戻しをしない保証、が必要。

## 2. 方針（決定済みの原則の具体化）

| 論点 | 設計 |
|---|---|
| 状態の正本 | 標準ライブラリ `sqlite3`（WAL・`synchronous=FULL`）の `RunStore`。タスク状態・出力・消費済み承認・予算の消費。Run単位で1ファイル（`reports/runs/<run_id>/state.sqlite3`） |
| 監査記録 | 追記式JSONL（Phase A）のまま。判断・実行の時系列。再開の正本ではない |
| 共通ID | ジャーナルの各イベントの `event_id` を、対応するストア行にも記録する。片側だけにある更新を突き合わせるために使う |
| 書込み順序（write-ahead） | ①ジャーナル `action_started` → ②送信を伴う実行 → ③**ストアにtransactionで結果と出力をcommit** → ④ジャーナル `action_finished`。③と④の間で止まった場合は再開時に④を補う（`reconciled`）。①と③の間で止まった場合は結果不明 |
| 結果不明 | `unknown_outcome`。**自動再実行しない**。予算は巻き戻さない（不明分は宣言された上限を消費済みとみなす＝安全側）。再実行は利用者が `retry_unknown` で明示し、`unknown_outcome_retry_authorized` を記録した新しいActionとしてGateを通す |
| 認証セッション | セッション（Cookie等）はプロセス内にしかないため、**再開時に認証を再適用する**。認証Actionは新しいActionとしてGateを通り、**新しいApprovalGrantが必要**（承認は一回限り） |
| プロファイル | `run_started` 時点のプロファイルハッシュ（対象・許可/除外・予算・計画・エンジン版）を保存。再開時に一致しなければ拒否する（スコープの拡大を再開に紛れ込ませない） |
| 予算 | 再開は「前回の消費を引いた残り」。ストアの消費記録（不明分は上限で計上）を使う。利用者が `additional_requests` を明示した場合のみ増やせる |
| 出力の保存 | 出力に含まれる応答本文・ヘッダー・URLは**保存前にマスク**する（`core.redaction`）。生の応答や認証値をSQLiteに残さない |
| ヘッドレス実行 | `cli.py`（P3.1の一部）。`scan fuzz` / `resume` / `status`。秘密値はコマンドラインに渡さず、権限0600の認証ファイルから読む。終了コードはP3.1の規則（0/1/2/130） |

## 3. 再開アルゴリズム（`resume_run`）

1. ジャーナルを開き（単一writerロック）、再生して検証する。途中破損は中止（`JournalCorrupt`）。
2. `RunStore` を開き、`run_id` とプロファイルハッシュを検証する。
3. **突合（reconcile）**: 各タスクについてジャーナルとストアを比べる。

   | ジャーナル | ストア | 処置 |
   |---|---|---|
   | `action_finished` あり | done等 | 一致。何もしない |
   | `action_started` のみ | done等（commit済み） | ストアから `action_finished`（`reconciled=true`）をジャーナルに補う |
   | `action_started` のみ | running／無し | `unknown_outcome` とし、両方へ記録する（自動再実行しない） |
   | `approval_consumed` あり | 消費記録なし | ストアへ補う（再利用を防ぐ） |
   | 無し | commit済み | 起こり得ない順序。破損として中止 |
4. Gateの状態（消費済み承認、重複キーの状態、失敗回数）をストアから復元する。
5. 完了済みタスクの出力から実行文脈（注入点・プローブ・異常・IDOR兆候）を復元する。
6. 計画の残りを実行する。認証タスクは再適用（新しい承認が必要）。`unknown_outcome` のタスクとその依存先は実行されず、結果は `partial`（理由付き）。
7. 通常どおり `close_run` → 最終結果。ジャーナルには `run_resumed` を記録する。

## 4. 受け入れ条件

- 任意の位置（Gate判断後／開始記録後／実行後・ストアcommit前／commit後・完了記録前／完了記録後）で強制終了させ、再開した結果が
  **二重実行なし・Findingの二重作成なし・予算の巻き戻しなし・完了済みタスクの再実行なし**であること（fault injection）。
- 結果不明のActionは再開で自動再実行されず、`retry_unknown` を明示した場合のみ新しいActionとして再実行される。
- 再開で認証を再適用するには新しい承認が必要で、無ければ認証情報は適用されない。
- プロファイル（許可対象・予算など）を変えた再開は拒否される。
- 出力ストアに生の認証値・未マスクの応答本文が残らない。
- 中断せずに完走したRunと、途中で止めて再開したRunの最終所見・coverageが（予算が拘束しない条件で）等価。

## 5. 実装の小分け

| 単位 | 内容 |
|---|---|
| B1 | `core/autonomy/run_store.py`: スキーマ、transaction、マスク済み出力、消費記録、突合用の読み出し |
| B2 | `runner.py` / `policy_gate.py` / `fuzz_capabilities.py` を再開対応に（書込み順序、出力の保存と復元、`resume`、`retry_unknown`、プロファイルハッシュ） |
| B3 | fault injection試験（上記5点）と等価性試験 |
| B4 | `cli.py`: `scan fuzz` / `resume` / `status`、認証ファイル、終了コード。GUIには接続しない |

## 6. 今回やらないこと

資産/探索グラフ・Fact/Hypothesisストア（Phase C以降）、複数Workerの並列、Reconの共通送信層への移行（Phase E）、
GUIからの再開操作、案件プロファイルの永続化（P3.1の残り）、所見台帳の差分（P3.2）。
