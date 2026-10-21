# 自律化 実装計画（手戻りを避ける着手順序）

作成: 2026-10-21。上位設計: [AUTONOMOUS_PLATFORM_DESIGN.md](AUTONOMOUS_PLATFORM_DESIGN.md)（§9で方針決定済み）、
最初のPhase: [AUTONOMOUS_PHASE_A_DESIGN.md](AUTONOMOUS_PHASE_A_DESIGN.md)。実装順序の正本は引き続き
[PRACTICAL_ROADMAP.md](PRACTICAL_ROADMAP.md)で、本書はその範囲内でPhase Aを小さな単位に割る。
状態の凡例: [ ] 未着手 / [x] 完了（検証出力あり）。完了の更新は実際に検証が通ってから行う。

## 1. 手戻りを避けるための原則

1. **依存の少ない部品から積む。** 他へ依存されるもの（ジャーナル → Gate → capability → Runner）を下から順に作り、各単位で単体テストを通してから次へ進む。
2. **後続が前提にする契約を最初に固定する。** ジャーナルのイベント形式（`schema_version`、`seq`、`prev_hash`）、IDの検証規則、破損時の挙動は、P3.2の台帳が再利用するため、A1で確定する。後から変えると台帳側も壊れる。
3. **1単位 = 1コミット。** 各コミットはその時点で `SELFTEST_NON_LLM_ONLY=1` の既存結果を退行させない。
4. **既存コードは変更しない方針で始め、変更が必要になったら別コミットに分ける。** 特に `HttpTransport`/`WebFuzzer`/`FuzzAgent` への変更は、等価性試験が通る状態を保てる最小の単位にする。
5. **新経路は既定でOFF。** 既存のGUI経路は従来動作のまま（Phase Aの間は新経路をGUIへ接続しない）。
6. **開発ループ**（CLAUDE.md/AGENTS.md）: 変更→検証→修正を最大5回、同じエラーが2回連続したら止めて報告。テストの弱体化はしない。

## 2. 実装順序

| 順 | 単位 | 内容 | 依存 | 完了条件（検証） |
|---|---|---|---|---|
| 0 | 設計文書のコミット | 設計3本＋本書 | なし | リンク・制御文字の検査 |
| 1 [x] | **A1 `core/autonomy/journal.py`** | 追記式JSONL、`seq`/`prev_hash`、`run_id`検証、単一writer排他、部分行回復、容量上限（fail closed）、機密マスク | なし | 単体テスト（追記・再生・部分行・途中破損・hash不整合・排他・上限・マスク・不正run_id）がselftestに統合され通る |
| 2 | A2 `actions.py` / `policy_gate.py` / `budget.py` | `CapabilitySpec`/`Action`/`GateDecision`、Gate検査（スコープ・カタログ・副作用クラス・予算・重複・fail closed・承認タイムアウト=deny）、`TaskState`（`exhausted`含む） | A1 | A3〜A5, A8の一部に相当する単体テスト |
| 3 | A3 `agents/fuzz_capabilities.py` | 既存メソッドを呼ぶ薄い層。`requests`等の直接送信を持たない | A2 | 静的検査テスト（直接送信なし） |
| 4 | A4 `core/autonomy/runner.py` | スクリプト化計画、STOP、`_finalize`契約、`skipped`/`cancelled` | A3 | STOP・予算0・注入点なしの各試験 |
| 5 | A5 等価性・安全試験 | 従来経路との等価性、範囲外canary、機密非漏えい、既存結果の非退行 | A4 | Phase A設計 §6 の A1〜A12 |
| 6 | P2.1（並行可） | ベンチマークと改修前基準値 | P1.2 | PRACTICAL_ROADMAP の受け入れ条件。Phase C以降の前提 |

順4までは、新規ファイルの追加が中心で既存挙動に影響しない。**順5で初めて既存経路との比較**を行う。差が出た場合は、
Phase A設計 §9 のとおり集合比較で説明できる差かを確認し、説明できない差は実装側を直す。

## 3. 各単位の停止・見直し条件

- 検証が通らず、同じエラーが2回連続: 止めて原因・試したこと・残課題を報告する。
- A5で既存経路との等価性が取れない: Phase Aの設計（capability境界の切り方）を見直す。ここまでの部品（A1〜A4）は再利用できる粒度に保つ。
- `HttpTransport` の変更が必要と分かった: 当該変更を独立コミットにし、既存selftestの全通過を条件とする。解決先IP再検査（上位設計 §9 #8）はPhase Cの前の別単位であり、ここには混ぜない。

## 4. 今回の範囲

順0〜順1（A1）まで。A1の完了後にコミットし、結果を報告して次の単位へ進むかを判断する。
実LLM・外部ネットワークを使う試験は追加しない。
