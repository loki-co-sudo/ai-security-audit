# CLAUDE.md

このリポジトリで作業するAIエージェント（Claude Code 等）向けの入口ドキュメント。
**詳細な規約・アーキテクチャ・自己更新ルールは [AGENTS.md](AGENTS.md) を参照**してください
（AGENTS.md が本プロジェクトの正典です）。

## 最初に読むもの

| 目的 | ドキュメント |
|---|---|
| プロジェクト概要・設計規約・禁止事項・再発防止ルール・**AGENTS.md自己更新義務** | [AGENTS.md](AGENTS.md) |
| マルチモデル（STRONG/FAST）ルーティング＆推論エフォートの設計・**継続実装ガイド** | [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) |
| システム設計書 | [docs/DESIGN.md](docs/DESIGN.md) |
| 学習ガイド（脆弱性・攻防・技術スタック） | [docs/ENGINEER_GUIDE.md](docs/ENGINEER_GUIDE.md) |

## 絶対に守ること（要約）

- **スレッド安全**: エージェント（バックグラウンドスレッド）→ GUI は必ず `EventBus` 経由。
- **LLMの役割分担**: 最終推論は `_stream_llm()`（STRONG）、機械的生成は `_complete_llm(role="fast")`（FAST）。
  モデル名・エンドポイントを直書きせず `core/model_router.py` で解決する。エフォート分岐は `self._effort()`。
- **セキュリティ境界を変えない**: 検出のみ・PoC送信なし・非DoS・同一オリジン限定・ローカル保存。
- **変更後は必ず**: `PYTHONUTF8=1 py tools/run_selftest.py` で回帰確認（Windows は cp932 で UnicodeEncodeError になるため UTF-8 強制）。
- **コミットメッセージ**: プレフィックス（`feat:` 等）は英語、説明文は日本語。
- **タスク完了時**: 変化に応じて [AGENTS.md](AGENTS.md) §4/§2/§3 を自己更新する（§5 の義務）。

## 開発ループ（すべてのコーディングタスクに適用）

コーディングは1回きりの「直線」ではなく、チェックが通るまで回す「ループ」で行う:

1. 【変更】コードを修正・追加する。
2. 【検証】`PYTHONUTF8=1 py tools/run_selftest.py` を実行する
   （Linux/macOS では `python3 tools/run_selftest.py`。UTF-8がデフォルトのため `PYTHONUTF8=1` は不要）。
   - テスト**1〜8・2b**（EventBus/config/ModelRouter/NetworkScanner/WebProber/LogWatcher/
     パターン検出/ReportGenerator/CVEClient）は非LLM・非外部ネットワーク前提で、常に全通過が必須。
   - テスト**9以降**（LLMClient・AuditAgent・MonitorAgent・ReconAgent・FuzzAgent 等）は実LLM
     API（`config.json` のキー）と実ネットワーク（`scanme.nmap.org` 含む）を要求するため、
     APIキー未設定の環境では失敗しうる。その場合は1〜8・2bの全通過を最低ラインとし、
     完了報告に「9以降は環境未整備のため未検証」と明記する（黙って省略しない）。
   - 依存パッケージは本リポジトリ専用の `.venv` に閉じてインストールする
     （`python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`）。
     このPCでは他のセキュリティツールを並行開発中のため、グローバル環境・他プロジェクトの
     ファイル/ポート/プロセスに影響を与えない。
3. 【修正】失敗したらエラーログを読み、原因を特定して直し、手順2へ戻る。

停止条件:
- 【成功】上記の最低ラインを満たしたときだけ「完了」と報告する。**通過した出力（末尾）を証拠として添える**。
- 【上限】ループは最大 **5 回**。使い切ったら止めて、何が残っているかを報告する。
- 【手詰まり】**同じエラーが2回連続**したら思考の固着と判断して止め、別コンテキスト
  （新しいセッション/会話）での修復を提案する。

絶対禁止:
- チェック出力（通過の証拠）なしで「完了」と報告すること。
- テストを通すためにアサーションを削除・弱体化・スキップすること。直すのはコードであり、評価基準ではない。
- 上記のセキュリティ境界（検出のみ・PoC送信なし・非DoS・同一オリジン限定・ローカル保存）を、
  チェックを通すために緩めること。
