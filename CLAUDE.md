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
     パターン検出/ReportGenerator/CVEClient）はLLM呼び出しを行わず、常に全通過が必須。
     ただし3（`example.com` へのDNS解決）・4（`example.com` へのHTTPプローブ）・
     8（NVD APIへのCVE照合）は外部ネットワークに到達する。オフライン環境ではこの3件は
     失敗しうるので、その場合も完了報告に明記する（黙って省略しない）。
   - テスト**9以降**（LLMClient・AuditAgent・MonitorAgent・ReconAgent・FuzzAgent 等）は
     `config.json` で疎通可能なLLMエンドポイント（ローカルOllama起動中 or クラウドAPIキー設定済み）
     を要求する。**未設定時の失敗モードは一様ではない**: LLMClientの疎通テストは明確に
     `FAIL`するが、MonitorAgent/ReconAgent/FuzzAgent はローカルの正規表現パターン検出や
     「完走したか」のみを検証するため、LLM呼び出しが失敗・空応答でも**PASSしうる**
     （`_complete_llm`/`_stream_llm` が例外を握りつぶしログに記録する設計のため）。
     したがって9以降のPASS数は「LLMが正しく機能した証拠」にはならない。
     疎通確認は `.venv/bin/python3 -c "import core.config as c; c.load(); print(c.get('llm_base_url'))"`
     の値に実際に何か listen しているかで判断する。未疎通の場合は1〜8・2bの全通過を最低ラインとし、
     完了報告に「9以降はLLMエンドポイント未疎通のため未検証（PASSしたものも含め信頼しない）」
     と明記する。
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
