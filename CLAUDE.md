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
