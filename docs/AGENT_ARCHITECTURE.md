# エージェントアーキテクチャ — ロール別モデルルーティング & 推論エフォート

> 本書は lokicode（`C:\Users\herok\projects\lokicode`）のエージェント設計を本ツールへ
> 移植した「マルチモデル / モード選択」機構の設計と、**下位AIモデルが継続実装するための手順**を
> まとめたもの。関連: [DESIGN.md](DESIGN.md) / [../AGENTS.md](../AGENTS.md) /
> lokicode の `specs/effort-presets.md`・`specs/agent-v3.md`・`specs/model-gate.md`。

## 1. なぜ単一モデルより効率的か（動機）

単一モデルで全処理を回すと、「量が出る機械的な処理」も「最終的な専門推論」も同じ
（高価な）モデルを使い、コストと速度で損をする。lokicode の知見は次の2点:

1. **コスト効率ルーティング**: 安価な *思考モデル* に量（調査・下書き・機械的生成）を、
   高性能な *合成モデル* に要所（計画・最終合成・検証）を担わせると、フロンティア級に
   迫る品質を大幅に安く得られる（Mixture-of-Agents / 役割分担）。
2. **推論エフォート**: 検証深度・アンサンブル幅などは「1つの最適点」が無く、
   **コスト↔精度のトレードオフをプリセットで露出**するのが正しい（テスト時計算スケーリング）。

## 2. 本ツールでの対応付け

| lokicode | 本ツール | 実体 |
|---|---|---|
| 合成（強）モデル | **STRONG** | `config.llm_model`。最終推論。`BaseAgent._stream_llm()` |
| 思考（安）モデル | **FAST** | `config.llm_fast_model`。機械的生成。`BaseAgent._complete_llm(role="fast")` |
| 強い検証器（JUDGE） | **検証パス** | `BaseAgent._verify_findings()`（STRONGで敵対的レビュー） |
| エフォート（速度/バランス/品質） | **EFFORT** | `settings.EFFORT_PRESETS` / `config.effort` |
| 難易度ルーター（オート） | 未実装（下記ロードマップ） | — |
| モデル要件ゲート | 未実装（下記ロードマップ） | — |

### 中核の規約（これだけ守れば自動で最適化される）

- **最終的な専門推論（脆弱性トリアージ・攻撃仮説・監査・検証パス）は `_stream_llm()`** を使う。
  → 常に STRONG モデルで走る。
- **量の出る機械的な生成（検出プローブ生成・要約・分類・抽出）は `_complete_llm(role="fast")`** を使う。
  → FAST モデルが設定されていればそちらへ、無ければ STRONG を共用（＝従来と同一挙動）。

新しいLLM呼び出しを追加するときは、この2択のどちらに当たるかで関数を選ぶだけでよい。

## 3. 実装ファイルと責務

| ファイル | 役割 |
|---|---|
| `core/settings.py` | `LLM_FAST_MODEL` / `LLM_FAST_BASE_URL` / `LLM_FAST_API_KEY` の既定、`EFFORT_LEVELS` / `DEFAULT_EFFORT` / `EFFORT_PRESETS` |
| `core/config.py` | 上記の config キー既定値（`llm_fast_model` 等・`effort`） |
| `core/model_router.py` | `current_effort()` / `fast_model_configured()` / `build_fast_client()` / `fast_signature()` |
| `agents/base_agent.py` | `_fast_client()`（キャッシュ付き）・`_complete_llm(role)`・`_effort()`・`_verify_findings()` |
| `core/orchestrator.py` | 深層解析ループ回数を `current_effort()["deep_loops"]` に連動 |
| `gui/dialogs/settings_dialog.py` | EFFORT セグメント・FAST モデル/URL/KEY 入力・保存 |
| `gui/app.py` | ヘッダーの ENGINE 表示に FAST・エフォートを併記 |

### EFFORT_PRESETS のパラメータ

| キー | speed（速度） | balanced（バランス・既定） | quality（品質） |
|---|---|---|---|
| `verify_pass`（STRONGによる検証パス） | ✗ | ✗ | ✓ |
| `cve_lookup`（NVD照合） | ✗ | ✓ | ✓ |
| `deep_loops`（LangGraph深層解析の最大反復） | 0 | 1 | 2 |

エージェントは `self._effort()` でこの dict を取得し、`verify_pass` / `cve_lookup` を分岐する。

## 4. FAST モデルの接続解決順

1. `llm_fast_model` が空 → **ルーティング無効**（STRONG を全処理に共用＝後方互換）。
2. `llm_fast_base_url` / `llm_fast_api_key` が空 → STRONG の接続情報を共用（同一エンドポイントで
   モデル slug だけ変える。OpenRouter で2 slug、Ollama で2ローカルモデルなど）。
3. 両方指定 → 別エンドポイント（例: ローカル Ollama=FAST + クラウド=STRONG）。

## 5. 下位AIモデル向け・継続実装ガイド（優先度順）

以下は lokicode に実装済みだが本ツールには未移植の機能。各項目は独立して着手できる。
**着手前に必ず `py tools/run_selftest.py`（`PYTHONUTF8=1`）で現状を確認**し、
**完了後に §8 の検証**を通すこと。

### 5.1 難易度ルーター（オート振り分け）〔中規模〕
- 参考: lokicode `specs/agent-v3.md` #1、`src/lib/router.ts` の `classifyTask`。
- 目的: 対象/コードの難易度を超軽量1コール（FASTモデル）で `trivial|standard|deep` に分類し、
  エフォートや LangGraph 有効/無効を自動選択する。
- 実装案: `core/model_router.py` に `classify_effort(text, llm) -> str` を追加。
  各パネルの開始時（例 `audit_panel._start_scan`）で「オート」トグルON時のみ分類し、
  結果を config の一時上書きとしてエージェントへ渡す。厳格プロンプトで1語返し、
  解析失敗時は `balanced` にフォールバック。
- UI: 各パネルのオプションバーに「AUTO」チェックボックスを追加。

### 5.2 モデル要件ゲート（弱いモデルの警告）〔小規模〕
- 参考: lokicode `specs/model-gate.md`、`src/lib/modelGate.ts`。
- 目的: FAST/STRONG が「賢さの壁」を下回る、または検証パスに向かないとき設定画面で警告。
- 実装案: `core/model_router.py` に `assess_readiness(strong_id, fast_id, models) -> list[str]`。
  `/v1/models` の応答に知能指数が無い OpenAI 互換が多いため、まずは
  「STRONG と FAST が同一」「FAST が STRONG より高価そうな既知slug」等の**ヒューリスティック警告**に留める。
  `settings_dialog` の接続テスト結果ラベル付近に琥珀色で表示。ブロックはしない。

### 5.3 検証器アンサンブル（judge ensembling）〔小規模・任意〕
- 参考: lokicode `specs/effort-presets.md` §6（見送り扱いだが本ツールでも任意）。
- 目的: `quality` エフォートで `_verify_findings()` を複数回走らせ、共通して残った所見だけ採用。
- 実装案: `_verify_findings()` に `samples: int` 引数を足し、`EFFORT_PRESETS["quality"]` に
  `verify_samples: 2` を追加。マーカー単位で多数決。コスト増のため quality 限定。

### 5.4 モデル別コスト×精度台帳〔大規模・将来〕
- 参考: lokicode ロードマップ「モデル自動最適化（多腕バンディット）」。
- 目的: スキャンごとに (model, 検出数, 所要時間) を `reports/telemetry.jsonl` へ記録し、
  コスパ最良モデルを提案。まずは記録だけ実装。

## 6. コスト/精度の考え方（運用者向け）

- **日常のスキャン**: STRONG=中堅クラウド or ローカル14B、FAST=空 or 廉価slug、EFFORT=balanced。
- **コスト最優先の一次トリアージ**: FAST に廉価モデル、EFFORT=speed（CVE照合・深層解析なし）。
- **重要診断・レポート提出前**: EFFORT=quality（STRONG検証パスで誤検知を削減、深層解析2回）。

## 7. 触ってはいけない不変条件（セキュリティ）

ルーティング/エフォートは**LLMの使い分けだけ**を変える。検出のみ・PoC送信なし・非DoS・
同一オリジン限定・ローカル保存の各境界（[../AGENTS.md](../AGENTS.md) §3）は一切変えないこと。
検証パスやFASTモデルに「エクスプロイトを実行させる」等の変更を加えてはならない。

## 8. 検証

```bash
PYTHONUTF8=1 py tools/run_selftest.py
```

- `2b. CORE — ModelRouter / Effort` が PASS すること（エフォート整合性・FASTルーティング・
  `_fast_client` キャッシュ）。
- 既存の全項目が回帰なく PASS すること。
- 手動: 設定で FAST モデルを空↔設定、EFFORT を speed↔quality に切り替え、
  WEB FUZZ を実行して「プローブ生成が FAST、トリアージが STRONG」で走ること、
  quality 時に `VERIFICATION PASS` が出ることを確認。
