# AI Security Audit System — 設計書 v2.0
## Autonomous Penetration Testing & Defense Platform

---

## 1. プロジェクト概要

### ビジョン
シグネチャ（既知パターン）に依存せず、AIが自律的に未知の脆弱性を探索・防御する次世代セキュリティプラットフォーム。
ポートフォリオとして企業へ提示した際、ホワイトハッカーとしての技術力で圧倒的な差別化を図る。

### 3つの動作モード

| モード | 目的 | ターゲット |
|--------|------|-----------|
| **CODE AUDIT** | ソースコードの論理バグ・未知脆弱性の推論 | Pythonファイル等 |
| **ATTACK MODE** | 許可された対象への自律ペネトレーションテスト | URL / IP / CIDR |
| **DEFENSE MODE** | リアルタイム攻撃検知・ログ解析・防御支援 | ログファイル / システム |

---

## 2. システムアーキテクチャ

```
┌──────────────────────────────────────────────────────────────────────┐
│                        GUI Layer (CustomTkinter)                      │
│  ┌─────────────┐  ┌──────────────────┐  ┌────────────────────────┐  │
│  │  CODE AUDIT │  │  ATTACK MODE     │  │  DEFENSE MODE          │  │
│  │  (Audit     │  │  (Recon + AI     │  │  (Log Watch + Alert    │  │
│  │   Panel)    │  │   Analysis)      │  │   + AI Analysis)       │  │
│  └──────┬──────┘  └────────┬─────────┘  └──────────┬─────────────┘  │
└─────────┼──────────────────┼──────────────────────  ┼───────────────┘
          │                  │                         │
          └──────────────────┼─────────────────────────┘
                             │
          ┌──────────────────▼─────────────────────────┐
          │              Event Bus                      │
          │     (queue.Queue, thread-safe UI updates)   │
          └──────────────────┬─────────────────────────┘
                             │
          ┌──────────────────▼─────────────────────────┐
          │           Agent Orchestrator                │
          │   (スレッド管理、エージェント起動・停止)      │
          └──────┬────────────┬────────────────┬────────┘
                 │            │                │
         ┌───────▼──┐ ┌───────▼──┐ ┌──────────▼──┐
         │  Audit   │ │  Recon   │ │  Monitor    │
         │  Agent   │ │  Agent   │ │  Agent      │
         └───────┬──┘ └───────┬──┘ └──────────┬──┘
                 │            │                │
         ┌───────▼──┐ ┌───────▼──┐ ┌──────────▼──┐
         │  (LLM)   │ │  Network │ │  Log        │
         │  Code    │ │  Scanner │ │  Watcher    │
         │  Analyzer│ │  + Web   │ │             │
         └──────────┘ │  Prober  │ └─────────────┘
                      └──────────┘
                             │
          ┌──────────────────▼─────────────────────────┐
          │              LLM Client                     │
          │   (OpenAI-compatible streaming API)         │
          │   Ollama / OpenAI / 任意のLLMバックエンド    │
          └────────────────────────────────────────────┘
```

---

## 3. ディレクトリ構造

```
AI-Security-tool/
├── DESIGN.md                    # 本ドキュメント
├── main.py                      # エントリーポイント
├── gui_audit_app.py             # v1.0 レガシー（互換性維持）
│
├── core/                        # アプリ共通基盤
│   ├── __init__.py
│   ├── settings.py              # 全設定（LLM, テーマ, etc.）
│   ├── llm_client.py            # LLM通信抽象層（ストリーミング対応）
│   └── event_bus.py             # スレッドセーフUI更新キュー
│
├── agents/                      # AIエージェント群
│   ├── __init__.py
│   ├── base_agent.py            # 抽象基底クラス
│   ├── audit_agent.py           # コード監査エージェント
│   ├── recon_agent.py           # 偵察・ペネトレーションエージェント
│   └── monitor_agent.py         # 防御監視エージェント
│
├── tools/                       # ツール層（ネットワーク・ファイル操作）
│   ├── __init__.py
│   ├── network_scanner.py       # ポートスキャン・サービス検出
│   ├── web_prober.py            # HTTPプローブ・技術フィンガープリント
│   └── log_watcher.py           # ログファイル監視・パースン
│
├── gui/                         # GUI層
│   ├── __init__.py
│   ├── app.py                   # メインウィンドウ（3タブ統合）
│   ├── panels/
│   │   ├── __init__.py
│   │   ├── audit_panel.py       # コード監査タブ
│   │   ├── attack_panel.py      # 攻撃モードタブ
│   │   └── defense_panel.py     # 防御モードタブ
│   └── widgets/
│       ├── __init__.py
│       ├── output_box.py        # カラー出力ボックス（共通）
│       └── progress_steps.py    # ステップ進捗ウィジェット（共通）
│
└── reports/                     # 生成レポート出力先
```

---

## 4. モード別詳細設計

### 4.1 CODE AUDIT モード

**フロー:**
```
ファイル選択
    ↓
[Step 1] ファイル読み込み・行数確認
    ↓
[Step 2] AST/CFG構造解析（コンテキスト構築）
    ↓
[Step 3] LLM: 論理バグ・未知脆弱性の推論（ストリーミング）
    ↓
[Step 4] 深刻度スコアリング（CRITICAL/HIGH/MEDIUM/LOW）
    ↓
[Step 5] 修正パッチコード生成
    ↓
[Step 6] 監査レポート最終化
```

**LLM役割:** コードのセマンティクスを理解し、既知CVEにない論理的欠陥を推論する

---

### 4.2 ATTACK MODE（ペネトレーションテスト）

> ⚠️ **要認証**: 実行前に「この対象への試験は許可されている」に同意必須

**フロー:**
```
ターゲット入力（URL/IP/CIDR） + 認証確認チェックボックス
    ↓
[Phase 1: RECON] ポートスキャン + バナーグラブ
    - 開放ポート検出
    - サービス・バージョン特定
    - OS フィンガープリント（TTL解析）
    ↓
[Phase 2: ENUM] Webターゲットの場合
    - HTTPヘッダー解析（Server, X-Powered-By, etc.）
    - セキュリティヘッダー欠如チェック
    - 技術スタック推定（Cookie名, レスポンス, metaタグ）
    - センシティブパス探索（robots.txt, .git, .env等）
    - SSL/TLS証明書情報
    ↓
[Phase 3: AI ANALYSIS] LLMが探索結果を統合分析
    - 発見サービス・バージョンの既知脆弱性推論
    - 攻撃チェーン仮説の構築
    - 未知の構成ミスの推定
    ↓
[Phase 4: REPORT] 優先度付き脆弱性リスト生成
    - Attack Surface Map
    - リスクスコア（CVSS類似）
    - 推奨ペネトレーション手順
```

**LLM役割:** 収集した技術情報から、実際の攻撃者視点で脆弱性仮説を構築する

---

### 4.3 DEFENSE MODE（リアルタイム防御監視）

**フロー:**
```
ログソース指定（ファイルパス / ディレクトリ）
    ↓
[継続監視] ファイル変更検知（watchdog）
    ↓
[パターンマッチ] 既知攻撃シグネチャ（SQLi, XSS, LFI, RCE, Brute Force等）
    ↓
[AI分析] 新着ログをLLMに送信 → 攻撃意図・深刻度・攻撃者TTPs推定
    ↓
[アラート生成] 
    - CRITICAL: 即座のインシデント対応が必要
    - HIGH: 詳細調査が必要
    - MEDIUM: 監視強化
    - LOW: 記録のみ
    ↓
[防御レスポンス提案]
    - IP ブロック推奨
    - WAFルール提案
    - パッチ適用推奨
    - フォレンジック手順
```

**LLM役割:** ログ文脈全体を読み、シグネチャにない攻撃パターン（APTアクター手法等）を検知する

---

## 5. コンポーネント詳細

### 5.1 Event Bus
```python
class EventBus:
    # イベント種別
    EVENT_LOG       = "log"      # システムログ
    EVENT_OUTPUT    = "output"   # AI出力テキスト（タグ付き）
    EVENT_STEP      = "step"     # ステップ進捗更新
    EVENT_ALERT     = "alert"    # 防御アラート
    EVENT_STATS     = "stats"    # 検出統計更新
    EVENT_STATUS    = "status"   # ステータスバー更新
    EVENT_DONE      = "done"     # 処理完了
```

### 5.2 LLM Client
```python
class LLMClient:
    # ストリーミングAPI（各チャンクをEvent Busにpush）
    def stream(self, messages, on_chunk: Callable[[str], None])
    # 非ストリーミング（一括取得）
    def complete(self, messages) -> str
```

### 5.3 Agent基底クラス
```python
class BaseAgent(ABC):
    def run(self, **kwargs) -> None    # バックグラウンドスレッドで実行
    def stop(self) -> None             # 停止シグナル送信
    def _log(self, msg: str)           # Event Bus経由でログ送信
    def _output(self, text, tag="")    # Event Bus経由でAI出力送信
    def _set_step(self, i, state)      # ステップ状態更新
```

---

## 6. セキュリティ・倫理ガイドライン

### 使用上の注意
1. **ATTACK MODE は許可された対象にのみ使用すること**
2. ツールは脆弱性「発見」に特化し、実際のエクスプロイト送信機能は実装しない
3. スキャン結果はローカルにのみ保存し、外部に自動送信しない
4. レポートには「AUTHORIZED PENETRATION TEST REPORT」の注記を付与

### ツールが実装しない機能（意図的除外）
- エクスプロイトペイロードの自動送信
- マルウェア・バックドアの生成
- 認証情報の総当たり攻撃（Brute Force）
- DDoS攻撃ツール
- C2（Command & Control）通信

---

## 7. 技術スタック

| カテゴリ | 技術 | 用途 |
|---------|------|------|
| GUI | CustomTkinter 5.x | ダークモードUI |
| LLM | OpenAI-compatible API | Ollama(Qwen) / OpenAI |
| HTTP | requests 2.x | Webプローブ |
| ファイル監視 | watchdog 6.x | ログ変更検知 |
| ネットワーク | socket (標準) | ポートスキャン |
| 非同期 | threading + queue | スレッドセーフUI |
| データ | 標準ライブラリのみ | 外部DB不要 |

---

## 8. 開発ロードマップ（優先順位順）

### Phase 1 — コアアーキテクチャ（本セッション）
- [x] DESIGN.md 作成
- [ ] core/ モジュール（settings, llm_client, event_bus）
- [ ] agents/base_agent.py
- [ ] gui/widgets/ 共通部品

### Phase 2 — CODE AUDIT 移植
- [ ] agents/audit_agent.py（gui_audit_app.py から抽出）
- [ ] gui/panels/audit_panel.py

### Phase 3 — ATTACK MODE 基本
- [ ] tools/network_scanner.py
- [ ] tools/web_prober.py
- [ ] agents/recon_agent.py
- [ ] gui/panels/attack_panel.py

### Phase 4 — DEFENSE MODE 基本
- [ ] tools/log_watcher.py
- [ ] agents/monitor_agent.py
- [ ] gui/panels/defense_panel.py

### Phase 5 — 統合・仕上げ
- [ ] gui/app.py（3タブ統合）
- [ ] main.py
- [ ] 動作検証

### 将来拡張（Phase 6+）
- LangGraph マルチエージェントオーケストレーション
- CVEデータベース連携
- HTML/PDF レポート自動生成
- Docker コンテナ化
- Slack/webhook アラート通知
