# AI Security Audit System — 設計書 v2.3
## Autonomous Penetration Testing & Defense Platform

---

## 1. プロジェクト概要

### ビジョン
シグネチャ（既知パターン）に依存せず、AIが自律的に未知の脆弱性を探索・防御する次世代セキュリティプラットフォーム。
ポートフォリオとして企業へ提示した際、ホワイトハッカーとしての技術力で圧倒的な差別化を図る。

### 4つの動作モード

| モード | 目的 | ターゲット |
|--------|------|-----------|
| **CODE AUDIT** | ソースコードの論理バグ・未知脆弱性の推論 | Pythonファイル等 |
| **ATTACK MODE** | 許可された対象への自律ペネトレーションテスト | URL / IP / CIDR |
| **WEB FUZZ** | Webアプリの注入点検出＋検出のみファジング（兆候観測） | Webアプリケーション |
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
├── main.py                      # エントリーポイント（スプラッシュ→遅延ロード→App起動）
├── config.json                  # 実行時LLM設定（gitignore済み）
│
├── core/                        # アプリ共通基盤
│   ├── settings.py              # 全設定（LLM, テーマ, APP_VERSION 等）
│   ├── config.py                # config.json 読み書き（settings.py をフォールバック）
│   ├── llm_client.py            # LLM通信抽象層（ストリーミング・OpenRouterヘッダー自動付与）
│   ├── event_bus.py             # スレッドセーフUI更新キュー
│   └── orchestrator.py          # LangGraph StateGraph（条件付き深層解析ループ）
│
├── agents/                      # AIエージェント群
│   ├── base_agent.py            # 抽象基底クラス
│   ├── audit_agent.py           # コード監査エージェント（CVE照合付き）
│   ├── langgraph_audit_agent.py # LangGraph強化型監査エージェント
│   ├── recon_agent.py           # 偵察・ペネトレーションエージェント
│   ├── fuzz_agent.py            # Webファジングエージェント（検出のみ）
│   └── monitor_agent.py         # 防御監視エージェント
│
├── tools/                       # ツール層
│   ├── network_scanner.py       # ポートスキャン・サービス検出
│   ├── web_prober.py            # HTTPプローブ・技術フィンガープリント
│   ├── web_fuzzer.py            # Webスマートファザー（クロール・注入点検出・異常観測）
│   ├── log_watcher.py           # ログファイル監視（tailf式ポーリング）
│   ├── cve_client.py            # NVD API v2 クライアント（CWE→CVE照合）
│   ├── report_generator.py      # HTML/PDFレポート生成
│   ├── pdf_writer.py            # 日本語対応PDFレンダラー（Pillowのみ）
│   ├── create_shortcut.py       # デスクトップショートカット生成（Windows）
│   ├── run_selftest.py          # 全機能セルフテスト
│   └── capture_screenshots.py   # スクリーンショット自動撮影
│
├── gui/                         # GUI層
│   ├── app.py                   # メインウィンドウ（4タブ統合・DPI対応）
│   ├── splash.py                # 起動スプラッシュスクリーン
│   ├── export_util.py           # HTML/PDFレポート出力共通ヘルパー
│   ├── dialogs/
│   │   └── settings_dialog.py   # LLM接続設定ダイアログ
│   ├── panels/
│   │   ├── audit_panel.py       # コード監査タブ
│   │   ├── attack_panel.py      # 攻撃モードタブ
│   │   ├── fuzz_panel.py        # Webファジングタブ
│   │   └── defense_panel.py     # 防御モードタブ
│   └── widgets/
│       ├── output_box.py        # カラー出力ボックス（共通）
│       └── progress_steps.py    # ステップ進捗ウィジェット（共通）
│
├── assets/                      # アプリアイコン・生成スクリプト
├── samples/                     # 動作確認用サンプル脆弱コード
├── docs/                        # 設計書（本書）・スクリーンショット
├── 起動.bat / 起動_silent.bat   # Windowsランチャー
├── 起動.sh / 起動.command       # Linux / macOS ランチャー
└── reports/                     # 生成レポート出力先（gitignore済み）
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

> ⚠️ **専門家向け**: セキュリティに精通した利用者が、許可された対象のみに使用すること（v2.1 でUI上の認可チェックボックスは廃止）

**フロー:**
```
ターゲット入力（URL/IP） + スキャンプロファイル選択
    （stealth=既定 / passive / moderate / aggressive）
    ↓
[Phase 1: RECON] ポートスキャン + バナーグラブ（プロファイル制御）
    - 開放ポート検出（stealth時は走査順ランダム化＋接続ジッター＋低並列）
    - サービス特定
    - SSL/TLS証明書情報取得
    - 受動OSフィンガープリント（バナー解析・追加通信なし）
    ↓
[Phase 2: ENUM] Webターゲットの場合
    - HTTPヘッダー解析（Server, X-Powered-By, etc.）
    - セキュリティヘッダー欠如チェック
    - 技術スタック推定（Cookie名, レスポンス, metaタグ）
    - センシティブパス探索（robots.txt, .git, .env等）
      ※stealth時は実在ブラウザUAをローテーション＋探索数を制限＋ジッター
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

### 4.3 WEB FUZZ（スマートファジング — 検出のみ）

**フロー:**
```
ターゲットURL入力（クエリ/フォームを持つWebアプリ）+ プロファイル + REQ予算
    ↓
[Phase 1] クロール: 同一オリジンを浅く辿り、クエリパラメータ・フォーム入力を注入点として抽出
    ↓
[Phase 2] AI検出プローブ生成: LLMが対象パラメータ名から各脆弱性クラス（SQLI/XSS/TRAVERSAL/SSTI）の
          最小の"検出"テストベクタをJSONで生成（組込みプローブとマージ）
    ↓
[Phase 3] ファジング（検出のみ）: 各注入点へプローブを送出し、レスポンス異常を観測
          - 未エスケープ反射（XSSマーカー）/ DBエラー署名（SQLi）
          - /etc/passwd 署名（トラバーサル）/ テンプレ評価 7*7=49（SSTI）
          ※ 総リクエスト数 max_requests で打ち切り（DoS回避）、ジッター/低並列、同一オリジン限定
    ↓
[Phase 4] AIトリアージ: 観測結果をLLMが評価し誤検知を除外、---VULN_START/END--- 形式で報告
```

**安全境界（設計上の不変条件）:** データ窃取・RCE実行・認証回避は行わない。脆弱性の"兆候"を
観測・報告するに留め、エクスプロイトは構築しない。`tools/web_fuzzer.py` がこの境界を担保する。

**LLM役割:** 文脈に応じた検出プローブの生成と、観測された異常の妥当性トリアージ。

---

### 4.4 DEFENSE MODE（リアルタイム防御監視）

**フロー:**
```
ログソース指定（ファイルパス）
    ↓
[継続監視] ファイル末尾をポーリング追跡（tailf式・標準ライブラリのみ）
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
# core/event_bus.py — イベント種別はモジュールレベル定数
LOG    = "log"      # システムログ
OUTPUT = "output"   # AI出力テキスト（タグ付き）
STEP   = "step"     # ステップ進捗更新 {idx, state}
ALERT  = "alert"    # 防御アラート {severity, message, time}
STATS  = "stats"    # 検出統計更新 {CRITICAL:n, ...}
STATUS = "status"   # ステータスバー更新
DONE   = "done"     # 処理完了 {error: bool}
CLEAR  = "clear"    # 出力エリアクリア

class EventBus:
    def emit(self, kind: str, payload=None)  # 送出（put ではない）
    def drain(self, limit=50) -> list[Event] # 非ブロッキング取り出し
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
    def run(self, **kwargs) -> None    # サブクラスが実装。バックグラウンドスレッドで実行
    def start(self, **kwargs) -> None  # スレッド起動（_safe_run でラップ）
    def stop(self) -> None             # 停止シグナル送信（threading.Event）
    def is_stopped(self) -> bool       # 中断チェック
    def _log(self, msg: str)           # Event Bus経由でログ送信
    def _out(self, text, tag="")       # Event Bus経由でAI出力送信
    def _step(self, idx, state)        # ステップ状態更新
    def _stream_llm(self, messages)    # LLMストリーミング→OUTPUTイベント
```

### 5.4 スキャンプロファイル（ステルス制御）
`core/settings.SCAN_PROFILES` が ATTACK MODE のフットプリント（検知されやすさ）
と速度のトレードオフを一元管理する。authorized な診断で IDS / レート検知に
配慮しつつ探査するための、正当なレッドチーム・トレードクラフト。

| プロファイル | threads | jitter(秒) | randomize | path制限 | 特徴 |
|---|---|---|---|---|---|
| `stealth`（既定） | 4 | 0.15–0.6 | ✓ | 12件 | 最も静か。順序ランダム化＋ジッター＋低並列 |
| `passive` | 10 | 0.05–0.25 | ✓ | 全件 | 軽量・控えめ |
| `moderate` | 30 | ~0 | ✓ | 全件 | バランス |
| `aggressive` | 80 | 0 | ✗ | 全件 | 最速・高並列（隔離環境向け） |

- **ポート順ランダム化**: 順次走査（21,22,23…）はIDS検知の典型パターンのため、
  `stealth`/`passive`/`moderate` ではポート順をシャッフルする。
- **タイミングジッター**: 各接続前にランダム遅延を挿入し、レートベース検知を回避。
- **UAローテーション**: `WebProber` は自己申告UA（"Security Audit Tool"）を使わず、
  `STEALTH_USER_AGENTS` の実在ブラウザUAをリクエストごとにローテーションする。
- **受動OSフィンガープリント**: `network_scanner.passive_os_fingerprint()` は
  収集済みバナー・HTTPヘッダーのみからOSを推定し、追加パケットを一切送らない
  （nmap -O のようなアクティブ探査とは異なる完全受動方式）。

```python
# tools/network_scanner.py
NetworkScanner.from_profile("stealth")  # プロファイルを適用して生成
passive_os_fingerprint(open_ports, web_headers) -> str | None
# tools/web_prober.py
WebProber(profile="stealth")            # UAローテーション＋ジッター＋並列制御
```

---

## 6. セキュリティ・倫理ガイドライン

### 使用上の注意
1. **ATTACK MODE / WEB FUZZ は許可された対象にのみ使用すること**
2. ツールは脆弱性「発見・兆候観測」に特化する。WEB FUZZ は検出プローブの送出に留め、エクスプロイト（データ窃取・RCE実行・認証回避）は実装しない
3. WEB FUZZ は総リクエスト数に上限を設け、ジッター/低並列でDoSを回避する。クロールは同一オリジン限定
4. スキャン結果はローカルにのみ保存し、外部に自動送信しない
5. 生成レポート（HTML/PDF）のフッターに「教育・研究・許可されたセキュリティ診断を目的とする」旨の注記を付与

### ツールが実装しない機能（意図的除外）
- エクスプロイト（データ窃取・RCE実行・認証回避）の自動実行 ※ファジングは"検出"のみ
- マルウェア・バックドアの生成
- 認証情報の総当たり攻撃（Brute Force）
- DoS / DDoS 攻撃ツール（リクエスト数を上限制御）
- C2（Command & Control）通信

---

## 7. 技術スタック

| カテゴリ | 技術 | 用途 |
|---------|------|------|
| GUI | CustomTkinter 5.2.2 | ダークモードUI |
| LLM | OpenAI-compatible API | Ollama(Qwen) / OpenAI / OpenRouter |
| HTTP | requests 2.x | Webプローブ・NVD API |
| ファイル監視 | socket + ポーリング（標準） | ログ追跡（tailf式） |
| ネットワーク | socket (標準) | ポートスキャン |
| 非同期 | threading + queue | スレッドセーフUI |
| オーケストレーション | LangGraph（オプション） | StateGraph 反復推論 |
| データ | 標準ライブラリ中心 | 外部DB不要 |

---

## 8. 開発ロードマップ

### 完了済み（v2.3.0）
- [x] WEB FUZZ（web_fuzzer + fuzz_agent + fuzz_panel）— クロール→AI検出プローブ→検出のみファジング→AIトリアージ
- [x] PDFレポート出力（pdf_writer、日本語対応・Pillowのみで依存追加なし）+ HTML/PDF共通エクスポート（export_util）
- [x] デスクトップショートカット生成（create_shortcut）+ タスクバーアイコン対応（AppUserModelID）

### 完了済み（v2.2.0）
- [x] ステルススキャンプロファイル（stealth/passive/moderate/aggressive）
- [x] 受動OSフィンガープリント（バナー・ヘッダー解析）

### 完了済み（v2.1.0）
- [x] コアアーキテクチャ（settings, config, llm_client, event_bus, orchestrator）
- [x] CODE AUDIT（audit_agent + audit_panel、CVE照合付き）
- [x] ATTACK MODE（network_scanner + web_prober + recon_agent + attack_panel）
- [x] DEFENSE MODE（log_watcher + monitor_agent + defense_panel）
- [x] 3タブ統合GUI（app.py）+ main.py + 起動スプラッシュ + アイコン
- [x] LLM接続設定ダイアログ（接続テスト・config.json永続化）
- [x] OpenRouter対応（推奨ヘッダー自動付与・モデルプリセット）
- [x] HTMLレポート自動生成（VULN/THREATマーカーをパース）
- [x] CVEデータベース連携（NVD API v2）
- [x] LangGraph マルチエージェントオーケストレーション（StateGraph + 深層解析ループ）
- [x] Docker コンテナ化（Dockerfile + docker-compose.yml）
- [x] クロスプラットフォームランチャー（Windows / Linux / macOS）
- [x] 全機能セルフテスト（tools/run_selftest.py）

### 将来拡張
- [ ] 拡張ポートスキャン（UDP対応 ※ステルス性とのトレードオフを検討）
- [ ] 認証付きWebアプリのファジング（セッション/CSRFトークン対応）
- [ ] CI/CD統合（GitHub Actions）
- [ ] Slack/webhook アラート通知
