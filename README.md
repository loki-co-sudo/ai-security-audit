# AI Security Audit System
**Autonomous Penetration Testing & Defense Platform v2.1**

> シグネチャ（既知パターン）に依存しない、AI駆動型・次世代自律ペネトレーションテスト＆脆弱性露出管理システム

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![CustomTkinter](https://img.shields.io/badge/CustomTkinter-5.2.2-darkblue)
![LLM](https://img.shields.io/badge/LLM-Ollama%20%2F%20OpenAI%20%2F%20OpenRouter-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 概要

本ツールは、セキュリティ専門家・研究者向けの **AI自律エージェントによるセキュリティ診断プラットフォーム**です。  
既知のCVEやシグネチャへの依存をなくし、大規模言語モデル（LLM）による **文脈理解・推論・異常検知** を組み合わせることで、従来ツールでは発見困難な**未知の脆弱性・設計上の論理的欠陥**を自律的に探索します。

### 3つの動作モード

| モード | 概要 | ターゲット |
|--------|------|-----------|
| **CODE AUDIT** | Pythonコードをセマンティック解析し、SQLi・IDOR・競合状態など設計上の脆弱性を発見 | `.py` ソースファイル |
| **ATTACK MODE** | ターゲットに対してAIが自律的にポートスキャン・HTTP探査・攻撃仮説生成を実施（許可されたターゲットのみ） | Webサービス・サーバー |
| **DEFENSE MODE** | ログファイルをリアルタイム監視し、攻撃パターンをMITRE ATT&CK準拠でAI分類・即時アラート | アクセスログ |

---

## スクリーンショット

### CODE AUDIT — セマンティック脆弱性解析

AIがコードの文脈を読み取り、CVEに存在しない論理的欠陥（タイミング攻撃・競合状態・認可不備など）を炙り出す。

![CODE AUDIT](docs/screenshot_audit.png)

### ATTACK MODE — 自律ペネトレーションテスト

ポートスキャン → サービス特定 → Web探査 → LLMによる攻撃仮説生成まで、AIエージェントが自律的に実行。  
**必ず許可されたターゲットに対してのみ使用すること。**

![ATTACK MODE](docs/screenshot_attack.png)

### DEFENSE MODE — リアルタイム脅威監視

ログをリアルタイムで追跡し、攻撃パターン（SQLi・XSS・コマンドインジェクション等）を即時検知。  
AIが攻撃者のTTP（戦術・技術・手順）をMITRE ATT&CKフレームワークで分類し、防御アクションを提示。

![DEFENSE MODE](docs/screenshot_defense.png)

---

## アーキテクチャ

```
AI-Security-tool/
├── main.py                    # エントリポイント（スプラッシュ→遅延ロード→App起動）
├── config.json                # LLM接続設定（gitignore済み・APIキー含む可能性あり）
├── requirements.txt           # 依存ライブラリ一覧
├── Dockerfile                 # Dockerコンテナ定義
├── docker-compose.yml         # Docker Compose設定
├── 起動.bat                   # Windowsランチャー（コンソールあり）
├── 起動_silent.bat            # Windowsランチャー（コンソールなし）
├── 起動.sh                    # Linuxランチャー
├── 起動.command               # macOSランチャー（Finderダブルクリック対応）
├── core/
│   ├── settings.py            # 全設定・カラーテーマ定数
│   ├── config.py              # config.jsonの読み書き（settings.pyをデフォルトとしてフォールバック）
│   ├── event_bus.py           # スレッドセーフUIイベントバス（Queue-based）
│   ├── llm_client.py          # OpenAI互換LLMクライアント（Ollama/OpenAI/OpenRouter・ホットリロード対応）
│   └── orchestrator.py        # LangGraph StateGraph（条件付き深層解析ループ）
├── agents/
│   ├── base_agent.py          # エージェント抽象基底クラス（threading.Event管理）
│   ├── audit_agent.py         # CODE AUDIT エージェント（CVE照合付き）
│   ├── langgraph_audit_agent.py # LangGraph強化型監査エージェント
│   ├── recon_agent.py         # ATTACK MODE エージェント（偵察・仮説生成）
│   └── monitor_agent.py       # DEFENSE MODE エージェント（ログ監視・脅威分析）
├── tools/
│   ├── network_scanner.py     # Socket-basedポートスキャナ（nmap不要）
│   ├── web_prober.py          # HTTP探査・技術スタック指紋採取
│   ├── log_watcher.py         # tailf式リアルタイムログ追跡（標準ライブラリのみ）
│   ├── cve_client.py          # NVD API v2クライアント（CWE→CVE照合・キャッシュ付き）
│   ├── report_generator.py    # HTMLレポート生成（ダークテーマ・脆弱性詳細付き）
│   ├── run_selftest.py        # 全機能セルフテスト（GUI以外を網羅）
│   └── capture_screenshots.py # README用スクリーンショット自動撮影
├── gui/
│   ├── app.py                 # メインウィンドウ（3タブ、DPI対応、⚙設定ボタン）
│   ├── splash.py              # 起動スプラッシュスクリーン（tkinter製・高速表示）
│   ├── dialogs/
│   │   └── settings_dialog.py # LLM接続設定ダイアログ（接続テスト・設定保存）
│   ├── widgets/
│   │   ├── output_box.py      # カラータグ付きAI出力ボックス
│   │   └── progress_steps.py  # ステップ進捗ウィジェット（DETECTION SUMMARY付き）
│   └── panels/
│       ├── audit_panel.py     # CODE AUDIT タブ（LangGraphトグル・レポート出力）
│       ├── attack_panel.py    # ATTACK MODE タブ（レポート出力）
│       └── defense_panel.py   # DEFENSE MODE タブ（レポート出力）
├── assets/
│   ├── create_icon.py         # アプリアイコン生成スクリプト（PIL）
│   ├── icon.ico / icon.png    # 生成済みアプリアイコン
├── samples/
│   └── target_code.py         # CODE AUDIT 動作確認用のサンプル脆弱コード
├── docs/                      # 設計書・スクリーンショット
└── reports/                   # スキャン結果出力先（ローカル保存のみ）
```

### 設計上の重要な決定

- **EventBus パターン**: エージェント（バックグラウンドスレッド）とGUI（メインスレッド）を完全に分離。  
  `queue.Queue` を使いスレッドセーフなメッセージパッシングを実現し、tkinterのスレッド制約を回避。
- **BaseAgent抽象クラス**: `threading.Event` による停止シグナリング。全エージェントが `is_stopped()` で中断できる。
- **DPI-aware ウィンドウ**: `GetDpiForWindow()` でWindowsの150%スケーリング環境に完全対応。
- **ストリーミングLLM出力**: 各AIチャンクをEventBus経由でリアルタイムにGUIへ流す。
- **設定の永続化**: `config.json` にLLM接続設定を保存。APIキーを含む可能性があるためgitから除外。

---

## 技術スタック

| 分類 | 技術 |
|------|------|
| 言語 | Python 3.10 以上 |
| GUIフレームワーク | CustomTkinter 5.2.2（ダークモード） |
| LLMバックエンド | Ollama + `qwen2.5-coder:14b`（デフォルト）/ OpenAI / OpenRouter（OpenAI API互換） |
| LLMクライアント | `openai` ライブラリ（OpenAI互換エンドポイント） |
| ネットワーク | `socket`（標準ライブラリ、nmap不要）、`requests` |
| 並行処理 | `threading`、`concurrent.futures.ThreadPoolExecutor` |
| ログ監視 | カスタムtailf実装 |
| セキュリティ参照 | MITRE ATT&CK、OWASP Top 10 |

---

## セットアップ

### 前提条件

- Python 3.10 以上
- [Ollama](https://ollama.ai/) インストール済み（ローカルLLM使用時）

### インストール

```bash
# 1. リポジトリのクローン
git clone https://github.com/turara-coder/ai-security-audit.git
cd ai-security-audit

# 2. 依存ライブラリのインストール
pip install -r requirements.txt

# 3. Ollamaモデルの準備（ローカルLLM使用時）
ollama pull qwen2.5-coder:14b

# 4. 起動
python main.py
```

### ダブルクリックで起動（OS別ランチャー）

| OS | ファイル | 動作 |
|---|---|---|
| Windows | `起動.bat` | コンソールウィンドウあり（エラー確認用・開発向け） |
| Windows | `起動_silent.bat` | コンソールなし・GUIのみ起動（デモ・展示向け） |
| Linux | `起動.sh` | `chmod +x 起動.sh` 後にダブルクリック / `./起動.sh` |
| macOS | `起動.command` | Finderでダブルクリックすると Terminal で起動 |

いずれも `py` / `python3` / `python` を自動検出して `main.py` を実行します。

---

### Docker で起動（オプション）

```bash
# イメージをビルドして起動（X11フォワーディングが必要）
docker compose up --build

# Windows — VcXsrv を起動後に:
docker run -e DISPLAY=host.docker.internal:0.0 ai-security-audit

# Linux — WSLg / Xサーバー使用時:
docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix ai-security-audit
```

---

## 使い方

### LLM接続設定（初回必須）

ヘッダー右上の **⚙ ボタン**から設定ダイアログを開く。

| 項目 | 説明 |
|---|---|
| BASE URL | Ollama: `http://localhost:11434/v1` / OpenAI: `https://api.openai.com/v1` / OpenRouter: `https://openrouter.ai/api/v1` |
| API KEY | Ollama: `ollama`（任意文字列） / OpenAI: `sk-...` / OpenRouter: `sk-or-v1-...` |
| MODEL | `qwen2.5-coder:14b`、`openai/gpt-4o`、`anthropic/claude-sonnet-4-5` など |

プリセットボタン（Ollama / OpenRouter / OpenAI / LM Studio）でBASE URLをワンクリック入力できる。  
「**接続テスト**」ボタンで疎通確認後、「保存」で `config.json` に書き込まれ次回起動時も保持される。

> **OpenRouter** 使用時は、`HTTP-Referer` / `X-Title` ヘッダーが自動付与されます（BASE URLに `openrouter.ai` を含む場合のみ）。

---

### CODE AUDIT モード

1. `「📂 ファイルを選択」` ボタンでPythonファイルを選択
2. **ENGINE 選択**: `Standard`（通常） または `LangGraph`（強化モード）を選択
   - **LangGraph モード**: CRITICAL 発見時に深層解析ループを自動実行。より徹底した攻撃チェーン分析。（要 `pip install langgraph`）
3. `「AI 監査を開始 ▶」` をクリック
4. 左ペインでステップ進捗を確認、右ペインでAI解析結果をリアルタイム受信
5. スキャン完了後、右上の `「📊 レポート出力」` ボタンでHTML形式のレポートを生成・保存

**検出対象の例**:
- SQLインジェクション（クエリ文字列結合）
- 予測可能なトークン生成
- TOCTOU競合状態
- タイミング攻撃の脆弱性
- 水平IDOR（不正オブジェクトアクセス）
- パストラバーサル
- 認可ロジックの設計欠陥

### ATTACK MODE（許可されたターゲットのみ）

1. ターゲットURL/IPを入力（例: `https://example.com` または `192.168.1.1`）
2. Intensity（passive / moderate / aggressive）を選択
3. 必要に応じて「Web Probe」をオン/オフ
4. `「SCAN ▶」` をクリック

> **重要**: 本ツールはセキュリティに精通した専門家が、**許可されたターゲットに対する診断のみ**に使用することを前提としています。  
> 無許可のスキャンは不正アクセス禁止法等の法律に違反します。実行はすべて利用者の責任で行ってください。

### DEFENSE MODE

1. `「📄 ログ選択」` でアクセスログを選択（または `「🔧 サンプル生成」` でテスト用ログを作成）
2. 「継続監視モード」チェックで、ファイル末尾をリアルタイム追跡するか選択
3. `「▶ 監視開始」` をクリック
4. 左ペインの **ALERT TIMELINE** で即時アラートを確認、右ペインでAI詳細分析を受信
5. `「📊 レポート出力」` で検知結果をHTMLレポートに出力

---

## セキュリティポリシー

本ツールは以下のポリシーに従って設計されています：

- **発見特化**: 脆弱性の「発見」に特化し、実際のエクスプロイト送信機能は実装しない
- **ローカル保存**: スキャン結果はローカルにのみ保存し、外部への自動送信は行わない
- **非破壊的**: ブルートフォース攻撃・DoS・C2通信・マルウェア生成機能は実装しない
- **専門家向け**: 本ツールはセキュリティ専門家の利用を前提とし、許可された対象のみへの使用を利用者の責任において求める

---

## 開発ロードマップ

- [x] GUIプロトタイプ（CustomTkinter、ダークモード）
- [x] CODE AUDIT エージェント（セマンティック解析）
- [x] ATTACK MODE エージェント（ポートスキャン + AI偵察）
- [x] DEFENSE MODE エージェント（リアルタイムログ監視・ALERT TIMELINE）
- [x] 3タブ統合GUIアプリケーション
- [x] LLM接続設定ダイアログ（接続テスト・config.json永続化）
- [x] クロスプラットフォームランチャー（Windows / Linux / macOS）
- [x] OpenRouter対応（推奨ヘッダー自動付与・モデルプリセット）
- [x] HTMLレポート自動生成（応用情報・セキスペ基準準拠・ダークテーマHTML）
- [x] CVEデータベース連携（NVD API v2 — CWEから関連CVEを自動照合）
- [x] LangGraphマルチエージェントオーケストレーション（StateGraph + 条件付き深層解析ループ）
- [x] コンテナ対応（Dockerfile + docker-compose.yml）
- [x] 起動スプラッシュ画面・アプリアイコン・起動高速化
- [x] 全機能セルフテスト（`tools/run_selftest.py`）

### 今後の拡張予定
- [ ] 拡張ポートスキャン（UDP対応・OS検出ヒューリスティック）
- [ ] Webファジングエージェント（クローリング→入力特定→AIペイロード生成）
- [ ] レポートのPDF出力対応

---

## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。

**本ツールは教育・研究・許可されたセキュリティ診断を目的としています。  
いかなる不正アクセスにも使用しないでください。**
