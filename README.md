# AI Security Audit System
**Autonomous Penetration Testing & Defense Platform v2.4**

> シグネチャ（既知パターン）に依存しない、AI駆動型・次世代自律ペネトレーションテスト＆脆弱性露出管理システム

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![CustomTkinter](https://img.shields.io/badge/CustomTkinter-5.2.2-darkblue)
![LLM](https://img.shields.io/badge/LLM-Ollama%20%2F%20OpenAI%20%2F%20OpenRouter-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 概要

本ツールは、セキュリティ専門家・研究者向けの **AI自律エージェントによるセキュリティ診断プラットフォーム**です。  
既知のCVEやシグネチャへの依存をなくし、大規模言語モデル（LLM）による **文脈理解・推論・異常検知** を組み合わせることで、従来ツールでは発見困難な**未知の脆弱性・設計上の論理的欠陥**を自律的に探索します。

### 4つの動作モード

| モード | 概要 | ターゲット |
|--------|------|-----------|
| **CODE AUDIT** | Pythonコードをセマンティック解析し、SQLi・IDOR・競合状態など設計上の脆弱性を発見 | `.py` ソースファイル |
| **ATTACK MODE** | AIが自律的にポートスキャン（スコープ選択 `common`/`extended`/`full`・UDP対応）・HTTP探査・攻撃仮説生成・PoC生成（**生成のみ／対象へは絶対に送信しない**）を実施（許可されたターゲットのみ） | Webサービス・サーバー |
| **WEB FUZZ** | Webアプリをクロールして注入点を抽出し、AIが生成した検出プローブで脆弱性の兆候（SQLi・XSS・トラバーサル・SSTI）を観測（検出のみ・非エクスプロイト） | Webアプリケーション |
| **DEFENSE MODE** | ログファイルをリアルタイム監視し、攻撃パターンをMITRE ATT&CK準拠でAI分類・即時アラート | アクセスログ |

> **レポート言語**: 設定で **日本語 / English** を事前選択でき、AIの分析出力もレポートもその言語で生成されます。
> **成果物の自動保存**: 調査レポートは `reports/investigation/`、PoC は `reports/poc/` に自動保存されます。
> **コスト最適化（マルチモデル）**: 高価な **STRONG** モデルは最終推論だけに使い、量の出る機械的処理は
> 安価な **FAST** モデルへ自動で振り分けられます。**推論エフォート（速度 / バランス / 品質）** を1クリックで
> 切り替え、コスト・速度・精度のトレードオフを選べます（詳細は下記「LLM接続設定」）。

---

## スクリーンショット

### CODE AUDIT — セマンティック脆弱性解析

AIがコードの文脈を読み取り、CVEに存在しない論理的欠陥（タイミング攻撃・競合状態・認可不備など）を炙り出す。

![CODE AUDIT](docs/screenshot_audit.png)

### ATTACK MODE — 自律ペネトレーションテスト

ポートスキャン → サービス特定 → 受動OS推定 → Web探査 → LLMによる攻撃仮説生成 → PoC生成まで、AIエージェントが自律的に実行。  
**スキャンプロファイル**（`stealth` / `passive` / `moderate` / `aggressive`）でフットプリント（検知されやすさ）と速度を切り替え可能。`stealth` はポート走査順のランダム化・接続ごとのジッター・実在ブラウザUAローテーション・低並列により、IDS/レート検知に引っかかりにくい静かな探査を行う。  
**ポートスコープ**は `common`（既定・主要26ポート）/ `extended`（拡張・約125ポート）/ `full`（全65535ポート）から選択でき、**UDP**スキャン（代表ポート・参考情報）も任意で併用可能。  
**PoC生成**は脆弱性検証用のPoCコードを**ローカルで生成・表示・保存するのみ**で、対象へ送信・実行することはありません（非破壊・検出指向）。  
**必ず許可されたターゲットに対してのみ使用すること。**

![ATTACK MODE](docs/screenshot_attack.png)

### WEB FUZZ — スマートファジング（検出のみ）

Webアプリを浅くクロールしてクエリ・フォームの注入点を抽出 → AIが各脆弱性クラスの**検出プローブ**を文脈推論で生成 → レスポンスの異常（未エスケープ反射・DBエラー署名・テンプレート評価・既知ファイル署名）を観測して脆弱性の兆候を報告。  
**検出のみ・非エクスプロイト**設計で、総リクエスト数に上限を設けDoSを回避。ステルスプロファイルのジッター／低並列を流用し、同一オリジン限定で動作する。  
**🔐 認証付きファジング**にも対応（Cookie / ヘッダー / ログインフォーム＋CSRFトークン自動抽出）し、ログイン後の領域も診断できる。  
**必ず許可されたターゲットに対してのみ使用すること。**

![WEB FUZZ](docs/screenshot_fuzz.png)

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
│   ├── fuzz_agent.py          # WEB FUZZ エージェント（クロール→AIプローブ→検出→トリアージ）
│   └── monitor_agent.py       # DEFENSE MODE エージェント（ログ監視・脅威分析）
├── tools/
│   ├── network_scanner.py     # Socket-basedポートスキャナ（nmap不要・スコープ選択/UDP対応）
│   ├── web_prober.py          # HTTP探査・技術スタック指紋採取
│   ├── web_fuzzer.py          # Webスマートファザー（クロール・注入点検出・異常観測／検出のみ・認証対応）
│   ├── log_watcher.py         # tailf式リアルタイムログ追跡（標準ライブラリのみ）
│   ├── cve_client.py          # NVD API v2クライアント（CWE→CVE照合・キャッシュ付き）
│   ├── report_generator.py    # HTML/PDFレポート生成（ダークテーマ・脆弱性詳細付き）
│   ├── pdf_writer.py          # 日本語対応PDFレンダラー（Pillowのみ・依存追加なし）
│   ├── create_shortcut.py     # デスクトップショートカット生成（Windows）
│   ├── known_vulns.yaml      # 既知サービスバナー脆弱性DB（ローカル照合用）
│   ├── run_selftest.py        # 全機能セルフテスト（GUI以外を網羅）
│   └── capture_screenshots.py # README用スクリーンショット自動撮影
├── gui/
│   ├── app.py                 # メインウィンドウ（4タブ、DPI対応、⚙設定ボタン）
│   ├── splash.py              # 起動スプラッシュスクリーン（tkinter製・高速表示）
│   ├── export_util.py         # レポート出力（HTML/PDF）共通ヘルパー
│   ├── dialogs/
│   │   ├── base.py            # ダイアログ共通基底（確実な前面表示・ダークタイトルバー）
│   │   ├── settings_dialog.py # LLM接続設定（モデル取得/検索・レポート言語・接続テスト）
│   │   ├── help_dialog.py     # 使い方ヘルプ（APIキー取得リンク付き）
│   │   └── auth_dialog.py     # WEB FUZZ 認証設定（Cookie/ヘッダー/ログインフォーム）
│   ├── widgets/
│   │   ├── output_box.py      # カラータグ付きAI出力ボックス
│   │   └── progress_steps.py  # ステップ進捗ウィジェット（DETECTION SUMMARYリアルタイム集計）
│   └── panels/
│       ├── audit_panel.py     # CODE AUDIT タブ（LangGraphトグル・レポート出力）
│       ├── attack_panel.py    # ATTACK MODE タブ（レポート出力）
│       ├── fuzz_panel.py      # WEB FUZZ タブ（プロファイル・REQ予算・レポート出力）
│       └── defense_panel.py   # DEFENSE MODE タブ（レポート出力）
├── assets/
│   ├── create_icon.py         # アプリアイコン生成スクリプト（PIL）
│   ├── icon.ico / icon.png    # 生成済みアプリアイコン
├── samples/
│   └── target_code.py         # CODE AUDIT 動作確認用のサンプル脆弱コード
├── testlab/                   # 検証用ローカル脆弱サイト（標準ライブラリのみ・127.0.0.1限定）
│   ├── vuln_server.py         # 意図的に脆弱なダミーサイト（WEB FUZZ/ATTACK の練習用）
│   └── README.md              # 使い方
├── docs/                      # 設計書・スクリーンショット
└── reports/                   # スキャン結果出力先（ローカル保存のみ）
    ├── poc/                   # 生成されたPoC（自動保存・gitignore）
    └── investigation/         # 調査レポート（自動保存・gitignore）
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
git clone https://github.com/loki-co-sudo/ai-security-audit.git
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

### デスクトップアイコンから起動（Windows）

アプリアイコン（`assets/icon.ico`）はタイトルバー・タスクバーに自動表示されます。  
デスクトップにダブルクリック起動用のショートカットを作るには：

```bash
py tools/create_shortcut.py
```

デスクトップに「AI Security Audit」ショートカット（コンソール窓なしで起動・アイコン付き）が作成されます。OneDrive等でデスクトップがリダイレクトされている環境にも対応しています。

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

ヘッダー右上の **⚙ ボタン**から設定ダイアログを開く。右上の **❓ ヘルプ**から、接続の考え方やAPIキー取得先（外部リンク）を確認できる。

| 項目 | 説明 |
|---|---|
| BASE URL | Ollama: `http://localhost:11434/v1` / OpenAI: `https://api.openai.com/v1` / OpenRouter: `https://openrouter.ai/api/v1` |
| API KEY | Ollama: `ollama`（任意文字列） / OpenAI: `sk-...` / OpenRouter: `sk-or-v1-...` |
| MODEL | STRONG（主）モデル。`qwen3:30b-a3b`、`openai/gpt-5.5`、`anthropic/claude-opus-4.8` など（自由入力） |
| EFFORT | **推論エフォート**（速度 / バランス / 品質）。コスト・速度・精度を1クリックで一括切替 |
| ⚡ FAST | FAST（廉価）モデル（任意）。設定すると機械的処理を安価なモデルへ振り分け。空欄＝主モデルを共用 |
| REPORT | レポート生成言語を **日本語 / English** から選択（AIの分析出力もこの言語になる） |

- プリセットボタン（Ollama / OpenRouter / OpenAI / LM Studio）でBASE URLをワンクリック入力。
- **「↻ 取得」** ボタンで接続先の `/v1/models` から利用可能なモデル一覧を取得し、**検索ボックス＋スクロール一覧**から選択できる（取得結果は `config.json` にキャッシュ）。一覧に無いモデルは MODEL 欄へ直接入力も可能。
- 「**接続テスト**」で疎通確認後、「保存」で `config.json` に書き込まれ次回起動時も保持される。

> **OpenRouter** 使用時は、`HTTP-Referer` / `X-Title` ヘッダーが自動付与されます（BASE URLに `openrouter.ai` を含む場合のみ）。

#### マルチモデル・ルーティングと推論エフォート（コスト・精度の最適化）

単一モデルで全処理を回すより効率的に動かすため、lokicode のエージェント設計を移植しています。

- **STRONG / FAST の役割分担**: 最終的な専門推論（脆弱性トリアージ・攻撃仮説・監査・検証）は **STRONG（主モデル）**、
  量の出る機械的処理（検出プローブ生成・要約など）は **FAST（廉価モデル）** が担当します。**⚡ FAST** を空欄にすると
  全処理を主モデルで行い、従来と完全に同一の挙動になります。FAST の接続先を空欄にすると主モデルの接続を共用し、
  別エンドポイント（例: **ローカル Ollama=FAST + クラウド=STRONG**）を使いたい場合のみ `config.json` の
  `llm_fast_base_url` / `llm_fast_api_key` を設定します。

- **推論エフォート（速度 / バランス / 品質）**: 1つのプリセットでコスト・速度・精度を一括調整します。

  | エフォート | 検証パス（STRONG） | CVE照合 | 深層解析ループ | 用途 |
  |---|---|---|---|---|
  | **速度** | ✗ | ✗ | 0回 | 最速・最安の一次トリアージ |
  | **バランス**（既定） | ✗ | ✓ | 1回 | 従来の既定挙動 |
  | **品質** | ✓ | ✓ | 2回 | 提出前の重要診断（強モデルの検証パスで誤検知を削減） |

  **品質**では、AIの所見に対して STRONG モデルが**敵対的レビュー（検証パス）**を行い、誤検知・過剰主張を除去します。

> 設計と、下位AIモデルが継続実装するための手順は [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) を参照。

#### Claude / Fable モデルの利用（OpenRouter経由）

BASE URL を OpenRouter（`https://openrouter.ai/api/v1`）にすると、Anthropic の Claude モデルを利用できます。MODEL欄は**自由入力**なので、候補に無いモデルもスラッグを直接入力すれば使えます（最新の一覧は「↻ 取得」で取得可能）。

| モデル | スラッグ |
|---|---|
| Claude Opus 4.8 | `anthropic/claude-opus-4.8` |
| Claude Sonnet 4.6 | `anthropic/claude-sonnet-4.6` |
| Claude Fable 5 | `anthropic/claude-fable-5` |
| GPT-5.5 | `openai/gpt-5.5` |

> セルフテスト（`tools/run_selftest.py`）のLLM呼び出しは、コスト削減のため廉価モデルを使用します。環境変数 `SELFTEST_MODEL` で任意モデルに差し替え可能です。

---

### CODE AUDIT モード

1. `「📂 ファイルを選択」` ボタンでPythonファイルを選択
2. **ENGINE 選択**: `Standard`（通常） または `LangGraph`（強化モード）を選択
   - **LangGraph モード**: CRITICAL 発見時に深層解析ループを自動実行。より徹底した攻撃チェーン分析。（要 `pip install langgraph`）
3. `「AI 監査を開始 ▶」` をクリック
4. 左ペインでステップ進捗を確認、右ペインでAI解析結果をリアルタイム受信
5. スキャン完了後、右上の `「📊 HTML」` / `「📄 PDF」` ボタンでレポートを生成・保存（PDFは日本語対応・ダークテーマ）

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
2. Profile を選択（既定は `stealth`）

   | プロファイル | フットプリント | 速度 | 用途 |
   |---|---|---|---|
   | `stealth`（既定） | 最小（順序ランダム化＋ジッター＋低並列＋UAローテーション） | 遅 | 検知を避けたい本番診断 |
   | `passive` | 小 | 中 | 軽量・控えめな探査 |
   | `moderate` | 中 | 速 | バランス |
   | `aggressive` | 大（高並列・ジッターなし） | 最速 | 隔離環境・時間優先 |

3. **PORTS**（ポートスコープ）を選択
   - `common`（既定）= 主要26ポート（**従来と同一挙動**）
   - `extended` = 拡張・約125ポート
   - `full` = 全65535ポート（時間がかかるため隔離環境/`aggressive` 向け）
4. 必要に応じて **UDP**（代表ポートの参考スキャン）/ **Web Probe** / **PoC生成（送信なし）** をオン/オフ
5. `「SCAN ▶」` をクリック

完了すると、調査レポートが `reports/investigation/` に、PoC生成をオンにしていれば PoC が `reports/poc/` に自動保存されます（PoC は**生成・保存のみで対象へは送信しません**）。

> **重要**: 本ツールはセキュリティに精通した専門家が、**許可されたターゲットに対する診断のみ**に使用することを前提としています。  
> 無許可のスキャンは不正アクセス禁止法等の法律に違反します。実行はすべて利用者の責任で行ってください。

### WEB FUZZ（許可されたターゲットのみ）

1. クエリやフォームを持つWebアプリのURLを入力（例: `https://example.com/search?q=test`）
2. Profile（ジッター・並列度）と **REQ BUDGET**（総リクエスト上限＝DoS防止）を選択
3. （任意）**🔐 認証**ボタンで認証情報を設定すると、ログイン後の領域もファジングできる
4. `「FUZZ ▶」` をクリック
5. （認証適用 →）クロール → AI検出プローブ生成 → ファジング（検出のみ）→ AIトリアージの順に自律実行
6. 観測した脆弱性の兆候をAIがトリアージし、`「📊 HTML」` / `「📄 PDF」` でレポート出力

#### 認証付きファジング（🔐 認証）

ログインが必要なWebアプリでも、認証済みセッションでクロール＆検出できます。次の3方式に対応（併用可）:

| 方式 | 入力 | 用途 |
|---|---|---|
| **Cookie** | `sessionid=...; csrftoken=...` | ブラウザのセッションCookieを貼り付け |
| **ヘッダー** | `Authorization` / `Bearer ...` | トークン認証（API・JWT等） |
| **ログインフォーム** | ログインURL・ユーザー名/パスワード欄と値 | フォーム認証。**CSRFトークン（hidden入力）は自動抽出**して送信 |

> **検出のみ・非エクスプロイト**: データ窃取やRCE実行などの攻撃は行わず、レスポンス異常から脆弱性の「兆候」を観測するに留めます。同一オリジン限定・リクエスト数上限つきでDoSを回避します。認証情報はローカルのセッションにのみ使用し、外部送信しません。

### DEFENSE MODE

1. `「📄 ログ選択」` でアクセスログを選択（または `「🔧 サンプル生成」` でテスト用ログを作成）
2. 「継続監視モード」チェックで、ファイル末尾をリアルタイム追跡するか選択
3. `「▶ 監視開始」` をクリック
4. 左ペインの **ALERT TIMELINE** で即時アラートを確認、右ペインでAI詳細分析を受信
5. `「📊 HTML」` / `「📄 PDF」` で検知結果をレポートに出力

---

## セキュリティポリシー

本ツールは以下のポリシーに従って設計されています：

- **検出のみ**: 脆弱性の「発見・兆候観測」に特化する。WEB FUZZ は検出プローブによる異常観測に留め、データ窃取・RCE実行・認証回避などのエクスプロイトは行わない
- **PoCは生成のみ・送信しない**: ATTACK MODE のPoC生成は、検証用コードを**ローカルで生成・表示・保存するのみ**。対象へ送信/実行する経路を持たず、安全ガード（`EXPLOIT_TRANSMISSION_ENABLED=False`）で不変条件を明示。非破壊・検出指向のPoCに限定する
- **非DoS**: 総リクエスト数に上限を設け、ジッター・低並列で過負荷を避ける。ブルートフォース・C2通信・マルウェア生成機能は実装しない
- **ローカル保存**: スキャン結果・PoC・調査レポートはローカルにのみ保存し、外部への自動送信は行わない
- **同一オリジン限定**: WEB FUZZ のクロールはターゲットと同一ホストのみを辿る
- **専門家向け・認可前提**: セキュリティ専門家が、許可された対象のみへ、利用者の責任において使用することを前提とする

---

## 開発ロードマップ

- [x] GUIプロトタイプ（CustomTkinter、ダークモード）
- [x] CODE AUDIT エージェント（セマンティック解析）
- [x] ATTACK MODE エージェント（ポートスキャン + AI偵察）
- [x] DEFENSE MODE エージェント（リアルタイムログ監視・ALERT TIMELINE）
- [x] WEB FUZZ エージェント（クロール→注入点抽出→AI検出プローブ生成→検出のみファジング→AIトリアージ）
- [x] 4タブ統合GUIアプリケーション
- [x] LLM接続設定ダイアログ（接続テスト・config.json永続化）
- [x] クロスプラットフォームランチャー（Windows / Linux / macOS）
- [x] OpenRouter対応（推奨ヘッダー自動付与・モデルプリセット）
- [x] HTMLレポート自動生成（応用情報・セキスペ基準準拠・ダークテーマHTML）
- [x] CVEデータベース連携（NVD API v2 — CWEから関連CVEを自動照合）
- [x] LangGraphマルチエージェントオーケストレーション（StateGraph + 条件付き深層解析ループ）
- [x] コンテナ対応（Dockerfile + docker-compose.yml）
- [x] 起動スプラッシュ画面・アプリアイコン・起動高速化
- [x] 全機能セルフテスト（`tools/run_selftest.py`）
- [x] ステルススキャンプロファイル（ポート順ランダム化・タイミングジッター・低並列・実在UAローテーション）
- [x] 受動OSフィンガープリント（バナー／ヘッダー解析・追加通信なし）
- [x] Webファジングエージェント（クロール→入力特定→AI検出プローブ生成、検出のみ・非エクスプロイト）
- [x] レポートのPDF出力対応（日本語対応・ダークテーマ・Pillowのみで依存追加なし）
- [x] デスクトップショートカット生成（`py tools/create_shortcut.py`）・タスクバーアイコン対応
- [x] レポート言語の選択（日本語 / English — AI出力もレポートも切替）
- [x] モデル一覧の自動取得・検索（接続先の `/v1/models` から取得＋キャッシュ）
- [x] 設定ヘルプ画面（APIキー取得先の外部リンク付き）
- [x] DETECTION SUMMARY のリアルタイム集計（ストリーミング中に逐次更新）
- [x] PoC生成（ATTACK MODE・生成のみ／対象へは送信しない・安全ガード付き）
- [x] PoC・調査レポートの自動保存（`reports/poc/` ・ `reports/investigation/`）
- [x] 拡張ポートスキャン（スコープ選択 `common`/`extended`/`full` ＋ UDP対応・選択式で従来挙動を維持）
- [x] 検証用ローカル脆弱サイト（`testlab/` — 自前で安全に動作確認）
- [x] 認証付きWebアプリのファジング（Cookie / ヘッダー / ログインフォーム＋CSRFトークン自動抽出）
- [x] マルチモデル・ルーティング（STRONG/FAST の役割分担でコスト最適化）＋推論エフォート（速度/バランス/品質）
- [x] 品質エフォート時の検証パス（STRONGモデルによる敵対的レビューで誤検知を削減）

### 今後の拡張予定
主要なロードマップ項目は実装済みです。マルチモデル基盤の上に、以下を継続実装できます
（設計・手順は [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) §5）:
- [ ] 難易度ルーター（オート振り分け）— 対象の難易度を判定しエフォートを自動選択
- [ ] モデル要件ゲート — 弱いモデル/検証に不向きな構成を設定画面で警告
- [ ] 検証器アンサンブル — 品質時に検証パスを複数回走らせ多数決で誤検知をさらに削減

---

## ドキュメント

| ドキュメント | 説明 |
|---|---|
| [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) | マルチモデル・ルーティング＆推論エフォートの設計と、下位AIモデル向け継続実装ガイド（lokicode移植） |
| [docs/ENGINEER_GUIDE.md](docs/ENGINEER_GUIDE.md) | ジュニアエンジニア向け学習ガイド — 脆弱性・ネットワーク・Web技術・AI/LLM・攻防体系・技術スタックを網羅的に解説 |

---

## 改善ロードマップ（精度・速度・堅牢性）

本ツールの精度・速度・堅牢性を継続的に向上させるためのアイディアを以下に整理しています。
各項目は **P0（即効性大・工数小）→ P1（計画的）→ P2（長期検討）** に優先順位付けされており、
**★☆☆〜★★★** で実装難易度を示しています。

> **注記**: Phase 1（P0全7件 + 追加1件）は v2.5 で実装済みです。Phase 2-4 はアイディア段階であり、未実装です。実装の着手順序はロードマップを参照してください。

### ⚡ 速度改善（7件）

| # | アイディア | 優先度 | 難易度 | 期待効果 | 主な影響ファイル |
|---|-----------|--------|--------|----------|-----------------|
| 1 | ~~CVE照合の並列化~~ ✅ v2.5実装済み | 🟢 P0 | ★☆☆ | CVE照合時間を約1/4に短縮 | `audit_agent.py`, `cve_client.py` |
| 2 | ~~CVEキャッシュの永続化~~ ✅ v2.5実装済み | 🟢 P0 | ★☆☆ | 再スキャン時のCVE照合を0秒に | `cve_client.py`, `settings.py` |
| 3 | 独立タスクの並列実行（LLM推論・CVE照合・ポートスキャンを同時進行） | 🟡 P1 | ★★☆ | 全体30〜40%短縮 | 各エージェント |
| 4 | FASTモデルの実設定有効化（`config.json`に`fast_model`追加・役割別ルーティング） | 🟡 P1 | ★★☆ | トークンコスト半減・レイテンシ30〜50%改善 | `model_router.py`, `settings.py` |
| 5 | ストリーミングGUI更新のバッファリング（50msごと/100文字ごとに`insert()`） | 🟡 P1 | ★☆☆ | GUI更新呼び出し回数を1/10〜1/50に削減 | `output_panel.py` |
| 6 | レポート保存の非同期化（`ThreadPoolExecutor.submit()`でfire-and-forget） | 🟡 P1 | ★☆☆ | 保存中のブロッキングをゼロに | `base_agent.py` |
| 7 | トークン事前カウントによるコンテキスト最適化（`tiktoken`で動的トランケーション） | 🔴 P2 | ★★☆ | トークン超過再送回数削減・精度向上 | `audit_agent.py`, `orchestrator.py` |

### 🎯 精度改善（9件）

| # | アイディア | 優先度 | 難易度 | 期待効果 | 主な影響ファイル |
|---|-----------|--------|--------|----------|-----------------|
| 1 | ~~AST静的解析プリプロセッサの実質化~~ ✅ v2.5実装済み | 🟢 P0 | ★☆☆ | 検出漏れ（FN）削減・誤検知（FP）抑制 | `audit_agent.py` |
| 2 | ~~入力トランケーション戦略の改善~~ ✅ v2.5実装済み | 🟢 P0 | ★☆☆ | ファイル後半の脆弱性を検出可能に | `orchestrator.py`, `audit_agent.py` |
| 3 | マルチファイルコンテキスト分析（importグラフ構築＋関数シグネチャ共有） | 🟡 P1 | ★★☆ | 複数ファイルにまたがる脆弱性発見率向上 | `orchestrator.py` |
| 4 | CVE照合結果のLLMフィードバック（CVSSスコアを重要度判定に注入） | 🟡 P1 | ★★☆ | LLMがCVE情報を根拠に説明可能に・FP削減 | `audit_agent.py`, `orchestrator.py` |
| 5 | ファジングペイロードの多様性向上（静的辞書＋AI生成プローブのハイブリッド） | 🟡 P1 | ★☆☆ | XSS/SQLi検出率向上 | `fuzz_agent.py`, `resources/` |
| 6 | ~~防御モニタリングのパターン集約フィルタ~~ ✅ v2.5実装済み | 🟢 P0 | ★☆☆ | LLM呼び出し回数を1/10〜1/100に削減 | `tools/monitor.py`, `monitor_agent.py` |
| 7 | 防御モニタリングのタイムウィンドウコンテキスト（直近30分のイベント履歴を添付） | 🟡 P1 | ★☆☆ | 多段階攻撃の検出率向上 | `monitor_agent.py` |
| 8 | ~~Deep AnalysisのFP検証強化~~ ✅ v2.5実装済み | 🟡 P1 | ★☆☆ | `balanced` effort時のFP率改善 | `audit_agent.py` |
| 9 | ~~偵察モード：既知サービスバナーのローカル照合~~ ✅ v2.5実装済み | 🟢 P0 | ★☆☆ | 既知サービスのLLMコストゼロ・ハルシネーション防止 | `tools/scanner.py`, `recon_agent.py` |

### 🛡️ 堅牢性・品質改善（3件）

| # | アイディア | 優先度 | 難易度 | 期待効果 | 主な影響ファイル |
|---|-----------|--------|--------|----------|-----------------|
| 1 | ~~設定バリデーション強化~~ ✅ v2.5実装済み | 🟢 P0 | ★☆☆ | 設定ミスによる実行時クラッシュを防止 | `core/config.py` |
| 2 | エラーハンドリング統一（指数バックオフ・タイムアウト値のプロファイル連動） | 🟡 P1 | ★☆☆ | ネットワーク不調時のスキャン中断防止 | `base_agent.py`, `llm_client.py` |
| 3 | GUI進捗表示改善とキャンセル機能（経過時間表示・`threading.Event`ベースの中断） | 🟡 P1 | ★★☆ | 長時間スキャンの状況把握・誤起動中断が可能に | `base_agent.py`, GUI panels |

### 推奨ロードマップ

```
Phase 1（即効性重視・P0全7件 + 追加1件）✅ v2.5 実装完了:
  ASTプリプロセッサ実質化 → トランケーション戦略改善
  → CVE照合並列化 + CVEキャッシュ永続化（同時着手可能）
  → モニターパターン集約フィルタ
  → 既知サービスローカル照合
  → 設定バリデーション

Phase 2（構造的速度改善・P1速度系）:
  タスク並列実行 → FASTモデル有効化
  → レポート非同期保存 → ストリーミングバッファ
  → エラーハンドリング統一

Phase 3（精度の深掘り・P1精度系）:
  マルチファイルコンテキスト → ファジングペイロード多様化
  → CVEフィードバック → FP検証強化
  → モニター時間窓コンテキスト → GUI進捗・キャンセル

Phase 4（長期検討・P2）:
  トークン事前カウントによるコンテキスト最適化
```

---

## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。

**本ツールは教育・研究・許可されたセキュリティ診断を目的としています。  
いかなる不正アクセスにも使用しないでください。**