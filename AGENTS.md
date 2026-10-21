# AI Agent Guidelines: AI Security Audit System

## 1. プロジェクトの概要と目的

**対象ユーザー:** セキュリティ専門家・研究者・ホワイトハッカー志望のエンジニア（ポートフォリオ用途を兼ねる）

**目的:** シグネチャ（既知パターン）に依存しない、LLM推論による自律型ペネトレーションテスト＆脆弱性露出管理プラットフォームの開発。CVEデータベースに載っていない設計上の論理的欠陥・未知のゼロデイ表面を発見することが技術的な差別化ポイント。

**4つの動作モード:**
- `CODE AUDIT` — Pythonソースをセマンティック解析し、SQL Injection・IDOR・競合状態・認可ロジック欠陥などを発見
- `ATTACK MODE` — 許可されたターゲットへのポートスキャン・Web列挙・AIによる攻撃仮説生成（偵察フェーズのみ）
- `WEB FUZZ` — Webアプリのクロール→注入点抽出→AI検出プローブ→検出のみファジング→AIトリアージ（兆候観測のみ・非エクスプロイト）
- `DEFENSE MODE` — アクセスログのリアルタイム監視・MITRE ATT&CK分類・即時アラート生成

### 最初に読むもの

| 目的 | ドキュメント |
|---|---|
| マルチモデル（STRONG/FAST）ルーティング＆推論エフォートの設計・**継続実装ガイド** | [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) |
| システム設計書 | [docs/DESIGN.md](docs/DESIGN.md) |
| 学習ガイド（脆弱性・攻防・技術スタック） | [docs/ENGINEER_GUIDE.md](docs/ENGINEER_GUIDE.md) |
| バグバウンティ対応の設計・実装計画 | [docs/BOUNTY_ROADMAP.md](docs/BOUNTY_ROADMAP.md) |
| WEB FUZZ をバグバウンティで使う際の具体的な運用フロー | [docs/BOUNTY_WEBFUZZ_WORKFLOW.md](docs/BOUNTY_WEBFUZZ_WORKFLOW.md) |
| 次の実装順序・対象ファイル・データ契約・受け入れ条件の正本（P0〜P4） | [docs/PRACTICAL_ROADMAP.md](docs/PRACTICAL_ROADMAP.md) |
| 完了済み機能の実装詳細・セルフテスト結果（通常のタスクでは読まなくてよい） | [docs/IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md) |

実践運用対応の実装依頼では、`docs/PRACTICAL_ROADMAP.md` §3の未完了IDを選んで該当節を読む。
現在の引き継ぎ状況・次にやるべき具体的な手順は本書 §4「未実装（ロードマップ）」を必ず読むこと。
新規機能と既存境界の不備修正を区別し、未検査を修正済みと判定しないこと。
文書のみの整理ではリンク・差分・未実装表記を検証し、下記コーディング用セルフテストは不要。

---

## 2. 技術スタックとアーキテクチャ

### 言語・フレームワーク・主要ライブラリ

| カテゴリ | 技術 |
|---|---|
| 言語 | Python 3.10+（3.14推奨） |
| GUI | CustomTkinter 5.2.2（ダークモード、`ctk.set_appearance_mode("dark")`） |
| LLM | OpenAI互換API（`openai` ライブラリ）— Ollama / OpenAI / OpenRouter |
| ネットワーク | `socket`（標準ライブラリのみ、nmap不要）、`requests` |
| 並行処理 | `threading`、`concurrent.futures.ThreadPoolExecutor` |

### ディレクトリ構成と役割

```
AI-Security-tool/
├── main.py                      # エントリポイント。スプラッシュ表示→遅延ロード→App起動
├── config.json                  # 実行時LLM設定（gitignore済み。APIキーを含む可能性あり）
├── requirements.txt             # pip install -r requirements.txt
├── 起動.bat                     # Windowsランチャー（コンソールあり）
├── 起動_silent.bat              # Windowsランチャー（コンソールなし）
├── 起動.sh                      # Linuxランチャー（.venv/bin/python3 優先、無ければ system python3/python）
├── 起動.command                 # macOSランチャー（Finderダブルクリック対応）
├── samples/
│   └── target_code.py           # CODE AUDIT 動作確認用のサンプル脆弱コード
├── testlab/
│   ├── vuln_server.py           # 手動確認用の模擬脆弱サーバー
│   ├── fixtures/web_fixture.py  # WEB FUZZ評価用の決定論的fixture（全リクエスト記録。特性化試験・P2.1で共用）
│   └── ground_truth.json        # 上記fixtureの正解（case_id/rule_id/location/expected）
├── assets/
│   ├── create_icon.py           # アプリアイコン生成スクリプト（PIL）
│   └── icon.ico / icon.png      # 生成済みアプリアイコン
├── docs/
│   ├── DESIGN.md                # システム設計書（アーキテクチャ詳細）
│   ├── BOUNTY_ROADMAP.md        # バグバウンティ対応の設計・実装計画（Phase A〜D・実装済み）
│   └── screenshot_*.png         # README埋め込み用スクリーンショット
├── Dockerfile                   # Dockerコンテナ定義（X11フォワーディング必要）
├── docker-compose.yml           # Docker Compose設定
├── core/
│   ├── settings.py              # 全定数（色・フォント・LLMデフォルト値・FASTモデル・EFFORT_PRESETS・スキャン設定・APP_VERSION）
│   ├── config.py                # config.jsonの読み書き＋バリデーション。settings.pyをデフォルトとしてフォールバック（llm_fast_model/effort/allowed_targets/scope_mode等）
│   ├── event_bus.py             # スレッドセーフUIイベントバス（queue.Queue基盤）
│   ├── llm_client.py            # LLMClient。update()でホットリロード可能。OpenRouterヘッダー自動付与。fetch_models()で価格・コンテキスト長・知能指数（Artificial Analysis）付きモデル一覧を取得。cost_tier()/sort_models()も提供
│   ├── model_router.py          # ロール別モデルルーティング（STRONG/FAST）＆推論エフォート（lokicode移植）。summarize_telemetry()/suggest_efficient_model()でテレメトリ実績を助言表示（自動切り替えはしない）
│   ├── scope_guard.py           # バグバウンティ対応: 対象範囲(Scope)の機械的判定 in_scope()（許可リスト一致のみ・v1はdeny-list非対応）
│   ├── http_transport.py        # P0.1/P0.2: WEB FUZZ全送信経路の唯一の送信口。normalize_origin()・HttpTransport（同一origin検査・共有予算・手動リダイレクト制御・RequestPolicyでレート/429リトライ/STOP中断/応答サイズ上限）。TLS設定・認証状態判定はtools/web_fuzzer.py側
│   ├── findings.py              # P1.1: 構造化所見・実行ライフサイクルのデータ契約。ScanResult/Finding/CoverageItem/ScanState/VerificationState/CoverageStatus（dataclass/Enum）
│   ├── redaction.py             # P1.2: 証拠のマスキング。mask_headers()/mask_url()/mask_body()（既知の機密値の完全一致＋キー名ヒューリスティック）、mask_value()でsha256先頭12文字付与
│   ├── evidence_store.py        # P1.2: reports/evidence/<scan_id>/へのHTTP証拠保存。EvidenceStore（件数/1件サイズ/総容量の上限、保存失敗はsave_errorsへ記録）
│   ├── orchestrator.py          # LangGraph StateGraph。深層解析ループ回数はエフォート連動（smart_truncate採用）
│   └── autonomy/
│       └── journal.py           # 自律化Phase A1: 追記式JSONLのRun Journal（seq/prev_hash連鎖・部分行回復・fail closed・単一writer）。設計は docs/AUTONOMOUS_*.md
├── agents/
│   ├── base_agent.py            # 抽象基底クラス。threading.Eventで停止管理、EventBusヘルパー群、_check_scope()（スコープガード）
│   ├── audit_agent.py           # CODE AUDITエージェント（7ステップ。ASTプリプロセッサ＋並列CVE照合＋FP検証強化）
│   ├── langgraph_audit_agent.py # LangGraph強化型監査エージェント（orchestrator.pyを使用）
│   ├── recon_agent.py           # ATTACK MODEエージェント（10ステップ・Phase 0で受動的サブドメイン列挙(crt.sh)・既知サービスローカル照合付き）
│   ├── fuzz_agent.py            # WEB FUZZエージェント（7ステップ・検出のみ・第2アカウント設定時はIDOR/アクセス制御チェックを追加実行）
│   └── monitor_agent.py         # DEFENSE MODEエージェント（ログ監視＋パターン集約フィルタ＋バッチAI分析）
├── tools/
│   ├── network_scanner.py       # socket-basedポートスキャナ、SSL証明書取得
│   ├── web_prober.py            # HTTP探査、技術スタック指紋、センシティブパス列挙
│   ├── web_fuzzer.py            # Webスマートファザー（クロール・注入点検出・異常観測／検出のみ）。第2セッション(session_b)によるIDOR比較はGET限定。全送信はcore/http_transport.HttpTransport経由（P0.1）
│   ├── subdomain_enum.py        # バグバウンティ対応: crt.shへの受動的サブドメイン列挙（単発GETのみ・サイレント失敗）
│   ├── log_watcher.py           # tailf式ログ追跡ジェネレータ、サンプルログ生成
│   ├── cve_client.py            # NVD API v2クライアント。永続キャッシュ＋並列照合・サイレント失敗
│   ├── report_generator.py      # HTML/PDF/Markdownレポート生成。---VULN_START---マーカーをパースして構造化出力
│   ├── pdf_writer.py            # 日本語対応PDFレンダラー（Pillowのみ・依存追加なし）
│   ├── create_shortcut.py       # デスクトップショートカット生成（Windows・OneDrive対応／Linux・.desktop対応）
│   ├── known_vulns.yaml         # 既知サービスバナー脆弱性DB（ローカル照合用・LLMコストゼロ）
│   ├── test_structured_reports.py # 確定所見・証拠リンク・GUI出力配線の固定回帰テスト
│   ├── test_run_journal.py      # Run Journal の固定回帰テスト（selftest 16mに統合）
│   ├── fuzz_characterization.py # 現行FuzzAgentを固定fixture+モックLLMで動かす特性化装置（自律化の比較基準。FuzzAgentは無変更）
│   ├── test_fuzz_characterization.py # 上記の固定試験（selftest 16nに統合）
│   ├── run_selftest.py          # 全機能セルフテスト（GUI以外をEventBus経由でE2E検証）
│   └── capture_screenshots.py   # README用スクリーンショット自動撮影
├── gui/
│   ├── app.py                   # メインウィンドウ。DPI対応、4タブ、30msポーリング、アイコン設定。
│   │                             Linuxではxrandrでプライマリモニタの解像度・位置を取得し
│   │                             マルチモニタ環境での2画面またぎ起動を防止（_pick_monitor）
│   ├── splash.py                # 起動スプラッシュ（tkinter製・重いモジュールロード前に高速表示）
│   ├── export_util.py           # HTML/PDF/Markdownレポート出力の共通ヘルパー
│   ├── dialogs/
│   │   ├── settings_dialog.py   # LLM設定モーダル（接続テスト・config.json保存・SCOPEセクション＝allowed_targets/scope_mode）。MODEL/FASTは検索式モデルピッカー共用（コスト階級・プロバイダ・知能指数フィルタ/ソート、適用先セレクタで切替）
│   │   └── auth_dialog.py       # WEB FUZZ認証設定（title引数でヘッダー文言を差し替え可能・第2セッション/IDOR比較用にも流用）
│   ├── widgets/
│   │   ├── output_box.py        # カラータグ付きスクロールテキストボックス（get_text()付き）
│   │   └── progress_steps.py    # ステップ進捗＋深刻度カウンターウィジェット（DETECTION SUMMARY）
│   └── panels/
│       ├── audit_panel.py       # CODE AUDITタブ（LangGraphトグル・📊HTML/📄PDF/📝MD出力）
│       ├── attack_panel.py      # ATTACK MODEタブ（📊HTML/📄PDF/📝MD出力）
│       ├── fuzz_panel.py        # WEB FUZZタブ（プロファイル・REQ予算・第2セッション/IDOR比較・📊HTML/📄PDF/📝MD出力）
│       └── defense_panel.py     # DEFENSE MODEタブ（📊HTML/📄PDF/📝MD出力）
└── reports/                     # スキャン結果出力先（ローカル保存のみ・gitignore済み）
```

### 設計パターンと重要な規約

#### EventBusパターン（最重要）
- バックグラウンドスレッド（エージェント）→ GUIスレッドへの通信は **必ず EventBus 経由**
- tkinterは非スレッドセーフ。エージェントから直接ウィジェットを操作しない
- `app.py` の `_poll_events()` が 30ms ごとに `bus.drain()` して `panel.dispatch()` を呼ぶ
- パネルごとに独立した EventBus インスタンスを持つ（クロスタブのイベント漏洩防止）

#### イベント種別（`core/event_bus.py`）
```python
LOG    = "log"     # システムログ（左ペインのログボックス）
OUTPUT = "output"  # AI出力テキスト（右ペイン、tag付き）
STEP   = "step"    # ステップ進捗更新 {idx, state}
ALERT  = "alert"   # 防御アラート {severity, message, time}  ← DefensePanelのALERT TIMELINEに表示
STATS  = "stats"   # 深刻度カウンター更新 {CRITICAL:n, HIGH:n, ...}
STATUS = "status"  # ステータスバー更新
DONE   = "done"    # 処理完了 {error: bool}
CLEAR  = "clear"   # 出力エリアクリア
```

#### ロール別モデルルーティング & 推論エフォート（lokicode 移植・重要）
コスト/精度を単一モデルより効率化するため、LLM呼び出しを役割で使い分ける。詳細と継続実装ガイドは
[docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md)。要点:
- **STRONG（`config.llm_model`）= 最終推論**。`_stream_llm()`（ストリーミング）が使う。
  脆弱性トリアージ・攻撃仮説・監査・検証パスはこれ。
- **FAST（`config.llm_fast_model`）= 機械的・量の出る生成**。`_complete_llm(role="fast")` が使う。
  検出プローブ生成・要約・分類など。FAST 未設定なら STRONG を共用（＝従来と完全に同一挙動）。
- **新しいLLM呼び出しを足すときは、この2択のどちらかで関数を選ぶだけ**でルーティングが効く。
- **推論エフォート**（`settings.EFFORT_PRESETS`／`config.effort`＝speed/balanced/quality）は
  `self._effort()` で参照。`verify_pass`（STRONG検証パス）・`cve_lookup`・`deep_loops` を分岐する。
- **検証パス** `_verify_findings(evidence, draft)` は品質エフォート時に STRONG で敵対的レビューし
  誤検知を削減する（lokicode の「強い検証器＝賢さの壁」）。マーカー形式を保つよう指示済み。

#### BaseAgentの継承ルール
新しいエージェントは必ず `BaseAgent` を継承し、`run(**kwargs)` を実装する。
```python
class MyAgent(BaseAgent):
    def run(self, target: str) -> None:
        # 各ステップで is_stopped() を確認して中断に対応
        if self.is_stopped(): return
        # LLMストリーミング
        self._stream_llm([self.llm.system("..."), self.llm.user("...")])
        self._done()
```

#### カラーテーマ（`core/settings.py`から参照）
- タブカラー: CODE AUDIT=`CYAN(#00D4FF)`, ATTACK=`RED_C(#FF3B3B)`, WEB FUZZ=`AMBER(#FFA500)`, DEFENSE=`GREEN(#00FF88)`
- 深刻度カラー: CRITICAL=RED_C, HIGH=ORANGE_H, MEDIUM=YELLOW_M, LOW=GREEN_L
- 新しいウィジェットは `BG_PANEL`, `BG_WIDGET`, `BG_INPUT` の3段階背景色を使い分ける

#### GUIパックオーダー（Windowsで頻発するレイアウトバグ防止）
- `side="bottom"` のステータスバーは `expand=True` のコンテンツより **先に** pack する
- 右側ヘッダーウィジェットは左側の `expand=True` ウィジェットより **先に** pack する

#### DPI対応
- Windowsの150%スケーリング環境を想定。`ctypes.windll.user32.GetDpiForWindow()` でdpiを取得し `scale = dpi/96.0` で論理座標に変換する

---

## 3. 開発におけるAIへの制約・ルール

### コード生成の原則

1. **スレッド安全性の維持**: エージェントのバックグラウンドスレッドから tkinter ウィジェットを直接操作しない。必ず EventBus 経由でイベントを emit し、GUIスレッドの `dispatch()` で処理する。

2. **エージェントの停止対応**: `run()` の長いループや重い処理の前後には `if self.is_stopped(): return` を挿入する。ユーザーが STOP ボタンを押したとき応答できるようにする。

3. **LLMエラーのハンドリング**: `_stream_llm()` はエラーを `on_error` コールバックで処理済み。`_complete_llm()` も例外をキャッチしてログに記録する。エージェント外でLLMを直接呼ぶ場合は try/except を必ず書く。

4. **設定値はハードコードしない**: `settings.py` や `config.json`（`core/config.py` 経由）から参照する。URL・APIキー・モデル名をコードに直書きしない。

5. **コメントは最小限**: 「WHY」が非自明な場合のみコメントを書く。「WHAT」を説明するコメントは不要（変数名・関数名が語る）。ドキュメントstring は1行まで。

6. **セキュリティポリシーの遵守**: 「検出のみ（エクスプロイト＝データ窃取・RCE実行・認証回避は非実装）」「スキャン結果はローカル保存のみ」「ブルートフォース・DoS・C2・マルウェア生成の非実装」「WEB FUZZ は同一オリジン限定・リクエスト数上限つき」に反するコードを生成しない。WEB FUZZ は脆弱性の"兆候観測"に留め、武器化したエクスプロイトを構築しない。（ATTACK MODE の認可チェックボックスは v2.1 で専門家向けUXのため廃止済み — 復活させない）

7. **新しいパネルを追加する場合**: `ctk.CTkFrame` を継承し、`dispatch(event: ev.Event)` メソッドを実装する。`app.py` に新しい EventBus とタブボタンを追加する。レポート出力は `gui/export_util.py` を使う。

### 命名規則
- クラス: `PascalCase`（例: `AuditAgent`, `OutputBox`）
- メソッド・変数: `snake_case`
- プライベートメソッド: `_snake_case`（先頭アンダースコア1つ）
- 定数: `UPPER_SNAKE_CASE`（`settings.py` に集約）
- イベント種別定数: `core/event_bus.py` に定義済みの定数を使う（文字列リテラルを直書きしない）

### コミットメッセージの規約
プレフィックス（`feat:`, `fix:`, `docs:`, `refactor:`, `chore:` 等）はそのまま英語で使うが、
それに続く説明文は**必ず日本語**で記述する。

```
# 良い例
feat: LLM設定ダイアログを追加
fix: DEFENSE MODEでALERTイベントが発火しないバグを修正
docs: READMEにセットアップ手順を追記
refactor: エージェント基底クラスのエラーハンドリングを整理

# 悪い例（英語の説明はNG）
feat: add LLM settings dialog
fix: fix ALERT event not firing in DEFENSE MODE
```

### 禁止事項
- `threading.sleep()` をGUIスレッド（メインスレッド）で使わない（フリーズする）
- `bus.flush()` をエージェント起動前以外で呼ばない（進行中のイベントが消える）
- `config.json` をgitにコミットしない（`.gitignore` 設定済み）
- `reports/` 配下のログ・HTMLをgitにコミットしない（`.gitignore` 設定済み）

### 再発防止ルール（過去のバグから）
- **EventBus は `emit(kind, payload)` で送出する**。`bus.put()` というメソッドは存在しない（以前 orchestrator.py が `bus.put()` を使いLangGraph実行時にクラッシュした）。
- **深刻度カウンタの dict キーは大文字 `CRITICAL/HIGH/MEDIUM/LOW`**。`str.format()` のプレースホルダ名と大文字小文字を必ず一致させる（report_generator がテンプレートの小文字 `{critical}` と不一致で KeyError を起こした）。
- **ループ内で関数引数と同名の変数を再代入しない**。特に `path` のようなパス引数を内側で上書きしない（log_watcher の `generate_sample_log` がリクエストパスで引数 `path` を潰し、`os.makedirs` が失敗した）。
- **ATTACK MODE のスキャン挙動は `core/settings.SCAN_PROFILES` で一元管理する**。スキャナのタイミング・並列度・ランダム化をエージェントやUIにハードコードしない（intensity の直値分岐を `NetworkScanner.from_profile()` / `WebProber(profile=...)` に置換済み。新プロファイルは settings に追加するだけで全体へ波及させる）。
- **`WebProber` は自己申告UA（"Security Audit Tool" 等）を使わない**。ステルス前提のため `STEALTH_USER_AGENTS` の実在ブラウザUAをローテーションする。
- **WEB FUZZ は「検出のみ・非エクスプロイト」を厳守する**。`web_fuzzer.py` はレスポンス異常（反射・DBエラー署名・テンプレ評価・既知ファイル署名）の観測に留め、データ窃取・RCE実行・認証回避は実装しない。総リクエスト数の上限（`max_requests`）・同一オリジン限定・ジッター/低並列でDoSを回避する。これらの安全境界を緩めない。
- **レポート出力は `gui/export_util.py` 経由に統一する**。各パネルで `report_generator` を直接叩く重複実装をしない（HTML/PDF両対応のため一元化済み）。PDFは `tools/pdf_writer.py`（Pillowのみ）で日本語をラスタ描画する — 標準14フォントはCJK非対応のため。
- **後方互換のためデフォルトを無効にする新しい安全機構は、UIに常時警告を表示する**。
  スコープガード（`allowed_targets` 空リスト＝無効）は既存インストールとの後方互換のため
  意図的にそうしているが、機能名だけ見て「設定すれば守られる」と誤解した初学者が設定を
  忘れたまま無防備に使ってしまう false sense of security を防ぐため、`settings_dialog.py`
  に常時警告文言を表示している（advisorレビュー指摘・2026-08-16、[docs/BOUNTY_ROADMAP.md](docs/BOUNTY_ROADMAP.md) Phase A）。
  同様の「デフォルト無効・後方互換」設計を追加する際はこのパターンを踏襲する。
- **検証器アンサンブル（`_vote_findings`）は所見を除外しない**。過半数一致しない所見も
  `CONFIDENCE: ENSEMBLE_MINORITY` を付けて最終結果に含める（union方式）。マーカーブロックへ
  新しいフィールドを追加する場合は、`report_generator._parse()` の `_field()` パターン
  （`^{key}:\s*(.+)` の行マッチ）に1行足すだけで安全に追加できる — 未知フィールドは
  既存パーサに無視されるため後方互換を壊さない（advisorレビュー指摘・2026-08-17、
  lokicodeの検証フェーズ設計との比較検討）。「本ツールの差別化ポイントである
  未知脆弱性の見逃し防止」という方針上、多数決による除外は今後も導入しないこと。
- **テレメトリ台帳（`reports/telemetry.jsonl`）の活用機能は助言のみに留め、自動切り替えを
  実装しない**。`core/model_router.summarize_telemetry()`/`suggest_efficient_model()` は
  ユーザーの明示設定を一切上書きしない（lokicodeの`lib/modelLedger.ts`のε-greedy自動選択は
  意図的に移植しなかった）。実測データが十分に溜まり、助言の精度が検証できるまでは
  この方針を変えないこと。
- **LLM呼び出しの役割分担を守る**。最終的な専門推論は `_stream_llm()`（STRONG）、機械的・量の出る
  生成は `_complete_llm(role="fast")`（FAST）を使う。モデル名・エンドポイントをエージェントに直書きせず、
  必ず `core/model_router.py` 経由で解決する。エフォート依存の分岐は `self._effort()` の dict を見る
  （`verify_pass`/`cve_lookup`/`deep_loops`）。FAST/エフォートの追加はセキュリティ境界（検出のみ・
  PoC送信なし・非DoS）を一切変えない範囲に限る。→ [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md)
- 重要な変更後は `py tools/run_selftest.py` でリグレッションを確認する（`PYTHONUTF8=1` 推奨）。
  Windows のコンソールは cp932 のことがあり、`—` 等の出力で UnicodeEncodeError になるため。
- **Markdown/ドキュメント中に `tools/`・`agents/` 等のパスを書くときは、直前にバックスラッシュを
  置かない**（v2.5.0で `AGENTS.md` にmojibake混入 — `\a`/`\t`/`\r`/`\v`/`\b` が制御文字として
  解釈され `a`/`t`/`r`/`v`/`b` の文字が消失した。原因はエスケープ解釈する何らかの中間処理を経由した
  ことと推測。ファイル編集後は `python3 -c "print([c for c in open(f,encoding='utf-8').read() if ord(c)<32 and c!='\n'])"`
  で制御文字混入がないか確認できる）。
- **トグルで新機能をONにする設計では、既定OFF時の挙動が「完全に元通り」であることをテストで
  保証する**。CTF Flag Hunt（`agents/recon_agent.py`）実装時、共有ヘルパー `WebProber.probe()`
  に無条件で `result["body"]`（最大20万文字）を保存する変更が設計書の記載外で混入し、
  `ctf_mode=False`（既定）でもメモリ使用量が増える差分が生じていた（LLMプロンプト
  `_build_recon_summary()` には混入せず、レポート保存も経由しないため実害はなし）。
  `probe()` に `capture_body: bool = False` を追加し、呼び出し側で `ctf_mode` のときだけ
  `True` を渡す形に修正、`tools/run_selftest.py` に既定オフでは `body is None` を確認する
  回帰テストを追加（れいレビュー指摘・2026-08-26、[docs/CTF_FLAG_HUNT.md](docs/CTF_FLAG_HUNT.md) §3）。
  共有モジュールに手を入れるトグル機能では、この「オフ時は完全に元通り」を必ずテストで固定すること。
- **「データを保存する」実装と「そのデータをレポート/ログに出す」配線は別物であり、後者を
  実装の最後に必ず確認する**。CTF Active Retrieval（`agents/recon_agent.py`）実装時、
  `CtfSafetyGuard.format_log()`（送信したペイロードの監査ログ）を`recon_data`に保存する
  処理は書いたが、Step9のレポート`body`組み立て（f-string連結）にそれを含める一行が
  当初抜けていた（受け入れチェックAC6「監査可能」のレビューで発覚・是正、
  [docs/CTF_ACTIVE_FLAG_RETRIEVAL.md](docs/CTF_ACTIVE_FLAG_RETRIEVAL.md) §6）。
  「変数に保存した」で満足せず、それを人間が実際に読む出力（レポート・ログ・UI）まで
  たどり着くか、実装の最後に配線元から配線先まで指でなぞって確認すること。

### 記事化について（意図的に対象外）

他の個人プロジェクトと違い、**このリポジトリは完成トリガーでの記事化提案の対象外**にして
いる（2026-08-12確定）。理由: 自律型AIペンテストは競合（XBOW・PentestGPT等）が強い分野な
上、攻撃系ツールを実名アカウントで積極的に宣伝すること自体が信用・雇用面のリスクになる
と判断したため。ユーザーが明示的に「この件を記事にして」と言わない限り、AIエージェント
側から記事化を提案しない。

### 開発ループ（すべてのコーディングタスクに適用）

コーディングは1回きりの「直線」ではなく、チェックが通るまで回す「ループ」で行う:

1. 【変更】コードを修正・追加する。
2. 【検証】`PYTHONUTF8=1 py tools/run_selftest.py` を実行する
   （Linux/macOS では `.venv/bin/python3 tools/run_selftest.py`。UTF-8がデフォルトのため
   `PYTHONUTF8=1` は不要。依存は本リポジトリ専用の `.venv` にのみ入っており、Kaliの
   externally-managed-environment制約もあって素の `python3`/グローバルpipでは動かない）。
   - **`SELFTEST_NON_LLM_ONLY=1`** を付けると、実LLM/実ネットワーク（9・10・11・12・17。
     `LLMClient`/`AuditAgent`/`MonitorAgent`/`ReconAgent`/`FuzzAgent`）をSKIPし、
     残り（1〜8・2b〜2d・13〜16）だけを実行する（CI＝`.github/workflows/selftest.yml`
     もこれを使う）。ただし3（`example.com` へのDNS解決）・4（HTTPプローブ）・
     8（NVD APIへのCVE照合）は非LLMだが外部ネットワークに到達するため、オフライン環境
     ではこの3件は失敗しうる（その場合も完了報告に明記する。黙って省略しない）。
   - `SELFTEST_NON_LLM_ONLY` を付けない通常実行では9以降も走るが、
     `config.json` で疎通可能なLLMエンドポイント（ローカルOllama起動中 or クラウドAPIキー
     設定済み）が要る。**未設定時の失敗モードは一様ではない**: LLMClientの疎通テストは
     明確に`FAIL`するが、MonitorAgent/ReconAgent/FuzzAgent はローカルの正規表現パターン
     検出や「完走したか」のみを検証するため、LLM呼び出しが失敗・空応答でも**PASSしうる**
     （`_complete_llm`/`_stream_llm` が例外を握りつぶしログに記録する設計のため）。
     したがって9以降のPASS数は「LLMが正しく機能した証拠」にはならない。
     疎通確認は `.venv/bin/python3 -c "import core.config as c; c.load(); print(c.get('llm_base_url'))"`
     の値に実際に何か listen しているかで判断する。未疎通の場合は
     `SELFTEST_NON_LLM_ONLY=1` での全通過を最低ラインとし、完了報告に
     「9以降はLLMエンドポイント未疎通のため未検証（PASSしたものも含め信頼しない）」
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

---

## 4. 現在の開発フェーズとロードマップ


完了済み機能の実装履歴（v2.1.0〜v2.6.0、バグバウンティ対応、CTF機能等）は
[docs/IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md) に移設した。新機能が完了したら
そちらに追記する（§5参照）。

### 未実装（ロードマップ）

**実践運用対応（[docs/PRACTICAL_ROADMAP.md](docs/PRACTICAL_ROADMAP.md)・2026-09-05改訂）**

実装順序・対象ファイル・データ契約・受け入れ条件は同ドキュメントを正とする。
旧CLI先行案は置換済み。次の実装単位は **P1.2の続き**（P1.1のデータ契約・
全4モード+LangGraphのFinding/CoverageItem配線、P1.2の証拠マスキング・保存基盤・
WEB FUZZへの証拠配線は実装済み・下記参照）。P1.2は継続中。

2026-09-06: 全4パネルがRESULTを保持し、HTML/MD/PDFへ確定ScanResultを渡す経路を追加。
次の実装はAUDIT/DEFENSEの証拠保存と入力マスキング。ATTACKは別途対象範囲を確認する。
WEB FUZZにも表示・LLM入力全体のマスキング、IDOR証拠、保存省略理由、未知IDの
validation error記録が残る。JSON出力も未実装。P1.2全体を完了扱いにしない。

P0.1・P0.2・P1.1は完了済み。実装詳細・セルフテスト結果は
[docs/IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md) を参照。

- [ ] P1.2 証拠保存・保存/表示/LLM送信前マスキング・共通レポート（**証拠の保存・
  マスキング基盤・WEB FUZZ保存・レポート表示への配線は実装済み・継続中**）。
  新規`core/redaction.py`: ディスク保存・GUI/ログ表示・LLM送信より前に機密値を
  マスクする。Cookie/Set-Cookie/Authorization等の既定センシティブヘッダー＋呼び出し側
  が把握している既知の機密値（設定済みcookie/token/password等）の完全一致マスクを主とし、
  キー名ヒューリスティック（password/token/api_key等）をURL/JSON/form本文への補助
  マスクとして併用。マスク済み値にsha256先頭12文字を付与（改ざん検出の補助であり
  匿名化ではない）。
  新規`core/evidence_store.py`: `reports/evidence/<scan_id>/`へHTTP証拠をJSON保存。
  件数・1件あたりのサイズ・総容量に上限（既定200件/20KB/5MB）を持ち、全通信の
  無制限保存はしない。1件あたりの上限超過時は本文を省略し理由を記録した上で保存する
  （所見自体は破棄しない）。保存失敗は`save_errors`に記録するのみで例外を投げない。
  evidence_idをそのままパスへ使わず正規表現で検証する（pathトラバーサル対策）。
  `core/config.py`に`save_evidence`設定を追加（既定False=既存動作維持）。
  `agents/base_agent.py`に`_begin_scan()`を追加し、`_finalize()`より前にscan_idを
  確定できるようにした（証拠保存がfinalize前からscan_idを参照するため）。
  `_findings_from_markers()`は`known_evidence_ids`引数を受け取り、LLM出力の
  `EVIDENCE_IDS:`行（カンマ/空白区切り）から**実在するIDのみ**`Finding.evidence_ids`
  へ採用する（存在しないID＝LLMの誤記・幻覚は黙って除外）。これは証拠の紐付けが
  意味的に正しいという保証ではない — LLMが対応する証拠を正しく引用したかまでは検証
  できない。`tools/report_generator._parse()`は`EVIDENCE_IDS`フィールドを追加抽出する
  （既存のNAME/SEVERITY/CWE/LINES等の抽出結果に影響なし）。
  **`agents/fuzz_agent.py`（WEB FUZZ）で実際に配線済み**: AIトリアージ呼び出しより前に
  `save_evidence`有効時のみ各異常(anomaly)のHTTP証拠を保存し、evidence_idを
  `_build_summary()`のプロンプトへ埋め込み、`_TRIAGE_SYS`にEVIDENCE_IDS引用の指示を
  追加した（未提供時は指示自体が発火しないよう条件付きの文言にした）。
  **2026-09-06の追加実装**: GUI全4パネルがRESULT payloadを保持し、次の開始時に
  リセット。共通export_utilからgenerate/generate_markdown/generate_pdfのscan_resultへ
  渡す。確定所見・対象・モデルを優先し、ストリーミング下書きは再集計しない。
  Findingにsnippet/analysisを追加し、旧マーカー変換で抜粋・分析本文を保持する。
  HTML/MDはreports/からの相対証拠リンク、PDFは証拠IDと相対保存場所を表示。
  IDは生成形式で検証し任意pathを拒否。確認状態・実行状態・errors/coverageと
  抑制未実装（0件）を表示する。参照がない場合は未保存/利用不可と記載する。
  旧マーカー入力の互換経路は残し、証拠/coverage不明を明示する。
  **2026-10-11の追加実装（AUDIT標準エンジン）**: `EvidenceStore.save_code_evidence()`
  （相対path・行範囲・マスク済み抜粋・由来`source`）を追加。保存対象は**ASTプリスキャンの
  決定的観測のみ**（LLMが後から報告するLINESから抜粋を作ると主張の言い換えで裏付けに
  ならないため作らない）。保存したevidence_idは「AST evidence IDs」節としてLLMへ渡し、
  `_EVIDENCE_INSTRUCTION`（IDがある時だけ付与）で引用させ、`known_evidence_ids`に実在する
  IDのみ採用する。AST該当が無い所見は証拠なし（レポートは「not saved / unavailable」）。
  `_findings_from_markers(rejected_evidence_ids=)`で除外した未知IDを`ScanResult.errors`へ
  「未知の証拠IDを除外」として残す（FUZZ/DEFENSE未配線）。上限到達による省略は
  `EvidenceStore.omissions`として`errors`へ「証拠保存を省略」と残す（保存失敗は従来どおり
  `save_errors`→「証拠保存エラー」。どちらも所見は破棄しない）。
  `core/evidence_store.py`は保存処理を`_persist()`へ共通化済み。
  **入力マスキング**: `core.redaction.mask_source()`を追加。機密名（password/secret/token/
  api_key/auth/credential等）への**同一行内の引用符付きリテラル代入**の値だけを
  `***REDACTED***(sha256:...)`へ置換する（行数不変・冪等）。AuditAgentは読み込み直後に、
  LangGraph版は`core/orchestrator.load_code`でマスクし、以降のLLM送信（検証パス含む）・
  AST・抜粋・表示はすべてマスク済みソースを使う。**save_evidenceのON/OFFに関係なく有効**。
  **トレードオフ**: 名前は残るため「ハードコード資格情報がある」こと自体は検出できるが、
  値の中身に基づく判断（弱い/既定パスワード等）はできなくなる。`==`/`!=`比較のリテラルもマスクする。複数行リテラル・
  機密名を含まない変数名・コメント内の値はマスクされない（ヒューリスティックの限界）。
  LangGraph版はAST観測が無いため証拠保存は未対応（常に証拠なし）。
  **2026-10-11の追加実装（DEFENSE）**: `EvidenceStore.save_log_evidence()`
  （入力元の相対path・マスク済みログ1行・一致パターン名・観測時刻）を追加。保存対象は
  **シグネチャ一致（集約フィルタ通過後）の行のみ**。ID付きで`[evidence_id=...]`を
  LLMへ渡し、IDがある時だけ`_EVIDENCE_INSTRUCTION`を付与、実在IDのみ採用・未知IDと
  上限省略/保存失敗は`errors`へ（AUDITと同じ記録方式）。`core.redaction.mask_log_line()`
  を追加（Authorization/Cookie等のヘッダー風トークン、`token=`等のクエリ/フォーム、
  JSONの機密キー。冪等）。**攻撃パターン検出は生の行で行い**、バッファ・アラート表示・
  LLM送信・保存にはマスク済みの行のみ使う（save_evidenceのON/OFFに関係なく有効）。
  **トレードオフ**: 機密名パラメータの値に入った攻撃ペイロード（例: `password=' OR 1=1--`）は
  シグネチャ検知とアラートは出るが、LLM分析にはペイロードが渡らない。
  **2026-10-11の追加実装（ATTACKのCTFフラグ報告）**: ATTACKの証拠保存範囲はHiro指示
  （2026-10-11）により「取得したフラグの中身と取得経路をレポートに残す」ことに限定。
  従来フラグは`recon_data["flags"]`（文字列のみ）で、ScanResult→HTML/MD/PDFには載らなかった。
  `ReconAgent._flag_findings()`が各フラグを`rule_id="CTF_FLAG"`・`severity="INFO"`
  （脆弱性の深刻度ではない。集計4区分には数えない）のFindingにする。description=フラグ本文
  （成果物なのでマスクしない）、location/analysis=取得経路、snippet=応答中のフラグ周辺抜粋。
  経路はActive Retrievalでは`_record_active_route()`が記録（Tier・メソッド・URL・params/data・
  ステータス・rationale・送信履歴上の位置。URLとパラメータは機密名ベースでマスク）、
  Flag Huntでは`_walk_leaves()`でrecon_dataを再帰し検出フィールドのパスを記録（従来の
  全体JSON化をやめた）。`save_evidence`有効時のみ、Active Retrievalの応答をHTTP証拠として
  保存しevidence_idsを付ける（OFFでも経路はレポートに出る）。**送信ロジック・安全ガード
  （スコープ必須・破壊的操作ブロック・予算）は変更していない**（記録のみ追加）。
  `_ctf_tier1`/`_ctf_llm_guided_tier`の戻り値（フラグ文字列のリスト）も不変。
  既知の限界: ATTACKのLLM所見（ポート/サービス等）の証拠保存は未対応。HTML/MDの見出し
  ラベルは脆弱性用（「脆弱コード」「Impact」等）のままで、フラグ所見では抜粋/経路の意味。
  **2026-10-11の追加実装（FUZZのIDOR証拠）**: `WebFuzzer._detect_idor()`の各兆候に
  `response_headers/response_body/baseline_body`を持たせ（第2セッションBの応答を主、第1
  セッションAの通常応答を比較用）、`FuzzAgent._save_evidence()`（異常＋IDORの保存を
  共通化）が`save_evidence`有効時にHTTP証拠として保存、`ACCESS CONTROL CHECK`節へ
  `evidence_id`を埋め込んでLLMに引用させる。両セッションの認証値は`known_secrets`で
  マスクされる。**注意**: IDOR証拠の本文は「アクセス権が無いはずの相手の応答」であり、
  他ユーザーの個人情報を含みうる。キー名ベースのマスクでは防げないため、`save_evidence`を
  有効にする場合は保存先（`reports/evidence/`）の取り扱いに注意する（1件20KB・200件・5MB上限）。
  **FUZZにも同じ記録方式を適用**: 上限到達の省略は「証拠保存を省略」、LLMが引用した未知IDは
  「未知の証拠IDを除外」として`ScanResult.errors`に残す。
  **FUZZの入力マスキング**: `run()`冒頭で既知の機密値（設定Cookie/ヘッダー値/パスワード）を
  作り、画面表示（対象・異常・IDOR）、fuzzerのログ、LLMへ渡すサマリー（→調査レポートにも
  同じ文字列が保存される）を`mask_log_line()`でマスクする（`save_evidence`のON/OFFに関係なく有効）。
  `_known_secrets()`は複数Cookieを`name=value`単位と8文字以上の値でも登録する。
  トレードオフ: `token=`等の機密名パラメータの値はLLMトリアージに渡らない（検出自体は生の
  応答で行う）。ページ本文中の機密値は、既知の値かキー名ヒューリスティックに該当する場合のみ隠せる。
  **JSON出力**: `report_generator.generate_json()`/`save_json()`、`export_util.export_json()`、
  全4パネルに「{ } JSON」ボタンを追加。HTML/MD/PDFと同じ確定結果から生成し、schema
  `ai-security-audit-report` v1（state/errors/coverage/counts/suppressed/所見＋検証済み証拠参照）。
  旧マーカー入力は`legacy=true`・`evidence_coverage="unknown"`。GUIの目視確認は未実施。
  **ATTACKのLLM所見の証拠保存**: `EvidenceStore.save_observation_evidence()`
  （`ObservationEvidence`: category=port/web_path/web_headers/subdomain、target_ref、マスク済みdetail）
  を追加。`ReconAgent._save_recon_evidence()`が`save_evidence`有効時のみ、scannerが実際に観測した
  ポート/バナー（TCP/UDP）・検出パス・応答ヘッダー（欠落セキュリティヘッダー含む）・
  受動サブドメインを保存し、`_build_recon_summary()`が各行へ`[evidence_id=...]`を埋め込む。
  LLMには`EVIDENCE_IDS:`行（CATEGORYの後）で引用させ、実在IDのみ採用・未知IDと上限省略は
  `errors`へ。フラグ証拠とstoreを共有（上限を二重に使わない）。LLMへ渡す偵察サマリーは
  `mask_log_line()`でマスク（Set-Cookie等。ON/OFFに関係なく有効・調査レポートにも同じ文字列が残る）。
  ATTACKは認証情報を持たないため、マスク対象は主に対象が返した値（Set-Cookie等）。画面表示の
  偵察ログ自体は未マスク（利用者自身のコマンド出力に近く、秘密は対象由来のため）。
  **LangGraph版の証拠保存**: 標準エンジンと同じ`save_ast_evidence()`（共通化）を、
  `build_audit_graph(evidence_hook=)`経由で`load_code`（マスク後）に呼ぶ。証拠ID一覧は
  `surface_scan`/`deep_analysis`のユーザープロンプト、引用指示はシステムプロンプトに追加。
  `save_evidence`OFFや引数未指定では従来どおり。AST観測のみ（LLMの主張からの抜粋は作らない）。
  **P1.2の実装範囲は一通り完了**。完了扱い(チェックボックス)にする前に確認する未了事項:
  GUI目視（新JSONボタン含む）、実LLMでの証拠ID引用の挙動、ATTACKの画面表示ログは未マスク、
  証拠ファイル移動・削除後のリンク切れは検査しない（既知の限界）。
  今回のリンクは保存時に採用されたIDを参照し、後からの証拠削除・移動は検査しない。
  検証: `SELFTEST_NON_LLM_ONLY=1 .venv/bin/python3 tools/run_selftest.py`で
  143 PASS / 0 FAIL / 5 SKIP（実LLM系未実施）。GUI目視確認は未実施。
  `tools/test_structured_reports.py`をselftestに統合（確定結果優先・不正ID・HTML/MDの
  エスケープ・実PDF生成・全パネルのRESULT→export配線）。
  セルフテスト2i（redactionの固定ダミー秘密値非漏えい検証）・2j（EvidenceStoreの
  保存物非漏えい・容量上限・pathトラバーサル対策）・2g2（evidence_ids検証: 既知ID採用・
  未知ID除外）・16k（FuzzAgentでの実際の証拠保存〜evidence_id引用〜検証の一連の流れ）
  を追加。
  （`tools/run_selftest.py` 142 PASS / 0 FAIL、実LLM系5件は既定どおりSKIP・2026-09-05）
- [ ] P2.1 CLI非依存の最小ベンチマーク（正常例と未検査を含む）
- [ ] P2.2 IDOR/SSTI/XSSの既存検出品質改善（P2.1の基準値取得後）
- [ ] P3.1 CLI・案件プロファイル・除外優先・実行設定分離
- [ ] P3.2 案件別JSONLイベント台帳・差分・期限付き抑制（不在だけでfixedにしない）
- [ ] P4.1 OpenAPI入力（明示選択された読み取り用GETから）
- [ ] P4.2 Python複数ファイル監査（多言語化とは別）
- [ ] P4.3 実ログ対応・ローテーション/縮小/部分行処理

引き継ぎ上の注意:

- 同一origin制約の不備修正は新トグルではないため、違反する旧動作をOFF互換として残さない。
- 所見の深刻度、検証状態、実行の成否、人の対応状態は別データにする。LLM失敗や認証切れを「検出ゼロ・成功」にしない。
- 既存CTF機能は独立した仕様を維持。本計画から能動機能へ権限を拡張しない。
- 新規検出クラス・通知・再開・他言語・外部API等は同文書 §9の保留事項。要約だけでも外部通知は外部送信であり、ローカル保存方針の例外を自動解釈しない。

**長期・任意**
- [ ] 自動脆弱性スキャンCI — 上記CI/CD統合の拡張案。push毎に自リポジトリへCODE AUDITを実LLMで
  自動実行しPRにコメント。secrets設定とコスト発生についてユーザーの明示的な合意が要る
- [ ] モデル別コスト×精度台帳の**自動切り替え** — 上記の助言表示から一歩進めて、
  lokicodeのε-greedy選択のように実行時に自動でモデルを選ぶ案。ユーザーの明示設定を尊重する
  現方針から踏み込むため、助言機能の実績が十分に溜まってから改めて検討する
- [ ] 下書き生成のFASTモデルへの移行・難易度ルーター4分類化＋ビームサーチ — 上記
  「見送った提案」参照
- 除外リストと案件別レートは上記P3.1/P0.2へ統合。発見サブドメインへの暗黙の自動展開は行わない。
- 外部プラットフォームの重複報告チェックは実践ロードマップ §9の保留事項。

> 完了済み: 拡張ポートスキャン（UDP対応）・認証付きWebファジング（v2.3）／
> マルチモデル・ルーティング＆推論エフォート（v2.4）／モデル要件ゲート（v2.5.1）／
> 難易度ルーター・検証器アンサンブル・テレメトリ台帳・CI（v2.6.0）／
> バグバウンティ対応 Phase A〜D（スコープガード・サブドメイン列挙・IDOR検出・Markdown出力）。

---

## 5. AGENTS.md の自己管理・自動更新ルール（最重要）

### 自動更新の義務

あなた（AIエージェント）は以下の変化が生じるタスクを完了した場合、**タスクの最後に必ずこのファイルを更新**してください。人間から明示的な指示がない場合でも同様です。

| 変化の種類 | 更新すべきセクション |
|---|---|
| 新機能の実装・完了 | [docs/IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md) に実装詳細を追記し、§4 の「未実装」から該当項目を削除 |
| 新しいファイル・クラスの追加 | §2 のディレクトリ構成に追記 |
| 設計パターン・規約の変更 | §2 の設計パターン、§3 のルールを更新 |
| バグ修正（設計上の誤りが原因） | §3 に再発防止ルールを追記 |
| ロードマップの変更・タスク追加 | §4 の「未実装」リストを更新 |
| セキュリティポリシーの変更 | §1 のセキュリティポリシー、§3 の禁止事項を更新 |

### 更新時の注意

- 完了済み機能の実装詳細・セルフテスト結果は[docs/IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md)に
  追記する（過去の記録は消さない）。**AGENTS.md自体（本ファイル）に完了済みの実装詳細を
  書き足さない**——毎セッション無条件でロードされるファイルなので、恒久ルール・現在進行中の
  ロードマップ以外は肥大化させない（2026-09-19、ひろ指示でコンテキスト効率化のため変更）。
- §4「未実装」は、進行中または次に着手するタスクの現在状態のみを保つ。完了したら
  IMPLEMENTATION_LOG.mdへ実装詳細を移し、ここからは短い1行に圧縮するか削除する。
- 新しいルールを追加する場合は「なぜそのルールが必要か」を1行で付記する
- このセクション（§5）自体は、この2026-09-19の方針変更以外では変更しない
