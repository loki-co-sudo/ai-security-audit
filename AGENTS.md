# AI Agent Guidelines: AI Security Audit System

## 1. プロジェクトの概要と目的

**対象ユーザー:** セキュリティ専門家・研究者・ホワイトハッカー志望のエンジニア（ポートフォリオ用途を兼ねる）

**目的:** シグネチャ（既知パターン）に依存しない、LLM推論による自律型ペネトレーションテスト＆脆弱性露出管理プラットフォームの開発。CVEデータベースに載っていない設計上の論理的欠陥・未知のゼロデイ表面を発見することが技術的な差別化ポイント。

**4つの動作モード:**
- `CODE AUDIT` — Pythonソースをセマンティック解析し、SQL Injection・IDOR・競合状態・認可ロジック欠陥などを発見
- `ATTACK MODE` — 許可されたターゲットへのポートスキャン・Web列挙・AIによる攻撃仮説生成（偵察フェーズのみ）
- `WEB FUZZ` — Webアプリのクロール→注入点抽出→AI検出プローブ→検出のみファジング→AIトリアージ（兆候観測のみ・非エクスプロイト）
- `DEFENSE MODE` — アクセスログのリアルタイム監視・MITRE ATT&CK分類・即時アラート生成

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
├── 起動.sh                      # Linuxランチャー
├── 起動.command                 # macOSランチャー（Finderダブルクリック対応）
├── samples/
│   └── target_code.py           # CODE AUDIT 動作確認用のサンプル脆弱コード
├── assets/
│   ├── create_icon.py           # アプリアイコン生成スクリプト（PIL）
│   └── icon.ico / icon.png      # 生成済みアプリアイコン
├── docs/
│   ├── DESIGN.md                # システム設計書（アーキテクチャ詳細）
│   └── screenshot_*.png         # README埋め込み用スクリーンショット
├── Dockerfile                   # Dockerコンテナ定義（X11フォワーディング必要）
├── docker-compose.yml           # Docker Compose設定
├── core/
│   ├── settings.py              # 全定数（色・フォント・LLMデフォルト値・FASTモデル・EFFORT_PRESETS・スキャン設定・APP_VERSION）
│   ├── config.py                # config.jsonの読み書き＋バリデーション。settings.pyをデフォルトとしてフォールバック（llm_fast_model/effort等）
│   ├── event_bus.py             # スレッドセーフUIイベントバス（queue.Queue基盤）
│   ├── llm_client.py            # LLMClient。update()でホットリロード可能。OpenRouterヘッダー自動付与
│   ├── model_router.py          # ロール別モデルルーティング（STRONG/FAST）＆推論エフォート（lokicode移植）
│   └── orchestrator.py          # LangGraph StateGraph。深層解析ループ回数はエフォート連動（smart_truncate採用）
├── agents/
│   ├── base_agent.py            # 抽象基底クラス。threading.Eventで停止管理、EventBusヘルパー群
│   ├── audit_agent.py           # CODE AUDITエージェント（7ステップ。ASTプリプロセッサ＋並列CVE照合＋FP検証強化）
│   ├── langgraph_audit_agent.py # LangGraph強化型監査エージェント（orchestrator.pyを使用）
│   ├── recon_agent.py           # ATTACK MODEエージェント（9ステップ・既知サービスローカル照合付き）
│   ├── fuzz_agent.py            # WEB FUZZエージェント（6ステップ・検出のみ）
│   └── monitor_agent.py         # DEFENSE MODEエージェント（ログ監視＋パターン集約フィルタ＋バッチAI分析）
├── tools/
│   ├── network_scanner.py       # socket-basedポートスキャナ、SSL証明書取得
│   ├── web_prober.py            # HTTP探査、技術スタック指紋、センシティブパス列挙
│   ├── web_fuzzer.py            # Webスマートファザー（クロール・注入点検出・異常観測／検出のみ）
│   ├── log_watcher.py           # tailf式ログ追跡ジェネレータ、サンプルログ生成
│   ├── cve_client.py            # NVD API v2クライアント。永続キャッシュ＋並列照合・サイレント失敗
│   ├── report_generator.py      # HTML/PDFレポート生成。---VULN_START---マーカーをパースして構造化出力
│   ├── pdf_writer.py            # 日本語対応PDFレンダラー（Pillowのみ・依存追加なし）
│   ├── create_shortcut.py       # デスクトップショートカット生成（Windows・OneDrive対応）
│   ├── known_vulns.yaml         # 既知サービスバナー脆弱性DB（ローカル照合用・LLMコストゼロ）
│   ├── run_selftest.py          # 全機能セルフテスト（GUI以外をEventBus経由でE2E検証）
│   └── capture_screenshots.py   # README用スクリーンショット自動撮影
├── gui/
│   ├── app.py                   # メインウィンドウ。DPI対応、4タブ、30msポーリング、アイコン設定
│   ├── splash.py                # 起動スプラッシュ（tkinter製・重いモジュールロード前に高速表示）
│   ├── export_util.py           # HTML/PDFレポート出力の共通ヘルパー
│   ├── dialogs/
│   │   └── settings_dialog.py   # LLM設定モーダル（接続テスト・config.json保存）
│   ├── widgets/
│   │   ├── output_box.py        # カラータグ付きスクロールテキストボックス（get_text()付き）
│   │   └── progress_steps.py    # ステップ進捗＋深刻度カウンターウィジェット（DETECTION SUMMARY）
│   └── panels/
│       ├── audit_panel.py       # CODE AUDITタブ（LangGraphトグル・📊HTML/📄PDF出力）
│       ├── attack_panel.py      # ATTACK MODEタブ（📊HTML/📄PDF出力）
│       ├── fuzz_panel.py        # WEB FUZZタブ（プロファイル・REQ予算・📊HTML/📄PDF出力）
│       └── defense_panel.py     # DEFENSE MODEタブ（📊HTML/📄PDF出力）
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
- **LLM呼び出しの役割分担を守る**。最終的な専門推論は `_stream_llm()`（STRONG）、機械的・量の出る
  生成は `_complete_llm(role="fast")`（FAST）を使う。モデル名・エンドポイントをエージェントに直書きせず、
  必ず `core/model_router.py` 経由で解決する。エフォート依存の分岐は `self._effort()` の dict を見る
  （`verify_pass`/`cve_lookup`/`deep_loops`）。FAST/エフォートの追加はセキュリティ境界（検出のみ・
  PoC送信なし・非DoS）を一切変えない範囲に限る。→ [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md)
- 重要な変更後は `py tools/run_selftest.py` でリグレッションを確認する（`PYTHONUTF8=1` 推奨）。
  Windows のコンソールは cp932 のことがあり、`—` 等の出力で UnicodeEncodeError になるため。

---

## 4. 現在の開発フェーズとロードマップ


### 実装済み（v2.5.0 — Phase 1 即効性改善 全7件 + 追加1件）

- [x] 設定バリデーション強化 — core/config.py に alidate_config()・未知キー警告・ffort/	imeout/
eport_lang の形式チェック
- [x] CVEキャッシュ永続化 — 	ools/cve_client.py に 
eports/cve_cache.json（TTL=1日）・_load_persistent_cache() / _save_persistent_cache()
- [x] CVE照合の並列化 — 	ools/cve_client.py に search_batch()（ThreadPoolExecutor・全CWEを並列送出）
- [x] AST静的解析プリプロセッサ — gents/audit_agent.py に st_scan() / _AstVisitor（危険カテゴリ13種・80+関数のパターン抽出→プロンプト注入）
- [x] 入力トランケーション戦略の改善 — gents/audit_agent.py に smart_truncate()（末尾優先・importスキップ分割・制限値12000文字）・core/orchestrator.py でも採用
- [x] 防御モニタリングのパターン集約フィルタ — gents/monitor_agent.py に (IP, pattern) キー・300秒ウィンドウ集約・LLM呼び出し削減
- [x] 既知サービスバナーのローカル照合 — 	ools/known_vulns.yaml（14サービス・約30 CVE）・gents/recon_agent.py に lookup_known_vulns()（PyYAML非依存の簡易パーサ内蔵）・9ステップ化
- [x] （追加）Deep AnalysisのFP検証強化 — gents/audit_agent.py で alanced effort時も検証パスを実行
### 実装済み（v2.4.0 — ロール別モデルルーティング & 推論エフォート）
- [x] `core/model_router.py` — STRONG/FAST ロール別モデルルーティング＋エフォート参照（lokicode移植）
- [x] `settings.EFFORT_PRESETS`（speed/balanced/quality）＋ `config.effort`／`config.llm_fast_model` 等
- [x] `BaseAgent._fast_client()`／`_complete_llm(role="fast")`／`_effort()`／`_verify_findings()`（STRONG検証パス）
- [x] エフォート連動: `audit_agent`（CVE照合ゲート＋検証パス）・`fuzz_agent`／`recon_agent`（検証パス）・`orchestrator`（deep_loops）
- [x] `settings_dialog` に EFFORT セグメント・FAST モデル/URL/KEY 入力／`app.py` ヘッダーに FAST・エフォート併記
- [x] セルフテスト `2b. ModelRouter/Effort`（エフォート整合性・FASTルーティング・キャッシュ）
- [x] 設計・継続実装ガイド `docs/AGENT_ARCHITECTURE.md`
- [ ] （継続）難易度ルーター（オート振り分け）／モデル要件ゲート／検証器アンサンブル → `docs/AGENT_ARCHITECTURE.md` §5

### 実装済み（v2.3.0 — Webファジング・PDF・デスクトップ統合）
- [x] `tools/web_fuzzer.py` — Webスマートファザー（同一オリジンクロール→クエリ/フォーム注入点抽出→検出プローブ送出→異常観測）。検出のみ・`max_requests` 上限でDoS回避
- [x] `agents/fuzz_agent.py` — WEB FUZZ エージェント（6ステップ：クロール→AI検出プローブ生成→ファジング→AIトリアージ）。出力は `---VULN_START/END---` 形式で report_generator と互換
- [x] `gui/panels/fuzz_panel.py` + `gui/app.py` 4タブ化（WEB FUZZ タブ追加、AMBERテーマ）
- [x] `tools/pdf_writer.py` + `report_generator.generate_pdf()/save_pdf()` — 日本語対応PDF出力（Pillowのみ・依存追加なし）
- [x] `gui/export_util.py` — HTML/PDF出力の共通ヘルパー（全パネルに「📊 HTML」「📄 PDF」ボタン）
- [x] `tools/create_shortcut.py` — デスクトップショートカット生成（OneDriveリダイレクト対応）＋ `main.py` で AppUserModelID 設定（タスクバーアイコン対応）

### 実装済み（v2.2.0 — ステルス強化）
- [x] ステルススキャンプロファイル `core/settings.SCAN_PROFILES`（stealth/passive/moderate/aggressive）— `NetworkScanner.from_profile()` / `WebProber(profile=...)` で適用、ATTACK MODE 既定は `stealth`
- [x] ポート走査順ランダム化＋接続ごとのタイミングジッター（IDS/レート検知の回避）
- [x] 実在ブラウザUAローテーション（`STEALTH_USER_AGENTS`）＋ステルス時のパス探索数制限
- [x] 受動OSフィンガープリント `network_scanner.passive_os_fingerprint()`（バナー/ヘッダー解析・追加通信なし）

### 実装済み（v2.1.0）

**コアインフラ**
- [x] `core/event_bus.py` — スレッドセーフイベントバス（LOG/OUTPUT/STEP/ALERT/STATS/STATUS/DONE/CLEAR）
- [x] `core/llm_client.py` — OpenAI互換ストリーミングクライアント（`update()` でホットリロード）
- [x] `core/config.py` — `config.json` による設定永続化（APIキーのgit除外済み）
- [x] `agents/base_agent.py` — threading.Event停止管理・EventBusヘルパー群

**エージェント**
- [x] `agents/audit_agent.py` — 7ステップのセマンティック脆弱性解析
- [x] `agents/recon_agent.py` — ポートスキャン→Web列挙→AI仮説生成（7ステップ）
- [x] `agents/monitor_agent.py` — ログ監視・パターンマッチ・15秒クールダウンのバッチAI分析・ALERT イベント発火

**ツール**
- [x] `tools/network_scanner.py` — socket-based ポートスキャナ（26ポート、SSL取得、バナーグラブ、プロファイル制御、受動OS推定）
- [x] `tools/web_prober.py` — 19技術スタック検出・セキュリティヘッダー評価・センシティブパス列挙（UAローテーション・ジッター・並列制御）
- [x] `tools/log_watcher.py` — tailf式ジェネレータ・200エントリのサンプルログ生成

**GUI**
- [x] `gui/app.py` — DPI対応メインウィンドウ、4タブ（v2.3で WEB FUZZ 追加）、30msポーリング、⚙ 設定ボタン
- [x] `gui/dialogs/settings_dialog.py` — LLM設定モーダル（プリセット・接続テスト・config.json保存）
- [x] `gui/widgets/output_box.py` — 13種カラータグ付きテキストボックス
- [x] `gui/widgets/progress_steps.py` — ステップリスト・プログレスバー・深刻度カウンター
- [x] `gui/panels/audit_panel.py` / `attack_panel.py` / `defense_panel.py` — 各タブパネル

**その他**
- [x] `requirements.txt`（langgraph, langchain-core 追加済み）
- [x] `README.md`（ポートフォリオ品質、スクリーンショット3枚付き）
- [x] `起動.bat` / `起動_silent.bat` / `起動.sh` / `起動.command`（Windows/Linux/macOS ランチャー）
- [x] GitHub プライベートリポジトリ（`loki-co-sudo/ai-security-audit`）
- [x] `tools/report_generator.py` — HTMLレポート生成（ダークテーマ、VULN/THREATマーカーをパース）
- [x] `tools/cve_client.py` — NVD API v2クライアント（CWE→CVE自動照合、@lru_cacheキャッシュ）
- [x] `core/orchestrator.py` + `agents/langgraph_audit_agent.py` — LangGraph StateGraphオーケストレーション
- [x] `Dockerfile` + `docker-compose.yml` — コンテナ対応
- [x] 全パネルに「📊 レポート出力」ボタン追加
- [x] CODE AUDITタブに ENGINE トグル（Standard / LangGraph）追加
- [x] OpenRouter対応（`llm_client.py` で `openrouter.ai` 検出時に `HTTP-Referer`/`X-Title` 自動付与・設定UIにプリセット追加）
- [x] `gui/splash.py` — 起動スプラッシュ画面 + アプリアイコン（`assets/`）+ 起動高速化（遅延インポート）
- [x] `tools/run_selftest.py` — 全機能セルフテスト（31項目、実LLM/実ネットワークでE2E検証。PDF/WebFuzzer/FuzzAgentはローカルモックサーバで検証）
- [x] バグ修正（レポート生成のキー不一致・サンプルログ生成の変数衝突・orchestratorのEventBus API誤用）

### 未実装（ロードマップ）

**次のフェーズ（優先度高）— マルチモデル基盤の上に継続実装**
詳細な設計と手順は [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) §5。
- [ ] 難易度ルーター（オート振り分け）— 対象/コードの難易度を判定しエフォートを自動選択
- [ ] モデル要件ゲート — 弱いモデル/検証に不向きな構成を設定画面で警告（lokicode `specs/model-gate.md`）
- [ ] 検証器アンサンブル — 品質時に検証パスを複数回走らせ多数決で誤検知をさらに削減

**長期**
- [ ] CI/CD統合（GitHub Actionsでの自動脆弱性スキャン）
- [ ] モデル別コスト×精度台帳（`reports/telemetry.jsonl`）→ コスパ最良モデルの提案

> 完了済み: 拡張ポートスキャン（UDP対応）・認証付きWebファジング（v2.3）／
> マルチモデル・ルーティング＆推論エフォート（v2.4）。

---

## 5. AGENTS.md の自己管理・自動更新ルール（最重要）

### 自動更新の義務

あなた（AIエージェント）は以下の変化が生じるタスクを完了した場合、**タスクの最後に必ずこのファイルを更新**してください。人間から明示的な指示がない場合でも同様です。

| 変化の種類 | 更新すべきセクション |
|---|---|
| 新機能の実装・完了 | §4 の「実装済み」リストに追加、「未実装」から削除 |
| 新しいファイル・クラスの追加 | §2 のディレクトリ構成に追記 |
| 設計パターン・規約の変更 | §2 の設計パターン、§3 のルールを更新 |
| バグ修正（設計上の誤りが原因） | §3 に再発防止ルールを追記 |
| ロードマップの変更・タスク追加 | §4 の「未実装」リストを更新 |
| セキュリティポリシーの変更 | §1 のセキュリティポリシー、§3 の禁止事項を更新 |

### 更新時の注意

- 過去の状態を消さずに、完了済みを `- [x]`、未着手を `- [ ]` で管理する
- 新しいルールを追加する場合は「なぜそのルールが必要か」を1行で付記する
- このセクション（§5）自体は変更しない
