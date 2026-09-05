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
├── 起動.sh                      # Linuxランチャー（.venv/bin/python3 優先、無ければ system python3/python）
├── 起動.command                 # macOSランチャー（Finderダブルクリック対応）
├── samples/
│   └── target_code.py           # CODE AUDIT 動作確認用のサンプル脆弱コード
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
│   └── orchestrator.py          # LangGraph StateGraph。深層解析ループ回数はエフォート連動（smart_truncate採用）
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

---

## 4. 現在の開発フェーズとロードマップ


### 実装済み（v2.5.0 — Phase 1 即効性改善 全7件 + 追加1件）

- [x] 設定バリデーション強化 — core/config.py に validate_config()・未知キー警告・effort/timeout/
  report_lang の形式チェック
- [x] CVEキャッシュ永続化 — tools/cve_client.py に
  reports/cve_cache.json（TTL=1日）・_load_persistent_cache() / _save_persistent_cache()
- [x] CVE照合の並列化 — tools/cve_client.py に search_batch()（ThreadPoolExecutor・全CWEを並列送出）
- [x] AST静的解析プリプロセッサ — agents/audit_agent.py に ast_scan() / _AstVisitor（危険カテゴリ13種・80+関数のパターン抽出→プロンプト注入）
- [x] 入力トランケーション戦略の改善 — agents/audit_agent.py に smart_truncate()（末尾優先・importスキップ分割・制限値12000文字）・core/orchestrator.py でも採用
- [x] 防御モニタリングのパターン集約フィルタ — agents/monitor_agent.py に (IP, pattern) キー・300秒ウィンドウ集約・LLM呼び出し削減
- [x] 既知サービスバナーのローカル照合 — tools/known_vulns.yaml（14サービス・約30 CVE）・agents/recon_agent.py に lookup_known_vulns()（PyYAML非依存の簡易パーサ内蔵）・9ステップ化
- [x] （追加）Deep AnalysisのFP検証強化 — agents/audit_agent.py で balanced effort時も検証パスを実行

### 実装済み（v2.4.0 — ロール別モデルルーティング & 推論エフォート）
- [x] `core/model_router.py` — STRONG/FAST ロール別モデルルーティング＋エフォート参照（lokicode移植）
- [x] `settings.EFFORT_PRESETS`（speed/balanced/quality）＋ `config.effort`／`config.llm_fast_model` 等
- [x] `BaseAgent._fast_client()`／`_complete_llm(role="fast")`／`_effort()`／`_verify_findings()`（STRONG検証パス）
- [x] エフォート連動: `audit_agent`（CVE照合ゲート＋検証パス）・`fuzz_agent`／`recon_agent`（検証パス）・`orchestrator`（deep_loops）
- [x] `settings_dialog` に EFFORT セグメント・FAST モデル/URL/KEY 入力／`app.py` ヘッダーに FAST・エフォート併記
- [x] セルフテスト `2b. ModelRouter/Effort`（エフォート整合性・FASTルーティング・キャッシュ）
- [x] 設計・継続実装ガイド `docs/AGENT_ARCHITECTURE.md`
- [x] （継続、完了）難易度ルーター／モデル要件ゲート／検証器アンサンブル → v2.5.1・v2.6.0で実装済み（下記）

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

### 実装済み（v2.5.1 — モデル要件ゲート）
- [x] `core/model_router.assess_readiness(strong_id, fast_id)` — STRONG/FAST取り違えのヒューリスティック警告（`_MODEL_WEIGHT_HINTS` の既知slugパターン照合。未知slugは判定対象外＝誤検知より見逃しを優先）。ブロックはしない
- [x] `gui/dialogs/settings_dialog.py` — MODEL/FAST欄の変更をtraceして`_readiness_label`にAMBER色で警告表示（`_update_readiness_hint()`）
- [x] セルフテスト `2b` に `assess_readiness` の3パターン（同一/取り違え/未知slug）を追加

### 実装済み（v2.6.0 — 難易度ルーター・検証器アンサンブル・テレメトリ台帳・CI）
詳細設計は [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) §5。AGENT_ARCHITECTURE.md §5 の
「下位AIモデル向け継続実装ガイド」記載の3項目（難易度ルーター・検証器アンサンブル・モデル別コスト×
精度台帳）＋長期ロードマップのCI/CD統合を実装。
- [x] **難易度ルーター（§5.1）** — `core/model_router.classify_effort(text, llm)` がFASTモデル1コールで
  対象/コードを trivial/standard/deep に分類しspeed/balanced/qualityへ写像（解析失敗・LLM例外は
  balancedにフォールバック）。`current_effort(override)` で一時上書きに対応し、
  `BaseAgent.set_effort_override()`/`_effort()` が1回のrun()だけに適用する（config.effortは変更しない）。
  `audit_panel`/`attack_panel`/`fuzz_panel` に AUTOトグルを追加（バックグラウンドスレッドで分類しUIをブロックしない）
- [x] **検証器アンサンブル（§5.3）** — `EFFORT_PRESETS["quality"]["verify_samples"] = 2`。
  `BaseAgent._verify_findings(evidence, draft, samples)` が独立に複数回検証パスを走らせ、
  `_vote_findings()`/`_parse_marker_findings()`（NAME/TITLE+LINESをsignatureとするマーカー単位の
  過半数一致）で採用する所見を決める。全会不一致なら最初のサンプルへフォールバック。
  samples=1は従来と同一挙動。**過半数に届かず除外された所見はサイレントに消さない** —
  文言差（例:「SQL Injection in login」↔「SQL injection via username param」）で
  signatureが一致しないだけの場合もあるため、`_verify_findings()` が除外分を出力ボックスに
  可視化してから最終レポート用の戻り値からは除く（誤検知の確定ではなく「比較不能」の扱い）
- [x] **モデル別コスト×精度台帳（§5.4・記録のみ）** — `BaseAgent._record_telemetry(mode, target, detections, elapsed)`
  が `reports/telemetry.jsonl` へ (ts, mode, target, model, effort, detections, total_detections,
  elapsed_sec) を追記。4エージェント全てのrun()終端で呼び出し。分析・コスパ提案機能は未実装（将来）
- [x] **CI/CD統合（第一段階）** — `.github/workflows/selftest.yml`。push/PR/手動実行で
  `SELFTEST_NON_LLM_ONLY=1 python tools/run_selftest.py` を走らせる（非LLM項目1〜8・2b〜2d・13〜16のみ。
  実LLM API・実ネットワークを要するテスト9・10・11・12・17は秘密情報が無いためCIでは常にSKIP。
  バグバウンティ対応で追加した2e・3b・7b・16bも非LLMのためこの対象に含まれる — 下記参照）。
  `tools/run_selftest.py` に `SELFTEST_NON_LLM_ONLY` 環境変数と `_skip_llm()` ヘルパーを追加。
  **スコープの注記**: ロードマップの原文「自動脆弱性スキャン」は自リポジトリへのCODE AUDIT自動実行
  （実LLM要・push毎にコスト発生）とも解釈できるが、まずは秘密情報なしで安全に回せる回帰テストCIを
  実装した。自動脆弱性スキャンCIは未実装のまま — ユーザーがAPIキーをGitHub Secretsに設定し明示的に
  望む場合のみ追加する
- [x] セルフテスト `2c`（`_vote_findings`・除外分の可視化・TITLE:対応）・`2d`（`_record_telemetry`）・
  `2b` 拡張（`classify_effort`/`current_effort(override)`/`set_effort_override`）を追加
- [x] AUTOトグルの堅牢化 — `_auto_classify()` を try/except で全面ラップし、FASTクライアント構築
  失敗など想定外の例外でもUIスレッドに `balanced` で復帰する（バックグラウンドスレッドの例外は
  呼び出し元に伝播しないため、揉み消さないと開始ボタンが押しっぱなし状態のまま固まる）

### 実装済み（バグバウンティ対応 — Phase A〜D）
詳細設計・advisorレビュー指摘の反映内容は [docs/BOUNTY_ROADMAP.md](docs/BOUNTY_ROADMAP.md)（2026-08-16策定、同日実装）。
新モードは追加せず、既存の ATTACK MODE / WEB FUZZ を横断的に拡張した。
- [x] **Phase A: スコープガード** — `core/scope_guard.py`（`in_scope()`純粋関数。許可リスト一致の
  みでv1はdeny-list非対応）、`core/config.py`（`allowed_targets`/`scope_mode`。空リスト＝無効＝
  既存インストールとの後方互換）、`BaseAgent._check_scope()`（recon_agent/fuzz_agentのrun()冒頭で
  呼び出し）。`settings_dialog.py` にSCOPEセクションを追加し、空のままだと無防備になる旨の警告を
  常時表示（false sense of security対策）
- [x] **Phase B: 受動的サブドメイン列挙** — `tools/subdomain_enum.py`（crt.shへの単発GETのみ・
  サイレント失敗）。`recon_agent.py` の新規Phase 0として実行し、スコープ外の発見は除外理由つきで
  可視化。crt.sh由来の資産は生存確認・所有確認が別途必要である旨を出力に明記。v1は発見のみで
  後続フェーズへの自動展開はしない。`SCAN_PROFILES["bounty"]` を追加（検知回避ではなく対象への
  配慮が目的である点をstealth等と区別）
- [x] **Phase C: IDOR/アクセス制御不備検出** — `tools/web_fuzzer.py` に第2セッション（`auth_b`/
  `session_b`）と `_detect_idor()` を追加。GET等の非破壊メソッドのみに限定（書き込み系は対象外）。
  `fuzz_agent.py` に認可チェックステップを追加しAIトリアージへ追加エビデンスとして渡す。
  `fuzz_panel.py` に第2セッション入力欄（`AuthDialog`再利用）を追加し、複数アカウント使用が
  プログラムのRules of Engagementで許可されているか確認する旨の注記を表示
- [x] **Phase D: バグバウンティ提出用Markdown出力** — `report_generator.generate_markdown()`。
  Summary/Steps to Reproduce/Impact/Suggested Fixの4項目形式。既存の`---VULN_START/END---`
  パーサを再利用。4パネル共通で📝MDボタンを追加
- [x] セルフテスト `2e`（ScopeGuard）・`3b`（SubdomainEnum）・`7b`（Markdown出力）・`16b`
  （WebFuzzer IDOR）を追加。いずれも非LLM・非ネットワーク（モック使用）
- [x] `.github/workflows/selftest.yml` が回す `SELFTEST_NON_LLM_ONLY=1` の対象範囲は
  1〜8・2b〜2e・3b・7b・13〜16b（実LLM要のテストは引き続きSKIP）

### 実装済み（AIモデル運用最適化 — テレメトリ活用 & 検証器アンサンブル見直し）
背景: 個人開発アプリ「lokicode」（`/home/loki/projects/lokicode`）の `lib/modelLedger.ts`
（EWMA記録+ε-greedy選択）・検証フェーズ（judge=常にsynthesis／min集約／defects union）の設計と
本リポジトリを比較検討した上で実装。比較で出た4提案のうち、既存データを読むだけ・設定を一切
上書きしない①と、コード自身の既存方針との矛盾を正す③のみを実装した（**明確に改善と言えるもの
のみ**という方針のため）。
- [x] **テレメトリ台帳の要約・モデル提案（①）** — `core/model_router.py` に
  `summarize_telemetry()`（`reports/telemetry.jsonl` を(mode, model)単位で集計し
  効率指標＝平均検出数/平均所要秒の高い順に返す。lokicodeの`MIN_RUNS_TO_TRUST=5`を踏襲し
  件数不足のグループは除外）と `suggest_efficient_model()`（現在のモデルより効率指標が
  margin倍以上良い実績があれば助言文字列を返す）を追加。**自動切り替えは実装しない**
  （lokicodeのbestModel/ε-greedy選択に相当する機能はあえて移植せず、助言表示のみに留めた）。
  `settings_dialog.py` に `_ledger_hint_label` を追加し、readiness_label と同じパターンで
  STRONG/FASTモデルそれぞれ4モード分の助言を表示
- [x] **検証器アンサンブルの集約方式見直し（③・fix）** — `agents/base_agent.py` の
  `_vote_findings()` を、過半数不一致の所見を最終レポートから除外する方式から、
  `CONFIDENCE: ENSEMBLE_MINORITY` を付記した上で全所見を採用するunion方式に変更。
  `EFFORT_PRESETS["quality"]["verify_samples"]=2` が既定のため旧方式の閾値（過半数=2）が
  実質「全会一致必須」と等価になっており、`_parse_marker_findings()` 自身が明言する
  「除外＝誤検知の確定ではない・サイレントに消さない」という方針と矛盾していたための修正
  （バグ修正）。`report_generator.py` の `_parse()`/`_render_finding()` がCONFIDENCEフィールドを
  拾い、HTML出力で「(単独検証)」と可視化する（PDF/Markdown側の個別対応はスコープ外）
- [x] セルフテスト `2f`（テレメトリ台帳の要約・助言、一時ディレクトリで本番ファイルを汚染しない）
  を追加。`2c`（検証器アンサンブル）・`7`（ReportGenerator）のアサーションをunion方式・
  CONFIDENCEフィールドに合わせて更新
- **見送った提案とその理由**（将来セッションが同じ提案を再検討する際の文脈として記録）:
  下書き生成をSTRONGからFASTへ移す案（lokicodeの0.27.0のDraft移行に相当）と、難易度ルーターの
  4分類化＋ビームサーチ導入（lokicodeのdeep-hard判定＋escalation相当）は、検出精度（見逃し率）
  への影響を検証する実測データが無い段階でリスクが大きいため見送った。テレメトリ活用が
  軌道に乗り実績データが溜まってから再検討する

### 実装済み（Linuxデスクトップショートカット対応）
- [x] `tools/create_shortcut.py` — Windows専用だった `create()` にLinux分岐を追加。
  `.venv/bin/python3`（無ければ system python3/python）で `main.py` を起動する
  XDGデスクトップエントリ（`.desktop`）を、`xdg-user-dir DESKTOP`（日本語ロケール等の
  「デスクトップ」リダイレクトにも対応、Windows版の`[Environment]::GetFolderPath('Desktop')`
  と同じ思想）で取得した実デスクトップパスと `~/.local/share/applications/`（アプリメニュー
  登録用・sudo不要）の両方に書き込む。実行ビット付与・`gio set ... trusted true`（GNOME系の
  初回信頼マーク、無い環境ではスキップ）も行う。生成内容の組み立ては `_build_desktop_entry()`
  として副作用のない純粋関数に分離し、`tools/run_selftest.py` の「18. TOOLS —
  DesktopShortcut」でファイルI/Oなしにテストする
- [x] `起動.sh` — system python3/python決め打ちだったのを `.venv/bin/python3` 優先に修正
  （見つからなければ従来通り system python3/python にフォールバック）。理由: 本プロジェクトの
  GUI依存（customtkinter等）は `.venv` にのみインストールされる方針（CLAUDE.md）のため、
  system python3 では `ModuleNotFoundError` になり起動できないバグがあった

### 実装済み（モデルピッカー — 検索・コスト階級・プロバイダ・知能指数）
lokicodeの `src/components/ModelPicker.tsx`（コスト階級分類・プロバイダフィルタ・検索）と
`src-tauri/src/openrouter.rs`（Artificial Analysis社の`intelligence_index`/`coding_index`
ベンチマーク取得）を参考に、MODEL欄が自由入力のみだった設定画面を検索・フィルタ式に改善。
- [x] `core/llm_client.py` — `fetch_models()` を openai SDK 経由（IDのみ取得）から
  `requests` で `/models` の生JSONを直接取得する方式に変更し、`_parse_models_response()`
  （純粋関数）で `price_out`（100万トークンあたりUSD・出力側）・`context`（コンテキスト長）・
  `intelligence`/`coding`（Artificial Analysis指数、無いモデルはNone）を抽出するように拡張。
  `cost_tier(price_out)` は lokicodeと同じ4階級閾値（無料/低=$1未満/中=$10未満/高）。
  `sort_models(models, by="id"|"intelligence")` は**lokicodeのModelPicker.tsxには無い、
  本ツール独自の追加**（知能指数降順、Noneは末尾固定＝未収録を0点扱いにしない）
- [x] `gui/dialogs/settings_dialog.py` — MODEL/FAST欄を、既存の検索式スクロール一覧
  （`_render_model_list()`等）に統合。追加した要素: 適用先セレクタ（MODEL/FASTどちらへ
  クリック反映するか）・コスト階級フィルタチップ（複数選択）・プロバイダフィルタチップ
  （取得件数の多い順に動的集計）・並び順トグル（ID順/知能指数順）。一覧の各行に
  コスト階級・価格・コンテキスト長・知能指数（あれば）を表示する。**lokicodeとの意図的な差分**:
  lokicodeは完全ボタン式（手入力不可）だが、本ツールはOllama等ローカル接続で一覧に出ない
  モデルを使うケースがあるため、既存の手入力欄（CTkEntry）はそのまま残した。また
  フィールドごとに独立したポップアップにせず、一覧を1つに共通化して適用先セレクタで
  切り替える設計にした（ダイアログの縦幅を抑えるため）
  `_available_models()` は self を使わない純粋ロジックのため `@staticmethod` にし、
  旧形式（`list[str]`）キャッシュとの後方互換を含めて `tools/run_selftest.py` の
  「19. CORE/GUI — モデルピッカー」でインスタンス化なしにテストする
- [x] `available_models` キャッシュ形式を `list[str]`→`list[dict]` に変更（後方互換あり、
  旧形式が残っていても正規化して読める）

### 実装済み（Linuxマルチモニタ ウィンドウ配置修正）
- [x] `gui/app.py` — `_setup_window()` が `winfo_screenwidth()`/`winfo_screenheight()` を
  そのまま使っていたため、X11のマルチモニタ環境（xrandrで複数モニタを結合した1つの仮想
  スクリーンとして扱う構成）では、ウィンドウが2画面にまたがって開くバグがあった
  （Windowsの `winfo_screenwidth()` はプライマリモニタのみを返すため気づかれずにいた）。
  Linux（`sys.platform.startswith("linux")`）では `xrandr --query` の出力から
  プライマリモニタ（無ければ位置(0,0)のモニタ、それも無ければ検出順の先頭）の
  解像度・位置を `_pick_monitor()`（純粋関数）で選び、ウィンドウをそのモニタ上に
  正しいサイズで開くようにした。xrandrが無い/失敗する環境（Wayland等）では
  従来通り `winfo_screenwidth()`/`winfo_screenheight()`・原点(0,0)にフォールバックする

### 実装済み（設定ダイアログのスクロール対応・モデルピッカー可視性修正）
- [x] `gui/dialogs/settings_dialog.py` — モデルピッカー追加後、ダイアログが固定高
  （660x820）の非スクロール `CTkFrame` のままだったため、SCOPE欄より下（検索・
  コスト階級/プロバイダフィルタ・モデル一覧）が画面外に隠れて操作不能になっていた
  （実機スクリーンショットで発覚。ヘッドレス環境のpy_compile/AST検証では検知不能
  だった教訓）。`body` を `CTkScrollableFrame` に変更し、スクロールで全項目に
  到達できるようにした

### 実装済み（試運転で発覚した検出漏れの修正・2026-08-17）
実LLM（OpenRouter, STRONG=Claude Haiku 4.5, FAST=Qwen 2.5-7B）での試運転により、
2件の構造的な検出漏れ（LLMの精度ではなく決定論的なコードの穴）が見つかり修正した:
- [x] `tools/web_fuzzer.py` の `crawl()` — URL自身のクエリパラメータを注入点として
  登録する処理が `text/html` 限定のContent-Typeチェックの中にあったため、JSON API・
  ファイル配信系エンドポイント（`application/json`・`text/plain` 等を返す）の
  パラメータが構造的に検出対象から漏れていた（IDOR・パストラバーサル検出の見逃しの
  直接原因）。パラメータ登録をContent-Typeチェックより前に移動（フォーム抽出・
  リンク追跡は引き続きHTML必須のため `text/html` 限定のまま）
- [x] `core/settings.ATTACK_PATTERNS` — DEFENSE MODEのパターン集約フィルタが、
  admin/config.php・`.env`・`.git/HEAD`・`?cmd=cat`形式のコマンドインジェクション・
  wp-admin・xmlrpc.php の6種の攻撃シグネチャに対応するパターンを持たず、
  `_pattern_match()` の時点（LLM分析より前）で無視されていた。新カテゴリ
  `SENSITIVE_FILE_PROBE`・`CMS_PROBE` を追加し、`CMD_INJECTION` に `?cmd=` 形式も
  追加（`agents/monitor_agent.py` の `_quick_severity()` にも両カテゴリをMEDIUMとして
  登録）。`tools/run_selftest.py` に `tools/log_watcher.py` の `attack_lines` 全件が
  最低1パターンにマッチすることを確認する回帰テストを追加

**試運転で見つかったが今回は対応しなかった項目**（将来検討）: DEFENSE MODEの
MITRE ATT&CKタグ付けが一部不正確だった（例: SQLiにT1021.001＝RDP横展開を誤って
付与）。これはLLMのプロンプト/判断品質の問題であり、パターンマッチのような
決定論的な修正では検証できない。再検証には実LLMでの再試運転（課金）が必要なため、
今回は見送った

### 実装済み（CTF Flag Hunt モード・2026-08-26）
ATTACK MODE に、認可された偵察レスポンスからCTF形式のフラグ（`flag{...}` / `ctf{...}`・
ラベル文脈付きの32/40/64桁hex）をローカル検出するトグルを追加。設計は
[docs/CTF_FLAG_HUNT.md](docs/CTF_FLAG_HUNT.md) 参照:
- [x] `agents/recon_agent.py` — `run()` に `ctf_mode: bool = False`（既定オフ）、
  `_detect_flags()`（正規表現・純ローカル・送信なし）、`_detect_and_report_flags()`
  （recon_data 全体を検出対象にし取りこぼしを防ぐ）を追加
- [x] `gui/panels/attack_panel.py` — 「CTF Flag Hunt」チェックボックス（既定オフ）を追加
- [x] `tools/web_prober.py` — `WebProber.probe()` に `capture_body: bool = False` を追加し、
  `ctf_mode=True` のときだけ `result["body"]`（最大20万文字）を保存。既定オフでは従来の
  `WebProber` の挙動・メモリ使用量と完全に同一（レビューで発覚した設計書外の副作用を是正
  — 上記§3の再発防止ルール参照）
- [x] `testlab/vuln_server.py` — 検証用のダミーフラグ（HTMLコメント）を埋め込み
- [x] `tools/run_selftest.py` — `_detect_flags()` の形式検出・誤検知防止（裸hexの非検出）の
  単体テスト、および `WebProber.probe()` の `capture_body` 既定オフ/明示オンの回帰テストを追加
- [x] `EXPLOIT_TRANSMISSION_ENABLED` / `_assert_no_transmission()` は無変更（安全境界維持を確認済み）

**方針の確認**: 上記は「既に取得済みの認可レスポンスからの検出」のみ。対象への追加の
攻撃的リクエストを伴う拡張（能動的なフラグ回収）はユーザー合意のうえ別機能として実装した
（下記「実装済み（CTF Active Flag Retrieval）」参照）。

### 実装済み（CTF Active Flag Retrieval・2026-08-26）
上記CTF Flag Huntを拡張し、LLMが偵察結果から脆弱性を判断して**実際にペイロードを送信し**
フラグを探すモードを追加（THM等、ユーザーが利用許可を持つ外部CTFプラットフォームを含む
対象を想定）。`EXPLOIT_TRANSMISSION_ENABLED`（既存の通常ATTACK MODEの安全設計）は無変更、
完全に独立した新しい実行パスとして追加。設計は
[docs/CTF_ACTIVE_FLAG_RETRIEVAL.md](docs/CTF_ACTIVE_FLAG_RETRIEVAL.md) 参照:
- [x] `core/ctf_safety.py`（新設） — `is_destructive()`（DROP TABLE/rm -rf/fork bomb等の
  破壊的パターンを機械的にブロック。LLMの判断だけに頼らない）、`require_explicit_scope()`
  （許可ホスト空リストは実行そのものを拒否 — 通常の`scope_guard.in_scope()`の
  「空=制限なし」という後方互換は本機能では採用しない）、`CtfSafetyGuard`（送信予算・
  連続エラー自動停止・監査ログを1箇所に集約する送信ラッパー）
- [x] `agents/recon_agent.py` — `run()` に `ctf_active`/`ctf_active_targets`/
  `ctf_active_max_tier`（既定オフ・Tier2まで）を追加。CTF Flag Hunt（送信なし）で
  見つからなかった場合のみ、Tier1（隠しファイル名の拡張パス巡回・LLM不要）→
  Tier2（LLMガイド・読み取り専用のLFI/UNION SQLi/コマンドインジェクション確認）→
  Tier3（既定オフ・認証バイパス等）の順で段階的に試行し、見つかった時点で即終了
- [x] `gui/panels/attack_panel.py` — 「CTF Active Retrieval」チェックボックス（既定オフ・
  赤系）と許可ホスト入力欄を追加。空のままでは実行できない旨を常時警告表示
  （`_update_scope_hint()` と同じ「false sense of security対策」パターン）
- [x] `testlab/vuln_server.py` — Tier1/Tier2検証用の読み取り専用エンドポイント
  （`/notes.txt`・`/download?file=`・`/account?id=`）を追加。実ファイルシステム/DBは
  一切使わず、パターンマッチによるシミュレーションに留める
- [x] `tools/run_selftest.py` — 破壊的操作の機械的ブロック（見逃し/誤検知なし）・
  スコープ空リスト拒否・予算/連続エラー自動停止・LLM応答の救済パース・Tier1/Tier2の
  実HTTP確認（インプロセスのtestlabサーバー）・Tierの段階的エスカレーション（Tier1で
  発見時はTier2のLLM呼び出し自体が発生しないこと）の8項目を追加
- [x] レポート監査ログ配線（レビューで発覚した抜け・是正済み） — 実装当初、Step9の
  レポートbody組み立てに`ctf_active_log`（送信したペイロード一覧）を含める配線が
  漏れていた。AC6「監査可能」を満たすため追加（下記再発防止ルール参照）
- [x] `EXPLOIT_TRANSMISSION_ENABLED` / `_assert_no_transmission()` は無変更（git diffで確認済み）

**未実施（実施にはユーザーの許可確認が必要）**: GUI起動での目視確認、実LLM
（STRONG/FAST）でのTier2/3実走、実際のTHM等CTFターゲットに対する実走。

### 未実装（ロードマップ）

**実践運用対応（[docs/PRACTICAL_ROADMAP.md](docs/PRACTICAL_ROADMAP.md)・2026-09-05改訂）**

実装順序・対象ファイル・データ契約・受け入れ条件は同ドキュメントを正とする。
旧CLI先行案は置換済み。次の実装単位は **P1.1: 構造化所見・実行状態・EventBus配線**。
P1.1以降はすべて未実装。文書整備を機能実装完了として扱わない。

- [x] P0.1 送信境界・共通予算（新規 `core/http_transport.py`。WEB FUZZの全送信経路
  `_get()`/`_send_as()`/ログインGET・POSTを`HttpTransport.request()`に一元化。
  送信直前の同一origin検査＋原子的な予算予約、301/302/303/307/308の手動リダイレクト
  追跡（GETは追跡・POSTは303→GETのみ追跡、それ以外のPOSTリダイレクトは追跡せず
  認証未確認として理由を返す）、別originへの転送・外部SSO/IdPは追跡しない。
  セルフテスト16c/16dで別origin送信ゼロ・予算共有・0予算時の未送信を検証済み。
- [x] P0.2 レート・STOP・認証状態・TLS設定（`core/http_transport.py`の`RequestPolicy`に
  rate_per_sec/max_consecutive_429/max_backoff_seconds/max_response_bytesを集約し
  `core/settings.SCAN_PROFILES`の`path_rate_per_sec`から配線。429はGET限定でRetry-After
  （秒/HTTP-date、不正値は上限付きバックオフ、上限超過や連続打ち切りは`last_error`に理由）
  に従い有限回・予算内で再送、POSTは自動再試行しない。STOPは送信前チェック・待機中の
  仮想時計対応interruptible sleep・WebFuzzer側のジッター待機/crawlループにも配線し
  停止後は新規送信を一切開始しない。応答本文は`stream=True`+`max_response_bytes`と
  読取時間(`timeout`)の両方で打ち切り`resp.fz_truncated`を付与（P1.2の証拠用）。
  認証状態(`WebFuzzer.auth_state`)は`authenticated/anonymous/expired/unknown`。
  Cookie/ヘッダー設定のみでは"authenticated"と断定せず、`confirm_url`+`expect_text`
  （`gui/dialogs/auth_dialog.py`④に追加）で判定するのが最も信頼できる経路。
  `confirm_url`未設定時はログインフォームの`login_outcome`(ok/failed/unconfirmed)を使い、
  "expired"は'failed'（パスワードフォーム残存等の実証拠）のときだけ断定し、
  P0.1のPOSTリダイレクト未追跡による'unconfirmed'は"unknown"に留める
  （でないと成功ログインまで"失敗"と誤認する）。`agents/fuzz_agent.idor_skip_reason()`
  はA/Bどちらのセッションが"expired"でもIDORチェックをskipする（対称）。
  TLS検証は`core/config.py`の`tls_verify`/`tls_ca_bundle`（既定False=既存動作維持、
  無効時は`WebFuzzer.log()`で警告）。`gui/dialogs/settings_dialog.py`に設定UIを追加
  （`gui/panels/fuzz_panel.py`は変更していない — TLSは案件横断のグローバル設定として
  scope/allowed_targetsと同じ置き場所にした設計判断）。`session.request()`が
  `requests.RequestException`を継承しない素の`OSError`を送出するケース（不正な
  `tls_ca_bundle`パス等）を捕捉し`tls_config_error`として扱う（未対応だとクラッシュする）。
  自己署名証明書での実ハンドシェイク成否はセルフテスト16hで検証（`openssl`要、
  無ければSKIP）。**未対応**: 「新しい案件プロファイルは検証ONを既定とする」はP3.1
  （案件プロファイル自体が未実装）に依存するため据え置き。認証状態は`authenticate()`
  呼び出し時点の一度きりの判定であり、スキャン中の再検証はしない。
  セルフテスト16e〜16hで仮想時計によるレート/429試験・待機中STOP・認証状態全パターン・
  TLS検証成否（実ハンドシェイク）・応答サイズ上限を検証済み。
  （`tools/run_selftest.py` 99 PASS / 0 FAIL、実LLM系5件は既定どおりSKIP・2026-09-05）
- [ ] P1.1 構造化所見・実行状態・RESULT/DONEイベント配線
- [ ] P1.2 証拠保存・保存/表示/LLM送信前マスキング・共通レポート
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
