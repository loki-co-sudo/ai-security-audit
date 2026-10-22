# 実装ログ（完了済み機能の変更履歴）

AGENTS.md §4 の「実装済み」記録がここに切り出されている（2026-09-19、コンテキスト効率化のため移設）。
現在進行中の作業・次にやることは AGENTS.md §4「未実装（ロードマップ）」と
[docs/PRACTICAL_ROADMAP.md](PRACTICAL_ROADMAP.md) を参照。ここは完了済み機能の実装詳細・
セルフテスト結果・発見した副次バグの記録であり、通常のタスクでは読む必要はない。

---

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
  GUI依存（customtkinter等）は `.venv` にのみインストールされる方針（本書§3「開発ループ」）のため、
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


---

## 実践運用対応ロードマップ — 完了項目の実装後記

設計仕様・受け入れ条件は [docs/PRACTICAL_ROADMAP.md](PRACTICAL_ROADMAP.md) を正とする。
以下はP0.1/P0.2/P1.1が完了した際の実装詳細・発見した副次バグ・セルフテスト結果の記録。

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
- [x] P1.1 構造化所見・実行状態・RESULT/DONEイベント配線。
  新規`core/findings.py`（`ScanResult`/`Finding`/`CoverageItem`/`ScanState`/
  `VerificationState`/`CoverageStatus`をdataclass/Enumで定義）。`core/event_bus.py`に
  `RESULT`イベント追加。`agents/base_agent.py`の`_finalize()`が最終`ScanResult`を確定し
  `RESULT`→`DONE`の順で**一度だけ**送出する（2回目以降の呼び出しは無視）。
  `_done()`/`_safe_run()`/`_check_scope()`をこれ経由にしたことで、**既存の実バグを
  副次的に修正**した: 従来は多数の`if self.is_stopped(): return`がbus.done()を呼ばずに
  抜けており、STOP後にGUIのボタンが再有効化されないまま残っていた
  （`_safe_run()`が`run()`の全終了経路——正常完了・例外・STOP早期return——を
  `cancelled`/`failed`/`completed`として確実に最終化するよう変更）。
  全5エージェント（audit/recon/monitor/fuzz/langgraph-audit）の`run()`冒頭で
  `self._current_mode`/`self._current_target`を設定し、フォールバック確定時の
  `ScanResult`にも正しいmode/targetが載るようにした。
  `agents/base_agent.py`に共通ヘルパー`_findings_from_markers()`を追加し、
  `report_generator._findings_and_counts()`が返す辞書列（NAME/SEVERITY/CWE/LINES/FIX
  マーカー形式）から`Finding`を構築する処理を各エージェントで共有する
  （品質エフォートの検証パスを通過した所見のみ`verification_state="corroborated"`とし、
  アンサンブル少数意見`ENSEMBLE_MINORITY`はLLMの同意だけで昇格させず"observed"のまま残す）。
  **所見・coverage・実行状態まで配線済み**:
  - `agents/fuzz_agent.py`（WEB FUZZ）: `_build_coverage()`が注入点ごとの検査記録と
    IDORチェックのtested/skipped（`idor_skip_reason()`との連携）を`CoverageItem`へ変換。
    `_determine_state()`がSTOP最優先→予算切れ/AIトリアージ空応答は`partial`
    （検出0件の成功とは区別）→それ以外は`completed`と判定する。
  - `agents/audit_agent.py`（AUDIT・標準）: `_build_coverage()`が対象ファイル1件の
    検査記録に加え、`smart_truncate()`がファイルサイズ上限超過で中間部分を省略した
    場合はその範囲を`skipped`として明示する（未検査の可視化）。`_determine_state()`は
    STOP最優先→AI推論空応答は`partial`→それ以外は`completed`。ファイル読み込み
    エラー時（`OSError`）も`_finalize(failed, ...)`で理由を残すよう変更。
  - `agents/langgraph_audit_agent.py`（AUDIT・LangGraph版）: `graph.invoke()`の戻り値
    （最終`AuditState`）を捕捉し、`outputs`を結合して同じ`_findings_and_counts`経由で
    `Finding`化（アンサンブル検証パスが無いためcorroborated=False固定）。coverage判定は
    `agents/audit_agent.AuditAgent._build_coverage()`を再利用（cross-module import。
    `smart_truncate`の既存の共有パターンに倣う）。`_determine_state()`は
    `load_code`/`surface_scan`ノードがOSError時・STOP時の両方で`source_code`を空・
    `phase="stopped"`のまま次工程へ進める設計のため、final_stateだけでは
    「読み込み失敗」と「STOP中断」を区別できない点に対応し、エージェント自身の
    `is_stopped()`を優先判定に使う（そうしないと読み込み失敗をcancelledと誤認する）。
  - `agents/recon_agent.py`（ATTACK）: `_build_coverage()`がポートスキャン（scope別）・
    UDPスキャン・Web列挙・受動的サブドメイン列挙の各tested/skippedを`CoverageItem`へ
    変換（CTF Flag Hunt/Active Retrievalは既存仕様どおり独立機能のためcoverageに含めない
    — roadmap §1の方針を維持）。`_determine_state()`はSTOP最優先→ホスト名解決失敗/
    AI攻撃仮説の空応答は`partial`→それ以外は`completed`。
    **副産物のバグ修正**: `tools/report_generator._findings_and_counts()`が
    ATTACK MODE（`---FINDING_START/END---`、TITLE/CATEGORY/EVIDENCE/ATTACK_SCENARIO/
    RECOMMENDED_ACTION形式）を`---VULN_START/END---`で検索していたため、ATTACK MODEの
    HTML/PDF/Markdownエクスポートが所見抽出0件になる既存バグを発見・修正した
    （P1.1でFinding変換の再利用元を調査中に発覚。VULN/THREAT側の抽出結果は無変更）。
  - `agents/monitor_agent.py`（DEFENSE）: `_build_coverage()`はログソース単位の記録
    （`ATTACK_PATTERNS`は常に全行へ適用され個別無効化する設定が無いため、パターン別
    tested/skippedは意味を持たないと判断し採用しなかった）。`_determine_state()`は
    STOP最優先→`watcher.watch()`の例外（従来はログに記録するだけで握りつぶしていた）や
    AI脅威分析の全空応答は`partial`→アラート0件（脅威なし）は`completed`と判定する。
  以上でWEB FUZZ・AUDIT（標準/LangGraph）・ATTACK・DEFENSEの全4系統が同じ
  ScanResult/RESULT/DONE契約で確定するようになった。
  **既知の限界（次のP1.x以降で対応）**: 「不正マーカー」（欠落・破損したブロック）は
  `report_generator._parse()`側の既存の緩い抽出（欠落フィールドは空文字）に委ねており、
  エージェントごとの専用テストは追加していない。「対象HTML・コード・ログを信頼しない
  入力として区切る」制約は、現行アーキテクチャがLLM出力をレポート文字列としてのみ
  扱い、scope/予算/ツール実行を動的に変更する経路がそもそも存在しないことで構造的に
  満たされているが、プロンプトインジェクション耐性としての専用テストは書いていない
  （既存の安全境界の副産物であり、新規の防御機構ではない点に注意）。
  セルフテスト2g（ライフサイクル: 正常/STOP/例外/二重呼び出しの4パターン）・
  2h（データ契約のdict化/JSON化）・2e拡張（scope block時のRESULT/DONE確定）・
  7c（report_generatorのATTACK MODE/FINDINGマーカー抽出バグの回帰テスト）・
  9b（AuditAgentの_build_coverage/_determine_state単体テスト＋ファイル読込失敗の非LLM
  E2E）・10c（MonitorAgentの_build_coverage/_determine_state単体テスト＋攻撃パターン
  無しログの非LLM E2E）・11b（ReconAgentの_build_coverage/_determine_state単体テスト）・
  13b（LangGraphAuditAgentの_determine_state単体テスト＋同E2E。langgraph未導入
  環境ではSKIP）・16i（FuzzAgentの_build_coverage/_determine_stateの単体テスト）・
  16j（注入点0件の実run()でのRESULT/DONE確定、非LLM E2E）を追加。
  （`tools/run_selftest.py` 124 PASS / 0 FAIL、実LLM系5件は既定どおりSKIP・2026-09-05）

- **P1.2続き（AUDIT証拠保存・入力マスキング、2026-10-11）**:
  `core/evidence_store.py`に`CodeEvidence`・`save_code_evidence()`・`relativize_path()`・
  `omissions`を追加し、保存処理を`_persist()`へ共通化。`core/redaction.mask_source()`を追加。
  `agents/audit_agent.py`: 読込直後にソースをマスク→AST観測を`save_evidence`時のみ保存→
  IDをプロンプトへ渡し引用させる→実在IDのみ採用、除外IDは`errors`へ。
  `core/orchestrator.load_code`も同じマスクを適用。`_findings_from_markers`に
  `rejected_evidence_ids`引数を追加。
  **設計判断**: 後付けの抜粋（LLM報告のLINES由来）は作らない／マスクは既存動作の変更
  （検出品質とのトレードオフ）だが、ロードマップの「LLM送信前マスク」要件を優先して
  ON/OFFに関係なく有効にした。値依存の判断（既定パスワード等）が弱まる点はAGENTS.mdに記載。
  テスト: `tools/test_audit_evidence.py`（モックLLMで`AuditAgent.run()`を実走。
  ダミー秘密値が保存物・LLM受信内容・investigationに残らない、ON/OFF、未知ID拒否、
  上限省略、保存失敗、相対path）。`tools/run_selftest.py` 144 PASS / 0 FAIL / 5 SKIP。

- **P1.2続き（DEFENSE証拠保存・ログ入力マスキング、2026-10-11）**:
  `core/evidence_store.py`に`LogEvidence`・`save_log_evidence()`、`core/redaction.py`に
  `mask_log_line()`を追加。`agents/monitor_agent.py`: パターン検出は生の行→マスク済みの行を
  バッファ/表示/LLM/保存へ。`save_evidence`時のみシグネチャ一致行を保存しIDをLLMへ渡す。
  `_findings_from_markers`はTHREAT形式でもそのまま利用できた（`_parse`が共通キーへ正規化）。
  **設計判断**: 検出は生、以降はマスク済み。機密名パラメータ内のペイロードはLLMに渡らない
  トレードオフをAGENTS.mdに記載。テスト: `tools/test_defense_evidence.py`（モックLLMで
  `MonitorAgent.run()`を実走）。`tools/run_selftest.py` 145 PASS / 0 FAIL / 5 SKIP。

- **P1.2続き（ATTACK: CTFフラグの中身・取得経路のレポート化、2026-10-11）**:
  Hiro指示により、ATTACKの証拠保存は「取得フラグの中身と経路をレポートに残す」範囲で実装。
  `agents/recon_agent.py`に`_walk_leaves`/`_flag_excerpt`/`_record_active_route`/
  `_flag_findings`を追加し、フラグを`CTF_FLAG`/`INFO`のFindingとしてScanResultへ載せた。
  Flag Huntの検出はrecon_data全体のJSON化から再帰走査に変更（検出フィールドを記録するため）。
  送信ロジック・安全ガードは無変更。テスト: `tools/test_flag_routes.py`
  （Active/Passive経路、証拠保存ON、URL/パラメータのマスク、HTML/MD/PDF）。
  `tools/run_selftest.py` 146 PASS / 0 FAIL / 5 SKIP。

- **P1.2続き（FUZZのIDOR証拠、2026-10-11）**: `_detect_idor`の兆候に両セッションの応答を持たせ、
  `FuzzAgent._save_evidence()`へ保存処理を切り出して異常＋IDORを共通保存。IDOR兆候の
  evidence_idをプロンプトへ埋め込み。テスト: selftest 16o（モックIDORサーバで実検出→保存→
  Cookie値マスク→ID採用）。`tools/run_selftest.py` 149 PASS / 0 FAIL / 5 SKIP。

- **P1.2続き（FUZZの保存省略理由・未知ID記録、2026-10-11）**: `_save_evidence`が
  `store.omissions`を、`run()`が`rejected_evidence_ids`を`errors`へ反映。AUDIT/DEFENSEと同方式。
  テスト: selftest 16oに2件追加。

- **P1.2続き（FUZZ入力マスキング、2026-10-11）**: 表示・fuzzerログ・LLMサマリーを
  `mask_log_line()`でマスク。`_known_secrets`を複数Cookie対応に拡張。テスト:
  `tools/test_fuzz_masking.py`（ローカルサーバ＋モックLLMで`FuzzAgent.run()`を実走し、
  表示/LLM/保存物にURLトークン・Cookie値が残らないことを確認。実走で、fuzzerのcrawlログに
  URLトークンが出るリークを発見し修正）。

- **P1.2続き（JSON出力、2026-10-11）**: `generate_json`/`save_json`/`export_json`と全4パネルの
  JSONボタンを追加。証拠参照はHTML/MDと同じ検証を再利用。テスト: `test_structured_reports`に
  JSON（確定結果・旧マーカー）とパネル転送を追加。GUI目視確認は未実施。

- **P1.2続き（ATTACK偵察観測の証拠保存、2026-10-11）**: `ObservationEvidence`/
  `save_observation_evidence`、`ReconAgent._save_recon_evidence`、サマリーへのID埋め込み、
  LLM送信前のサマリーマスク、未知ID/上限のerrors記録。フラグ証拠とstore共有、errorsは
  重複を畳む。テスト: `tools/test_attack_evidence.py`（部品単位。`run()`全体は
  ポートスキャンを伴うため未実走＝未検証）。

- **P1.2続き（LangGraph版の証拠保存、2026-10-11）**: `audit_agent.save_ast_evidence()`へ共通化し、
  `build_audit_graph(evidence_hook=)`で`load_code`後に呼ぶ。AuditStateに
  `evidence_listing/evidence_instruction`を追加。テスト: `test_audit_evidence`に
  LangGraphEvidenceTest（ON/OFF・マスク・実在ID採用・未知ID記録）。

- **自律化 Phase A（2026-10-21〜22）**: 設計 `docs/AUTONOMOUS_PLATFORM_DESIGN.md`・`AUTONOMOUS_PHASE_A_DESIGN.md`・
  `AUTONOMOUS_IMPLEMENTATION_PLAN.md`。実装: `core/autonomy/`（`journal.py` 追記式JSONL・seq/prev_hash連鎖・
  部分行回復・fail closed・単一writer・`run_finished`は一度だけ/16KB/終端、`actions.py`、`policy_gate.py`
  スコープ/副作用クラス/予算/重複/ApprovalGrant（引数ハッシュ・期限・一回限り・期限切れは常にdeny）・判断を
  実行前に記録、`budget.py` LLMは呼出前に予約、`task_graph.py` `unknown_outcome`、`runner.py`）、
  `agents/fuzz_capabilities.py`（WEB FUZZ新経路`AutonomousFuzzAgent`。現行`FuzzAgent`は無変更）。
  既存コードへの追加のみの変更: `EvidenceStore`の由来情報（`content_sha256`/`action_id`/`masking_version`/
  `truncated`と`verify()`）、`WebFuzzer.fuzz_log`（検査単位の実行記録）、`BaseAgent._llm_gate`と
  `LLMClient`の任意`max_tokens`/`usage_out`。testlabに決定論fixtureと`ground_truth.json`。
  テスト: selftest 16m〜16s（Journal 16件、特性化8件、由来情報7件、Gate/予算/状態25件、実行記録7件、
  LLMゲート11件、新経路24件）。`SELFTEST_NON_LLM_ONLY=1` 160 PASS / 0 FAIL / 5 SKIP。
  現行経路との意図的な差は `AUTONOMOUS_PHASE_A_DESIGN.md` §13。未実装: Planner（固定計画のみ）、再開（SQLite）、
  Fact/Hypothesisストア、Validation、他モードのcapability化、解決先IP再検査、GUI接続。実LLM・実環境での確認は未実施。

- **自律化 Phase B（B1〜B3、2026-10-22）**: `docs/AUTONOMOUS_PHASE_B_DESIGN.md`。`core/autonomy/run_store.py`
  （sqlite3 WAL・`synchronous=FULL`。計画・タスク状態・マスク済み出力・消費済み承認）、`resume.py`
  （プロファイルハッシュ、ジャーナル⇔ストアの突合）。書込み順序は journal `action_started` → 実行 →
  store commit → journal `action_finished`（`event_id` を両者で共有）。再開は完了済みタスクを再実行せず出力を復元し、
  結果不明（`unknown_outcome`）は自動再実行しない（`retry_unknown`で明示、予算は不明分を宣言上限で計上）、
  認証はセッションがプロセス内にしか無いため再適用（新しい承認が必要）、プロファイル不一致・終了済みRunは拒否。
  `AutonomousFuzzAgent.run(resume_run_id=, retry_unknown=, additional_requests=)`。テスト: `tools/test_fuzz_resume.py`
  （子プロセスを`os._exit(137)`で強制終了 × 4タスク × 5位置の全走査、承認・拒否・非漏えい）、`test_run_store.py`。
  selftest 16t/16u。`SELFTEST_NON_LLM_ONLY=1` 162 PASS / 0 FAIL / 5 SKIP。未実装: CLI（B4）、案件プロファイル、
  所見台帳の差分、他モード。


- **自律化 Phase B4（2026-10-22）**: `cli.py` を追加。`scan fuzz / resume / status`、必須の空でない
  `--allow`、JSON stdout・進捗stderr、Run配下の結果保存と`--out`、終了コード130→2→1→0。
  認証は0600・所有者検査済み通常ファイルのみ。`--approve-auth`で役割ごとに5分・一回限りの承認を発行し、
  未承認では送信しない。クラッシュ再開は`load_profile()`と既存run引数を使用。SIGINTは協調停止し結果保存後130。
  `status`はread-onlyのSQLiteとジャーナルを参照し、実行や所見閾値の再評価は行わない。
  事前コミット指定のprofile_json/load_profileは既に`aa3b53e`でコミット済みだったため重複コミットは行っていない。
  既存FuzzAgent/WebFuzzer/AutonomousFuzzAgentは変更なし。READMEに操作・制約を記載。
  `tools/test_cli.py`の11試験をselftest 16vへ統合（MockLLM・loopback fixture・子プロセス）。
  検証コマンド: `PYTHONUTF8=1 SELFTEST_NON_LLM_ONLY=1 .venv/bin/python3 tools/run_selftest.py`。
  出力末尾: `163 PASS / 0 FAIL / 5 SKIP (89.2s)`。実LLM系5項目・GUI・Windowsは未検証。
  サンドボックス内はsocket作成がEPERMのため、承認済みのサンドボックス外実行で検証した。
  試験設計時に確認した既存の限界: 送信予算1でクロールが注入点発見前に打ち切られる場合、
  AutonomousFuzzAgentがcompletedを返すケースがある。CLIは既存ScanResultのstateを採用し、今回は検出側を変更していない。
  この境界の改善はP2.1の予算切れfixtureで別途扱う。

- **P2.1 一部（WEB FUZZ detector固定モード、2026-10-22）**: `tools/benchmark.py`（`python tools/benchmark.py web-fuzz
  [--runs N] [--save-baseline PATH] [--compare]`）、罠を含む`testlab/fixtures/web_benchmark.py`、正解データ
  `testlab/benchmark/ground_truth_web_fuzz.json`（21ケース。IDORは期待権限つき）。集計器は(rule_id, location)で照合し、
  重複は1件、未検査を正常例の正解に数えず、分母0はN/A。**改修前基準値**（`testlab/baselines/web_fuzz_detector.json`）:
  TP6/FP7/FN0、IDORはPrecision0.29（公開/閲覧者別/アクセス制御外ページを長さ類似だけで候補にする）、SSTIとXSSは各FP1
  （偶然の49・text/plain反射）、SQLI/TRAVERSALは静的な罠を無視。3回実行で検出集合は一致。テスト: `tools/test_benchmark.py`
  （selftest 16w）。`SELFTEST_NON_LLM_ONLY=1` 164 PASS / 0 FAIL / 5 SKIP。P2.1全体は未完了（実LLM評価・他モード等）。


## 2026-10-22 P2.2(IDOR一部): ログイン画面・公開リソースを根拠にしない
`WebFuzzer._detect_idor` に、(1) A/B応答がログイン画面(`type=password`)なら除外、(2) 認証なしセッションでも同内容が取れる
公開リソースなら除外、を追加(候補1件につき最大+1リクエスト)。ベンチマーク: IDOR TP2→2、FP6→1、TN2→7。
残FPは閲覧者別ページ(/order)で期待権限表が必要(未実装)。selftestのIDORモックは認証必須に修正(公開扱いで除外されるため)。
検証: `SELFTEST_NON_LLM_ONLY=1` 164 PASS / 0 FAIL / 5 SKIP。SSTI・XSS改善と期待権限入力は未着手。

## 2026-10-22 P2.2(SSTI/XSS)
SSTI: 49出現後に別の算術式でも評価されるか追加確認(`WebFuzzer._confirm_ssti`、乱数は`_rng`でseed固定可、予算に含む)。
XSS: HTML以外のcontent-typeの反射は兆候にしない。文言は「反射観測…ブラウザでの実行は未確認」。
ベンチマーク: SSTI/XSSともFP1→0、TP維持。検証はコミット時のselftest結果を参照(SELFTEST_NON_LLM_ONLY=1)。

## 2026-10-22 P2.2(IDOR期待権限表・検出器側)/P3.1設計
`core/engagement.py`(`parse_idor_expectations`)、`WebFuzzer.idor_expectations`/`_expectation_for`、所見の`basis`(expectation|observed)。
ベンチマーク`--with-expectations`と基準値を追加(IDOR FP 1→0・TP維持。表は正解データ由来の上限値)。案件ファイル設計はPRACTICAL_ROADMAP §P3.1。
未実装: 表をCLI/GUI/再開経路へ渡す配線。

## 2026-10-22 P3.1(1)(2): `--engagement`でIDOR期待権限表をfuzz CLIへ配線
`cli.py scan fuzz --engagement FILE`(キーは`engagement_id`/`idor_expectations`のみ・未知キーと不正な表はJSONのfailedで送信前に終了)。
`AutonomousFuzzAgent.run(idor_expectations=)`が検証→`WebFuzzer.idor_expectations`へ渡し、表がある場合だけprofile_hashへ含め、
profile_jsonに保存して`resume`で復元。実BenchmarkServerへのCLI実行で、表なしはobserved3件、表あり(/publicをb=deny宣言)で
`basis=expectation`の所見が追加されることを確認。`tools/test_cli.py`に検証・復元の2試験を追加。
未実装: 旧FuzzAgent(GUI)経路・GUI入力、所見のbasisのレポート表示、`--targets-file`、exclude優先。

## 2026-10-22 P3.1(3): 除外優先・`--targets-file`
`--exclude`/案件ファイル`exclude`(host/IP/CIDR)を許可より優先(`AutonomousFuzzAgent.run(excluded_targets=)`→Policy Gate、
表がある時のみprofile_hashに含め、profile_jsonへ保存して再開で復元)。`--targets-file`(逐次・最大50件・重複除去・1件でも不正なら全体を実行しない)、
`--auth-file`併用は拒否。`tools/test_cli.py`に除外優先・バッチ・併用拒否の3試験を追加。

## 2026-10-22 P3.1(4一部): `scan audit`
`cli.py scan audit --target FILE [--out] [--fail-on] [--effort]`。AuditAgent(標準エンジン)を1回実行し、結果JSONをstdout・進捗をstderr。
`--allow`/ジャーナルは不要(ローカルファイルのみ)。LLMへ送るソースは常にマスク済み。`tools/test_cli.py`に試験を追加(MockLLM)。
未実装: attack/defense、LangGraph版の選択、`core/scan_runner.py`への共通化、`--format md`。

## 2026-10-22 P3.1(4一部): `scan defense`
`cli.py scan defense --target LOG`(MonitorAgentを`watch_mode=False`で1回走査)。試験はシグネチャ検知(アラート件数)を確認。
MockLLMの`complete()`は`{}`を返すため、所見(Finding)化はこの試験では検証していない(実LLM未検証)。`--duration`、attackは未実装。

## 2026-10-22 P3.1(4一部): `scan attack`
`cli.py scan attack --target T --allow ... [--exclude] [--profile] [--port-scope common|extended] [--udp] [--no-web]`。ReconAgentを`generate_exploit=False`で実行。
`allowed_targets`/`scope_mode=block`はプロセス内の`config._cfg`だけを一時的に上書きして終了時に戻す(config.jsonへ保存しない)。
除外は許可より優先し、範囲外・除外は送信前に終了。試験: 範囲外/除外で0リクエスト、--allow必須、許可内で完走。
実LLM・実環境での確認は未実施。`core/scan_runner.py`への共通化・attackの`--targets-file`は未実装。

## 2026-10-22 P3.2(中核): 所見台帳
`core/findings_ledger.py`(追記式JSONL・排他ロック・差分NEW/PERSISTING/NOT_OBSERVED/REGRESSED/UNVERIFIED・対応status・期限付き抑制)、
`core.settings.DETECTOR_VERSIONS`と`BaseAgent._finalize`でScanResult.detector_versionを設定(従来は常に空)。
CLI: `--engagement-id`で自動記録、`diff`/`mark`/`suppress`/`findings`。試験: `tools/test_findings_ledger.py`(selftest 16x)、`tools/test_cli.py`。
設計判断と制約の詳細は docs/PRACTICAL_ROADMAP.md §P3.2。レポート側の抑制フィルター・差分表示は未実装。

## 2026-10-22 P4.1(初期版): OpenAPI入力
`tools/openapi_loader.py`、`WebFuzzer.seed_points`/`seed_rejected`、`AutonomousFuzzAgent.run(seed_points=)`(profile_hashとprofile_jsonへ保存)、
CLI `openapi FILE` / `scan fuzz --openapi ... --openapi-op ...`。副次修正: CLIの単一結果から`target`を消していた`result.pop("target")`を除去(台帳へ対象が記録されなかった)。
制約と未実装は docs/PRACTICAL_ROADMAP.md §P4.1。

## 2026-10-22 P4.3(中核): 実ログ対応
`LogWatcher`の作り直し(バイナリ読み・inode+サイズ追跡・部分行保持・rename-create/copytruncate/一時不在、`stats`)、`normalize_log_line()`(JSONL平坦化、
不正行は生テキストで検知)、`core/mitre.py`(未収録IDは「未確認」)、`MonitorAgent`への接続(縮小時はpartial+注記)。
試験: `tools/test_log_watcher.py`(selftest 16z)。journald/syslog・gzip回転・長時間実運用検証は未実施。

## 2026-10-22 P4.2(初期版): Python複数ファイル監査
`tools/code_index.py`、`AuditAgent._run_project`(ディレクトリ入力のみ)、CLI `scan audit --target DIR`。coverageは送信した関数を含むファイルのみtested、
未送信・省略・解析不能はskipped、上限や未解析があればpartial。LangGraph版・GUI・証拠保存・CVE照合・実LLM評価は未対応。

## 2026-10-22 P2.1(DEFENSE detector固定モード)
`tools/benchmark.py defense`、`testlab/benchmark/ground_truth_defense.json`(43判定)、基準値`testlab/baselines/defense_signatures.json`。
検知器は無変更。`tools/test_benchmark.py`に`DefenseBenchmarkTest`を追加(selftest 16w)。

## 2026-10-22 DEFENSEシグネチャ改善(defense-2)
`MonitorAgent._pattern_match`にURLデコード照合とSCANNERのUA限定、`ATTACK_PATTERNS`のBRUTE_FORCE/CMS_PROBE/SQL末尾`--`/`$()`を文脈限定。
ベンチマーク全58判定: TP25・FP0・FN4(未見ケース由来)。修正前基準値は`defense_signatures.before-defense-2.json`。

## 2026-10-22 P3.2(レポート連携)
`Ledger.report_view(result)`(読み取り専用)を追加。`scan_result`に`ledger`キーとして渡すと、HTML/MD/PDF/JSONが共通の`_apply_ledger`で
期限内の抑制所見を所見一覧・件数から除外し、抑制件数・理由・期限、直前scanとの差分(NEW/PERSISTING/REGRESSED/NOT_OBSERVED/UNVERIFIED)、
所見ごとのfinding_idと対応statusを表示する。期限切れの抑制は表示に戻る。未記録scanや過去scanなしは差分を出さず理由を表示。`ledger`なしは従来どおり。
試験: `tools/test_ledger_reports.py`(selftest 16x2)。GUI・CLIからのengagement_id指定は未配線(GUI目視も未実施)。

## 2026-10-22 P3.1(追補): format md / effort auto / defense duration / profiles
`cli.py`: `--format md`(`render_markdown`)、`--effort auto`(`resolve_effort`→`classify_effort`)、`scan defense --duration`
(`MonitorAgent.run(max_seconds=)`。期限終了はcompletedで`errors`に注記)、`--use-profile`(`expand_profile`、`config.json`の`profiles`・`PROFILE_KEYS`の許可キーのみ)。
試験: `tools/test_cli.py`(26件)。実LLMでのautoの分類は未検証(MockLLMでは既定へフォールバック)。

## 2026-10-22 DEFENSEシグネチャ改善(defense-3)
`ATTACK_PATTERNS`: UNION ALL SELECT、`|`+nc/bash/sh、`Failed password for`、IPv6ループバックSSRFを追加。未見8判定を追加し66判定でTP33・FP0・FN0。
修正前基準値は`defense_signatures.before-defense-3.json`。`DETECTOR_VERSIONS["DEFENSE"]="defense-3"`。

## 2026-10-22 P3.1(追補): audit/defense/attackの--targets-file
`cli.py`: `--target`と排他の`--targets-file`(auditはパス、attackはhost/URL、defenseはログパス)。逐次実行し`aggregate()`で集約、台帳は各結果を記録。
SIGINT後の残りは「中断のため未実行」。試験: `tools/test_cli.py`(27件)。

## 2026-10-22 P4.1(追補): OpenAPI YAML対応
`openapi_loader._load_yaml`: JSONで読めない場合のみPyYAMLの`SafeLoader`で読む。alias/anchorは展開膨張を避けるため拒否、`!!python`等のタグ・不正・深い入れ子はOpenApiError。
通信しない・serversを使わない点はJSONと同じ。`requirements.txt`にPyYAMLを明示。仕様変更に伴い、旧試験の「YAMLは拒否」ケースを削除し有効YAMLの試験へ移した。

## 2026-10-22 P3.1(追補): core/scan_runner.py
挙動を変えないリファクタリング。`run_attack`/`run_local`/`ConsoleBus`/`aggregate`/`masked`/`resolve_effort`/入力検査を`core/scan_runner.py`へ移動(GUI非依存)。
`cli.CLIError`は`scan_runner.RunnerError`の別名。LLM生成は`llm_factory`でcli側から渡し、既存試験の`cli.LLMClient`差し替えを維持。WEB FUZZ・resume・statusは未移動。

## 2026-10-22 P4.2(追補): LangGraph版の複数ファイル監査
`LangGraphAuditAgent._run_project`: ディレクトリ入力で標準エンジンと同じ`code_index`の索引・マスク・優先付き文脈・coverage/注記を使う。
`build_audit_graph(source_loader=)`で本文を差し替え、文脈は深層解析の上限(8000字)に合わせて表層/深層が同じ本文を見る(smart_truncateが働かない)。
ASTプリスキャン・証拠保存・CVE照合は未対応。試験: `tools/test_code_index.py`の`LangGraphProjectTest`(モックLLMのみ。実LLMでの深層解析の質は未検証)。

## 2026-10-22 P2.1(追補): 実LLM評価ハーネスとAUDITの初回実測
`tools/live_eval.py`(config.json非変更・呼出し上限・タイムアウト指定)、`testlab/benchmark/ground_truth_audit.json`、`tools/test_live_eval.py`(selftest 16ab)。
無料枠モデルでの3回: 再現率1.0/1.0/0.375。詳細と限界は docs/PRACTICAL_ROADMAP.md 付録。

## 2026-10-22 実LLM動作確認(無料枠モデル・各1回)
AUDITの証拠ID引用、`--effort auto`、DEFENSEのMITRE ID、WEB FUZZのトリアージを確認。結果と限界は docs/PRACTICAL_ROADMAP.md 付録。コード変更なし。

## 2026-10-22 実LLM測定(WEB FUZZ・DEFENSE 各3回)
無料枠モデル・effort=speedで各3回。WEB FUZZは3回とも同じ2所見(重大度のみ揺れ)、DEFENSEは所見の切り分けと重大度が回ごとに変動し、3回目で未収録MITRE IDの「未確認」表示が実LLM出力で発火。結果と限界は docs/PRACTICAL_ROADMAP.md 付録。コード変更なし。

## 2026-10-22 P3.2(追補): CLIの出力へ台帳ビューを配線
`cli.record_ledger`が記録後に`Ledger.report_view()`を各結果の`ledger`へ付ける(バッチは対象ごと)。`--format md`は抑制除外・差分表示、`exit_code`の`--fail-on`は`active_findings()`で期限内抑制を除く(JSONの`findings`は全件のまま。台帳記録失敗時はビューが無く全所見で判定)。
試験: `tools/test_cli.py`の`test_scan_output_carries_ledger_view_and_fail_on_ignores_only_active_suppressions`(監査2ファイルのバッチ。一部抑制は失敗のまま、全件抑制で0、md出力、engagement無しは従来どおり)。cli.py変更を外すと落ちることを確認。GUIは未配線。

## 2026-10-22 P3.1(追補): WEB FUZZの対象ごと実行を`core/scan_runner.py`へ移動
`run_fuzz_targets()`(除外判定・認証承認grantの生成・AutonomousFuzzAgentの起動・結果収集・中断時のskipped)を`cli.main`から移した。挙動は不変(承認TTL300秒・除外優先・agentへのSIGINT伝播は`on_agent`/`was_interrupted`経由)。`cli.py`は入力検査・認証読込・案件設定・OpenAPI選択・LLM生成・status・台帳記録を担当。試験: `tools/test_cli.py` 29件が移動前後で同一結果。

## 2026-10-22 P3.1(追補): rate_limit_rpsとprofilesのscope_mode
`scan fuzz --rate-limit-rps R`(0<R<=1000)。`WebFuzzer(rate_limit_rps=)`はプロファイルの`path_rate_per_sec`との小さい方を採用し、緩める方向には働かない(無制限プロファイルには上限を足せる)。Runのプロファイル(`profile_json`)に保存して再開でも維持し、指定時だけ`profile_hash`に入れる(未指定のRunとの再開互換を保つ)。
`config.json`のprofilesに`rate_limit_rps`(fuzzのみ)と`scope_mode`を追加。`scope_mode`は新規実行が常にblockのため`"block"`の明示だけ受理し、`warn`等は拒否する(安全境界を緩める設定を作らない)。試験: `tools/test_cli.py`(3件追加)。

## 2026-10-22 P4.1(追補): サンプル値生成の拡張と認証要件の表示
`tools/openapi_loader.py`: `_sample`をparameter側example/examples優先・allOf統合・oneOf/anyOf先頭・3.1の型配列・array要素・最小値・formatに拡張(再帰/循環は深さ制限と既存の$ref循環検出)。`Operation.auth`(scheme名・種類・in/schemeのみ)を追加し`openapi FILE`の出力に含める。送信境界(GET+queryのみ・path値生成なし・body/POSTなし・serversを使わない)は不変。
試験: `tools/test_openapi_loader.py`に`SampleAndAuthTest`(3件)。ヘッダ名・説明・外部URLが出力に漏れないことも確認。

## 2026-10-22 P4.3(追補): gzipアーカイブ入力
`LogWatcher`が`.gz`を1回通しで読む(`_read_gzip`: 展開後256MiB・1行1MiBの上限、BadGzipFile/EOFError/zlib.errorをstatsへ記録)。`MonitorAgent`は上限超過・破損でstateをpartialにしerrorsへ注記。試験: `tools/test_log_watcher.py`の`GzipArchiveTest`(5件)、`tools/test_cli.py`にCLI経由1件。journald/syslogは未実装。

## 2026-10-22 P4.3(追補): journaldアダプター
`tools/log_watcher.py`: `parse_journal_target()`、`LogWatcher._read_journal()`(固定引数のsubprocess・select+os.readで停止に応答・1行1MiB上限)、`normalize_log_line()`でjournaldの`MESSAGE`先頭化とバイト配列復号。`core/scan_runner.run_local`はdefenseの`journald*`対象をファイル検査の代わりにunit検証する。`MonitorAgent`は`journal_error`でpartial+注記。
試験: `tools/test_log_watcher.py`の`JournaldTest`(6件・偽のjournalctlで引数/エラー/追跡停止/検知を確認)、`tools/test_cli.py`にCLI経由1件(PATH上の偽journalctl、オプション注入unitは実行前に拒否)。実機のjournalctlは件数のみ確認(直近10000件を読め、不正行0・エラー無し)。権限不足環境・長時間追跡は未検証。

## 2026-10-22 P2.1(追補): ATTACK偵察のdetector固定ベンチと3つの検出修正
`testlab/fixtures/attack_benchmark.py`、`testlab/benchmark/ground_truth_attack.json`(122判定)、`tools/benchmark.py attack`、基準値`testlab/baselines/attack_recon.json`と改修前`attack_recon.before-fixes.json`、`tools/test_benchmark.py`の`AttackBenchmarkTest`(5件)。
`tools/web_prober.py`: soft-404検出(canary pathの指紋・found_pathsに`exposed`・結果に`soft_404`)、HttpOnly判定の大文字小文字無視、技術検出のヘッダーを`Key: Value`形式化。改修前 TP24/FP60/FN3(held含む全122判定) → 改修後 TP27/FP2/FN0。残FP2は本文のキーワード言及(意図的に未修正)。詳細と限界は docs/PRACTICAL_ROADMAP.md §P2.1。
