# 実践運用対応ロードマップ・実装引き継ぎ仕様

作成: 2026-09-02。改訂: 2026-09-05（ユーザー依頼によるコード調査と改善方針の具体化）。
改訂: 2026-09-18（別プロジェクトでの実装知見に基づき、過去scan/investigationの参照検索の構想を§9に追記）。
本書は**今後の実装順序・受け入れ条件の正本**である。以下の新規API・設定・コマンドは未実装の設計仕様であり、現行機能の説明ではない。
今回の調査はソースの静的確認であり、外部ターゲットや実LLMでの再現・精度評価は実施していない。

## 1. 目的と文書の役割

許可されたWeb/API診断・自分のコード監査・継続監視で、根拠付きの所見を保存し、修正後に再検査できるツールを目指す。
優先する成果は「検査範囲の制御」「観測事実と推論の区別」「未検査の可視化」「再現性」。指摘件数や攻撃機能の数を単独の品質指標にしない。

| 文書 | 役割 |
|---|---|
| [AGENTS.md](../AGENTS.md) / [CLAUDE.md](../CLAUDE.md) | 開発規約・既存の安全境界・検証手順。実装状況の要約 |
| 本書 | 未実装作業の順序・設計契約・受け入れ条件。新しい計画を別ファイルに複製しない |
| [DESIGN.md](DESIGN.md) | 既存システムの構成。古い将来案から着手順を決めない |
| [AGENT_ARCHITECTURE.md](AGENT_ARCHITECTURE.md) | STRONG/FAST・エフォート・検証器の設計 |
| [BOUNTY_ROADMAP.md](BOUNTY_ROADMAP.md) | 実装済みPhase A〜Dの設計経緯 |
| [BOUNTY_WEBFUZZ_WORKFLOW.md](BOUNTY_WEBFUZZ_WORKFLOW.md) | 現行GUIの操作手順。本書の未実装機能を使用可能と案内しない |
| [CTF_FLAG_HUNT.md](CTF_FLAG_HUNT.md) / [CTF_ACTIVE_FLAG_RETRIEVAL.md](CTF_ACTIVE_FLAG_RETRIEVAL.md) | 独立した既存CTF機能の仕様。本計画はCTFの権限・送信機能を拡張しない |

## 2. コード調査で確認した出発点

実装前に以下の関数と呼び出し経路を再確認する。実環境での漏えいや誤検知件数を確認したという意味ではない。

| 確認対象 | 現状と改善理由 |
|---|---|
| `tools/web_fuzzer.py`: `crawl()` / `_extract_forms()` / `_send()` | リンク探索はnetloc比較だがフォームactionに同等の検査がない。送信直前の共通検査が必要 |
| 同: `_form_login()` / `_get()` / `_send_as()` | ログイン通信は通常の予算計数を通らず自動リダイレクトを使用。セッションはTLS検証を無効化 |
| 同: `_bodies_similar()` | 本文の意味や一致ではなく長さ比でIDOR候補を選別。認可の期待値が必要 |
| 同: `_detect()` | SSTIは固定値49の出現、XSSは反射等の兆候を利用。脆弱性の確認と同一視しない |
| `agents/base_agent.py`: LLMヘルパー / `_safe_run()` | LLMエラーの表示・空文字復帰と実行全体の成否が分離。停止時の早期returnもある |
| `tools/report_generator.py`: `_parse()` | マーカー付き文章を所見へ変換。最終所見・下書き・証拠を独立管理していない |
| `agents/audit_agent.py`: `run()` / `smart_truncate()` | 単一ファイル入力、既定12,000文字の切り詰め。ファイル間の認可・データフローを扱いにくい |
| `tools/log_watcher.py`: `watch()` | 保存位置から読み直す。ファイル置換・縮小時の読取位置補正が必要 |

## 3. 実装順序と状態

依存順は **P0 → P1 → P2 → P3 → P4**。各行をレビュー可能な変更単位とする。最初の実装はP0.1のみ。
P2の最小ベンチマークはCLIを待たず、Pythonの呼び出し口から実行する。

| 状態 | ID | 作業 | 依存・完了の要点 |
|---|---|---|---|
| [x] | P0.1 | WEB FUZZの送信境界・共通予算 | 外部フォーム・転送先への送信ゼロ、認証も予算内 |
| [x] | P0.2 | レート・停止・認証状態・TLS設定 | P0.1。待機中に停止可能、認証失敗を区別 |
| [x] | P1.1 | 構造化所見・実行状態・EventBus配線 | P0。失敗や未検査を検出ゼロの成功にしない |
| [ ] | P1.2 | 証拠・マスキング・共通レポート | P1.1。保存からGUI/各形式の参照まで確認 |
| [ ] | P2.1 | 最小ベンチマーク・改修前基準値 | P1。正常例を含む評価、CLI不要 |
| [ ] | P2.2 | IDOR/SSTI/XSSの検出改善 | P2.1。変更前後の比較で品質を判断 |
| [ ] | P3.1 | CLI・実行単位の設定・案件プロファイル | P2。構造化結果と実行状態を利用 |
| [ ] | P3.2 | 案件別所見台帳・差分・抑制 | P3.1。未検査を修正済みにしない |
| [ ] | P4.1 | OpenAPI入力 | P3。列挙と送信を分離、許可済み操作のみ |
| [ ] | P4.2 | Python複数ファイル監査 | P3。関係する関数を索引化、未解析を明示 |
| [ ] | P4.3 | 実ログ対応・ローテーション | P3。置換・縮小・部分行を検証 |

P4内は用途に応じて一項目ずつ選択できる。保留事項を自動で追加しない。

### 進捗サマリ(最新: 2026-10-22・この表が進捗の入口)

進捗の正本はこの節。詳細な実装記録は `docs/IMPLEMENTATION_LOG.md`、各IDの未了事項は該当節、リポジトリ横断の概況は `~/projects/PROJECT_STATUS.md`。
実装やロードマップの状態が変わったら、**この表・§4/AGENTS.md §4・IMPLEMENTATION_LOG・PROJECT_STATUS.mdを同じ作業で更新する**。
チェックボックスは「受け入れ条件を全て満たし、未検証が無い」場合のみ [x] にする。

| ID | 進捗 | 実装済み | 残り・未検証 |
|---|---|---|---|
| P1.2 | ほぼ実装・未完了扱い | 証拠保存・マスキング・全4モードの配線・HTML/MD/PDF/JSON、AUDITで実LLMの証拠ID引用を1回確認 | GUI目視、他モードの実LLM引用、ATTACK画面ログの未マスク |
| P2.1 | 一部 | WEB FUZZ・DEFENSEシグネチャのdetector固定ベンチと基準値、AUDITの実LLM評価(無料枠モデル3回・`tools/live_eval.py`) | 他モデルでの実LLM評価、ATTACKの実LLM評価、WEB FUZZ/DEFENSEの大きな正解データでの実LLM評価(3回の小規模測定のみ)、ATTACKのベンチ、トークン使用量(現状は文字数のみ) |
| P2.2 | 検出器側は実装 | IDOR(ログイン/公開除外・期待権限表)、SSTI別式確認、XSS content-type | 期待権限表のGUI入力・旧FuzzAgent配線、同一origin確認URL、逆方向 |
| P3.1 | ほぼ実装 | `scan fuzz/audit/defense/attack`・`--targets-file`・`--engagement`・除外優先・`--format md`・`--effort auto`・`defense --duration`・`--use-profile`・`core/scan_runner.py`(ATTACK/AUDIT/DEFENSE/WEB FUZZ・resumeの対象ごと実行)・`--rate-limit-rps`・profilesの`rate_limit_rps`/`scope_mode`(block のみ) | 案件プロファイルのGUI入力、予算(max_llm_calls等)のprofiles化 |
| P3.2 | 中核+レポート連携 | 台帳・差分・mark/suppress/findings、レポート層の抑制除外と差分表示、CLI(`--engagement-id`)の出力への台帳ビュー付与・`--format md`の抑制除外/差分・`--fail-on`の期限内抑制除外 | GUIからのengagement_id指定と配線 |
| P4.1 | 初期版 | ローカルJSON/YAML・明示選択のGET+query | 複雑schema・path param・body・認証scheme・GUI |
| P4.2 | 初期版 | 標準エンジン・LangGraph版(モックLLM)の複数ファイル監査 | GUI、証拠保存、実LLM評価 |
| P4.3 | 中核 | ローテーション/縮小/部分行/JSONL/MITRE確認 | journald/syslog、gzip回転、長時間運用検証 |
| 共通 | 一部検証 | selftest 170 PASS / 0 FAIL / 5 SKIP(`SELFTEST_NON_LLM_ONLY=1`)。AUDITは実LLMで3回評価、証拠ID引用・effort autoは実LLMで各1回、DEFENSE・WEB FUZZは各3回の小規模測定(付録) | 実LLM系5件のselftest、AUDIT/DEFENSE/WEB FUZZ以外の実LLM評価、より大きな正解データでの複数回評価、GUIの目視確認は全体を通して未実施 |

## 4. P0: 通信・認証の境界

### P0.1 最初の変更: 全送信経路の同一オリジン検査と共通予算

対象: 新規 `core/http_transport.py`、既存 `tools/web_fuzzer.py`、`agents/fuzz_agent.py`、`tools/run_selftest.py`。
最初はWEB FUZZだけに適用し、ReconやCTFの送信経路を同時に書き換えない。

設計契約:

1. `normalize_origin(url)` はHTTP/HTTPSのみ受理し、scheme・正規化host・実効portを返す。HTTPとHTTPSは別origin。userinfo付きURLや不正portは拒否する。IPv6、既定port、省略portをテストする。
2. `HttpTransport.request(session, method, url, ...)` を唯一の送信口とする。`_get()`・`_send_as()`・ログインページGET・ログインPOSTがすべて通る。基準originは認証前に確定する。
3. 毎回送信直前にoriginを検査する。フォーム抽出時の除外は補助であり、送信口の検査を省略しない。既存scopeのwarn設定や空allow-listも、WEB FUZZの同一origin制約を無効にしない。
4. 自動リダイレクトを無効化する。クロール/プローブは原則3xx自体を観測。認証で追跡する場合は各hopを再検査し上限を持つ。GETの301/302/303/307/308とPOSTの303→GETを扱い、POSTの301/302/307/308は初期版では自動再送せず認証未確認とする。
5. 予算はスキャン単位でA/Bセッションが共有。実送信の試行ごとに送信前に1件予約し、失敗した通信も数える。転送hopも1件。拒否して未送信のURLは数えない。将来並列化しても超過しない原子的な予約にする。
6. 外部SSO/IdPへのログイン追跡は初期版では非対応。認証情報・Cookieを別originへ送らない。HTTPライブラリの暗黙の再試行で予算を迂回させない。
7. 既存仕様の不備修正なので、安全境界を迂回する旧動作を残すOFFトグルは追加しない。同一originの通常動作と既存GUI/APIの呼び出し互換性を保つ。

受け入れ条件:

- 基準サーバーと別originの受信記録サーバーを使い、外部action、scheme変更、別portへの転送で後者の受信件数が0。
- Cookie・任意認証ヘッダーを設定した同じ条件でも別originへの受信が0。
- ログイン、A/B比較、転送、通信失敗を混ぜても予算Nに対する実送信がN以下。0件予算では認証も送らない。
- 同一originの通常クロール・ログイン・フォーム・既存検出の回帰試験が通る。未対応の認証転送理由が出力される。

### P0.2 レート・停止・認証状態・TLS

対象: P0.1のファイル、`core/settings.py`、`core/config.py`、`gui/dialogs/auth_dialog.py`、`gui/panels/fuzz_panel.py`。

- `RequestPolicy` に総予算、秒あたり上限、timeout、redirect上限、連続429上限を集約。設定値をエージェントに直書きしない。
- 429の`Retry-After`は秒とHTTP-dateに対応。不正値は上限付きバックオフ。指定待機が実行期限を超える場合は早く再送せず未完了として終了する。
- 初期版はプローブ・認証POSTを自動再試行しない。GETの再試行は有限回・予算内。低並列とジッターは維持する。
- 待機は停止イベントで中断可能にし、停止後は新しい送信を開始しない。進行中の同期HTTP呼び出しはtimeoutまで残り得ることを明記し、ストリーム読取量・時間も制限する。
- 認証状態は`authenticated / anonymous / expired / unknown`。Cookie設定だけでは成功とせず、任意の同一origin確認URLと期待フィールドで判定する。失敗を検知した認証必須検査はskipし理由を残す。
- TLS検証ONと独自CAを選べる設定を追加。既存インストールの暗黙変更を避け、旧設定は警告付きで維持、新しい案件プロファイルは検証ONを既定とする。自己署名証明書は案件ごとに明示設定する。

受け入れ条件: 仮想時計によるレート/429試験、待機中STOP、認証切れ、TLS検証成否、応答サイズ上限を検証。P1実装後はskip理由を構造化結果にも接続する。

## 5. P1: 構造化結果と証拠

### P1.1 データ契約と実行ライフサイクル

対象: 新規 `core/findings.py`、`agents/base_agent.py`、各agent、`core/orchestrator.py`、`core/event_bus.py`、GUI各panel。
標準ライブラリのdataclass等を利用し、特定LLMプロバイダーのJSON出力機能を必須にしない。

| 型 | 必須の内容 |
|---|---|
| `ScanResult` | `schema_version`, `scan_id`, `engagement_id`, mode, target, 開始/終了時刻, `state`, エラー一覧, coverage, findings, 設定/検出器/モデル/プロンプトの版 |
| `Finding` | `finding_id`, `rule_id`, 位置, severity, `verification_state`, `evidence_ids`, 説明, 修正案, 検証器の支持情報 |
| coverage項目 | 対象endpoint/コード位置・parameter・rule・認証context、`tested / skipped / failed`、理由。単なるページ数では代用しない |

- 実行状態は`completed / partial / failed / cancelled`。予算切れ・認証失敗・必須LLMのエラーや不正応答は、検査の実績に応じてpartialまたはfailed。completedは指定した検査範囲について完了した意味であり、対象に脆弱性がない保証ではない。
- `verification_state`は`observed / corroborated / manually_confirmed`。LLMが同意しただけでmanually_confirmedへ昇格しない。severity、対応status、アンサンブル支持率を混同しない。
- LLMヘルパーはエラーを構造化して記録する。FAST失敗時の既存プローブへの代替など必要検査を完遂できた場合は、代替の事実を記録し、無条件に全体failedにはしない。
- `RESULT`イベントを追加し、最終結果を確定してから`DONE`を一度だけ送る。例外・STOP・早期returnでも最終化する。既存`DONE.error`は維持し、partial/failed/cancelledを成功扱いしない。
- draftはOUTPUTの表示用。最終findingsとSTATSは確定データから計算し、下書きと検証結果を二重集計しない。既存の少数意見も保持するunion方針は維持する。
- 対象HTML・コードコメント・ログは信頼しない入力として区切る。そこに含まれる指示でscope・送信予算・ツール実行を変えない。

受け入れ条件: LLM空応答/例外、不正マーカー、STOP、scope拒否、注入点なし、予算切れの結果とイベント順を検証。全4モードとStandard/LangGraphで同じ契約を満たす。

### P1.2 証拠保存と出力の移行

進捗（2026-09-06）: 全4GUIパネル→確定ScanResult→HTML/MD/PDFの経路と証拠参照を実装。
確定所見の抜粋・分析本文、実行/確認状態、errors/coverageを保持し、下書きは再集計しない。
旧マーカー入力は互換維持。残りはAUDIT/DEFENSE等の証拠保存、全表示/LLM入力前の
マスキング、IDOR証拠、保存省略理由、未知IDのvalidation error、JSON出力。
進捗（2026-10-11）: AUDIT標準エンジン（ASTプリスキャンの決定的観測）とDEFENSE（シグネチャ
一致行）の証拠保存、LLM送信前のソース/ログマスキング、未知ID/上限省略/保存失敗のerrors記録を
実装。ATTACKはCTFフラグの中身・取得経路のレポート化まで実装（LLM所見の証拠保存は未対応）。
FUZZのIDOR証拠も保存対応済み。FUZZの入力マスキングも実装済み。JSON出力、ATTACKの偵察観測、LangGraph版の証拠保存も実装済み。実装範囲は一通り完了。
完了扱いにする前の未了事項: GUI目視、実LLMでの引用挙動確認、ATTACK画面表示ログの未マスク。
本項目は未完了。証拠ファイルを後から移動・削除した場合のリンク切れは検査しない。

対象: 新規 `core/evidence_store.py`、`core/redaction.py`、`tools/report_generator.py`、`gui/export_util.py`、各agent/送信層。

- HTTP証拠はmethod・マスク済みURL/headers/body抜粋・status・比較用通常応答・時刻・省略理由。コードは相対path・範囲・抜粋、ログは時刻・入力元・マスク済み抜粋を扱う。
- `reports/evidence/<scan_id>/`へ所見に必要な証拠のみ保存し、件数・1件のサイズ・総容量を制限する。全通信の無制限保存は実装しない。
- Cookie/Set-Cookie/Authorization、設定した認証ヘッダー、URL中やJSON/form中の機密値を**ディスク保存・GUI/ログ表示・LLM送信より前に**マスクする。マスク済み証拠にハッシュを付ける。ハッシュは改ざん検出の補助であり匿名化ではない。
- 保存失敗は明示し所見を破棄しない。raw内容を別のデバッグログへ退避しない。証拠の削減・マスキングによる再現性の限界も記載する。
- 証拠保存は新設定`save_evidence`で明示的に有効化（既存設定ではOFF）。OFFでも構造化された観測と保存未実施の表示は残す。ONでも生の認証情報は保存しない。
- LLMに渡す証拠IDの集合を固定し、存在しないIDは採用せずvalidation errorとする。これは証拠の意味まで正しいと保証する仕組みではない。
- `_parse()`を旧マーカー変換アダプターとして残し、JSON/MD/HTML/PDFを共通Findingから生成する。旧レポートは証拠・coverage不明として読む。過去の生データを自動再処理・外部送信しない。
- HTML/MDには相対証拠リンク、PDFには証拠IDと保存場所を出す。各形式で確認状態・抑制件数を表示する。出力文字列をエスケープし、証拠IDをそのまま任意pathにしない。

受け入れ条件: 固定したダミー秘密値が全出力・保存物・LLMモックの受信内容に残らない。旧マーカー互換、未知証拠ID拒否、保存失敗、容量超過、各形式からの証拠参照を検証する。

## 6. P2: 評価を先に作り、既存検出を改善する

### P2.1 ベンチマーク

対象: 新規 `tools/benchmark.py`、`testlab/fixtures/`、`testlab/ground_truth.json`、既存testlab/selftest。

- CLIに依存せずdetector/agentへ固定入力とLLMモックを注入する呼び出し口を作る。後でP3のrunnerに接続する。
- SQLi/XSS/SSTI/IDORごとに脆弱例と正常例を用意。公開オブジェクト、別内容で同じ長さの本文、共通ログイン画面、認証期限切れ、エスケープされた反射、偶然49を含む応答を含める。
- ground truthはcase_id・rule_id・location・期待結果・期待権限で持つ。LLMのタイトル文字列で正解照合しない。重複所見は同じケースのTPを水増ししない。
- クラス別TP/FP/FN、Precision、Recall、未検査率、所要時間、HTTP試行数、LLM使用量を出す。分母0はN/A、使用量を取得できない場合はunknown。
- 未検査を正常例の正解に数えない。脆弱な未検査ケースはend-to-end評価の見逃しとして計上し、検査済み部分の評価と分ける。
- detector固定評価と実LLM評価を別モードにする。CIは前者だけ。実LLM評価はモデル/設定/プロンプト/ソースcommitと実行回数を保存し、反復による変動を示す。
- P2.2変更前に同じfixtureで基準値を保存する。現testlabの模擬応答だけで実世界の精度を主張しない。

受け入れ条件: 手計算可能な予測集合で集計器を検証し、同じ固定入力では同じ結果になる。LLM接続失敗でも評価成功を偽装しない。

2026-10-22 進捗: WEB FUZZの**detector固定モード**のみ実装（`tools/benchmark.py`、`testlab/fixtures/web_benchmark.py`、
`testlab/benchmark/ground_truth_web_fuzz.json`、基準値 `testlab/baselines/web_fuzz_detector.json`、`tools/test_benchmark.py`）。
SQLi/XSS/SSTI/TRAVERSAL/IDORの脆弱例と罠（静的エラー文言・text/plain反射・偶然の49・公開/閲覧者別ページ）を含む。
**P2.1全体は未完了**: 実LLM評価モード、AUDIT/ATTACKのベンチ、LLM使用量の取得、
複数回実行での分散の報告（実LLM時）は未実装。基準値はdetectorの現状であり、実世界の精度の主張ではない。
2026-10-22追記: 認証期限切れ(`/inbox`・bobのみログイン画面)と共通ログイン画面(`/gate`)の罠を追加。現行detectorは
期限切れを正しく無視(TN)、共通ログイン画面はIDOR候補にして誤検出(FP)。IDORのFPは5→6、基準値を更新。
2026-10-22 P2.2(IDOR一部): `_detect_idor`に、A/Bどちらかの応答がログイン画面(`type=password`)なら根拠にしない、
認証なしセッションの対照で同内容が取れる公開リソースは根拠にしない、の2つを追加。IDORは TP2→2・FP6→1・TN2→7
(recallは維持。FP除去は /public・/gate・/safe・/item・/doc-sqlerr)。認証なし対照のログイン画面は「公開」の根拠にしない
(長さ偶然一致で /order が消えた誤りを修正)。残るFPは閲覧者別ページ /order で、期待権限表(未実装)なしでは区別できない。
追加送信は候補1件につき最大1リクエスト(予算に含む)。
2026-10-22 P2.2(SSTI/XSS): SSTIは49出現後に別の算術式(`WebFuzzer._rng`でseed固定可)も評価されるか追加確認し、
確認できなければ兆候にしない(追加送信は予算に含む)。XSSはHTML以外のcontent-typeの反射を兆候にせず、兆候の文言を
「反射観測(content-type記録・ブラウザ実行は未確認)」にした。SSTI FP 1→0・XSS FP 1→0、TP/FNは不変
(fixtureの/greetは任意の`a*b`を評価するよう変更)。期待権限入力は未着手。基準値更新済み。
2026-10-22 P2.2(IDOR期待権限表・検出器側): `core/engagement.py`の`parse_idor_expectations()`と
`WebFuzzer.idor_expectations`を追加。表(path・param・任意のvalue・a/b の allow|deny)がある対象だけ、b=allow(閲覧が期待上許可)
またはa=deny(A対照が成立しない)なら違反の根拠にせず、a=allow・b=denyでBが200・類似内容・非ログイン画面を取得すれば
`basis="expectation"`の所見にする(期待表は認証なし公開判定より優先)。表に無い対象は従来どおり`basis="observed"`・要人手確認。
ベンチマーク`--with-expectations`(基準値`testlab/baselines/web_fuzz_detector_expectations.json`): IDOR TP2・FP0・TN8。
**この数字は表を正解データ由来で与えた上限であり、利用者が正しく表を書いた場合の値。実世界の精度の主張ではない。**
未実装: 表のGUI入力、同一origin認証確認URL、JSONフィールド識別、逆方向(B所有物をAで読む)。

2026-10-22 追記(DEFENSEのdetector固定モード): `python tools/benchmark.py defense`(正解データ`testlab/benchmark/ground_truth_defense.json`・
基準値`testlab/baselines/defense_signatures.json`)。`ATTACK_PATTERNS`の実コードパス(`MonitorAgent._pattern_match`)を、攻撃行と正常な罠の行
(記事slug・静的ファイル名・表示ラベル等)へ当てる。ラベルは行の意味で付け、検知器の出力に合わせていない。基準値(43判定): TP13・FP5・FN5・TN20、
precision/recallとも約0.72。**見えている限界**: URLエンコードされたSQLi/XSS/SSRFの見逃し、BRUTE_FORCEの大文字小文字(`Failed login`)の見逃し、
`zap`/`nmap`/`wp-admin`/`$(…)`/末尾`--`の部分一致による誤検知。LLM分析の品質は対象外(MonitorAgentのLLM部分は未評価)。
2026-10-22 追記(DEFENSE検知の改善 `defense-2`): URLデコード(1回・2回)後の行でも照合、BRUTE_FORCEの大文字小文字無視、SCANNERはcombined形式ならUser-Agent欄のみ、
CMS_PROBEは英数字・ハイフン非隣接、末尾`--`は直前が引用符/括弧/数字、`$(…)`は既知コマンドのみ。修正前の基準値は`defense_signatures.before-defense-2.json`に保存。
調整対象の43判定ではFP5→0・FN5→0(**過学習のため実力とは見なさない**。うち`lfi-double-encoded`にLFI_RFIのラベルを足したのは結果を見た後の整合修正)。
そこで**調整後に結果を見ずに意味でラベルを付けた未見ケース14行(15判定)を追加**した全58判定の基準値: TP25・FP0・FN4・TN29、recall約0.86。
**残る見逃し(FN)**: `UNION ALL SELECT`、パイプ+`nc`のコマンド連結、実際のsshdの`Failed password for invalid user`、IPv6ループバック`http://[::1]`のSSRF。未修正のまま基準値に残している。
検出器版は`DETECTOR_VERSIONS["DEFENSE"]="defense-2"`(台帳の再検査判定は版違いを不在の根拠にしない)。
2026-10-22 追記(`defense-3`): defense-2で残った4件を修正 — `UNION ALL SELECT`、`|`直後の`nc/ncat/netcat/bash/sh`、`Failed password for`(sshd)、IPv6ループバック(`[::1]`・`[0:0:0:0:0:0:0:1]`)のSSRF。
修正後に、結果を見る前に書いた未見の8判定(攻撃4・正常4: 大小混在UNION ALL、unionとselectを含む記事slug、`|bash`、パイプ区切りタグ、sshd root失敗、成功ログイン、IPv6完全表記、公開IPv6)を追加。
66判定でTP33・FP0・FN0・TN33(新8判定は初回で全て正解)。ただし**元の4件はこの修正のために合わせたケース**で、満点は実力の証明ではない。
sshdの`Failed password`は単発では「失敗1回」にすぎず、ブルートフォースの判断は既存の集約フィルタ(IP×種別)に依る。修正前の基準値は`defense_signatures.before-defense-3.json`。検出器版は`defense-3`。

### P2.2 IDOR・SSTI・XSS

対象: `tools/web_fuzzer.py`、`agents/fuzz_agent.py`、認証dialog/fuzz panel、P2.1のfixture。

- IDOR: テスト用A/Bアカウントと各所有物、許可/拒否の期待表、同一originの認証確認URL、識別するJSONフィールド等を入力できるようにする。
- 公開リソース、同一アカウントの二重設定、ログイン画面、認証未確認はアクセス制御違反の確定根拠にしない。本文長の類似だけでcorroboratedにしない。
- A所有物をAで読む対照と、期待上は拒否されるBでのGETを比較する。逆方向も設定したテスト用所有物のみ。ID総当たり・書き込み・認証回避は追加しない。期待権限未設定の従来2セッション比較はobserved/要確認として保持する。
- SSTI: 固定49の存在から、異なる算術式と通常/文字列対照の比較へ変更。乱数はfixtureでseed固定可能にする。追加試行も予算に含める。ファイル読取/RCEへ拡張しない。
- XSS: content-type・反射位置・エスケープを記録し「反射観測」を表す。ブラウザ実行確認を実装していない段階で「実行確認済み」と記載しない。

受け入れ条件: 正常例で確定扱いしないこと、既存の脆弱例の取りこぼしが増えていないことをP2.1で比較。差がある場合はTP/FP/FNと理由を記載し、単に検出数減少を成功としない。

## 7. P3: CLI・案件設定・継続追跡

### P3.1 CLIと案件プロファイル

対象: 新規 `cli.py`、`core/scan_runner.py`、既存 `core/config.py`・各agent・EventBus。
GUIから独立したrunnerがイベントをdrainし、P1のScanResultを受け取る。必要なagent変更は許容する。

以下は実装予定のコマンド仕様であり、現時点で実行しない。

```text
python cli.py scan fuzz --target http://127.0.0.1:8080 --profile lab --format json
python cli.py scan audit --target samples/target_code.py --format json
python cli.py diff --before SCAN_ID_1 --after SCAN_ID_2 --engagement lab
python cli.py status FINDING_ID accepted-risk --reason "対応判断を記録" --engagement lab
```

- `scan {audit,attack,fuzz,defense}`、`--target`と`--targets-file`は排他。初期版のバッチは逐次実行。defenseは`--single-pass`または有限の`--duration`を指定可能にする。
- `--format {text,json,md}`、`--out`、`--effort {speed,balanced,quality,auto}`。JSON結果はstdout、進捗はstderr。autoは既存classify_effortを呼び、永続設定のeffort enumへautoを保存しない。
- 終了コード: 0=completedかつ閾値超過なし、1=completedかつ所見閾値超過、2=failed/partial/設定不正、130=cancelled。優先度は130→2→1→0。`--fail-on {none,low,medium,high,critical}`の既定はnone。閾値判定の確認状態も設定可能にし既定observed以上、抑制分は除外して件数を別記する。
- `config.json`の`profiles`に案件ID、明示targets、allowed_targets、excluded_targets、scope_mode、scan_profile、effort、rate_limit_rps、予算、TLS設定を保持。秘密値を結果の設定snapshotへ入れない。
- 優先順位は明示CLI引数 > 案件profile > 既存設定 > defaults。設定を実行ごとにコピーし、バッチの次対象やGUIへ漏らさない。`config.json`を自動保存しない。
- 新規案件のネットワーク実行はscope_mode=block、明示的な許可対象を要求。除外は許可より優先。旧`in_scope()`の空リスト互換は既存GUI向けに残すが、新案件の検査を迂回させない。
- allow/denyはまずhost/IP/CIDR（IPリテラルのみ）の既存文法に限定。pathルールは非対応として検証エラーにし、URLのpathを黙って捨てない。origin制約と案件scopeは両方満たす必要がある。
- CIDRやcrt.sh発見結果を暗黙展開しない。対象リストで明示されたホストだけ実行する。CTF Active RetrievalはCLI初期版に公開しない。

**案件ファイル設計と実装状況(2026-10-22)**: `--engagement FILE`(JSON・秘密値を含めない。認証は従来の`--auth-file`)。
優先順位は明示CLI引数 > 案件ファイル > 既存設定。現状のキーは `engagement_id`・`idor_expectations`(`core/engagement.py`で検証)・
`exclude`(host/IP/CIDR)のみで、未知キーは拒否する。`targets`・`allow`・`scan_profile`・`effort`・予算の案件ファイル化は未実装(CLI引数で指定)。

実装順と状況:
1. 検出器がIDOR期待権限表を受け取る【済】。
2. `--engagement`でfuzz CLIへ`idor_expectations`を渡す【済】。再開用のprofile_json/profile_hashに含め、再開時はprofile_jsonから復元。
   表が空のRunはhashにキーを入れず従来Runと再開互換。
3. 除外優先・`--targets-file`【済】。`--exclude`/案件ファイルのexcludeは許可より優先(CLIで送信前に拒否し、Policy Gateにも渡す)。
   `--targets-file`は1〜50件(重複除去・1件でも不正なら全体を実行しない)を逐次実行し、対象ごとに設定コピー・別Run・別承認。
   結果は`batch:true`の集約JSON(全対象completedのときだけcompleted、中断時の残りは未実行として記録)。
   **`--targets-file`と`--auth-file`は併用不可**(認証値を他対象へ送らないため)。
4. 他モードへ展開【済(ただし`core/scan_runner.py`への共通化は未実装・現状はcli.pyに実装)】:
   `scan audit|defense --target FILE`(ローカルファイルのみ・Runジャーナル無し・`--out/--fail-on/--effort`。auditは標準エンジン、
   defenseは既定でログの1回走査、`--duration SECONDS`(1〜86400)で有限時間の監視。期限終了はcompletedで、その旨をerrorsに注記)、`scan attack --target T --allow ...`(--allow必須・scope_mode=blockをプロセス内だけで
   固定しconfig.jsonへ保存しない・除外優先・CTF能動機能とexploit生成は公開しない。偵察のみ)。
実装済み(追補): audit/defense/attackの`--targets-file`(1〜50件・逐次・重複除去・失敗は他対象の結果を消さず、全completedでなければ全体はpartial/failed)、`--format md`(stdoutにMarkdown。既定json)、`--effort auto`(classify_effortを1コール使用。config.jsonへ保存しない。auditはマスク済み先頭4000字を送る)、
`--use-profile NAME`(config.json `profiles`を既定値として展開、明示引数が優先、秘密値・未知キーは拒否)。
未実装: GUI(設定ダイアログ/fuzz panel)と旧FuzzAgent経路への期待権限表の配線、core/scan_runner.py: ATTACK/AUDIT/DEFENSE/WEB FUZZ(`run_fuzz_targets`、resumeも同じ経路)の実行層は分離済み(認証ファイル読込・案件設定・OpenAPI選択・status・台帳記録はcli.pyに残る)。

受け入れ条件: GUIをimportせず全モードのモック実行、終了コード、stdoutのJSON単独解析、設定優先順位と非永続性、除外優先、バッチ設定分離、SIGINT後の最終結果保存を検証する。

2026-10-22: P3.1の一部として、自律化Phase B4の `cli.py scan fuzz / resume / status` を実装。
この `status` はRunの状態確認であり、上記将来案の所見対応状態の変更コマンドではない。
案件プロファイル(`config.json`の`profiles`)等は未実装であり、P3.1全体は未完了のままとする(上記の実装状況を参照)。
検証は自律化実装計画およびREADMEを参照。

### P3.2 所見台帳と再検査

対象: 新規 `core/findings_ledger.py`、`cli.py`、`tools/report_generator.py`。

- `reports/engagements/<engagement_id>/events.jsonl`を追記式イベント台帳とする。scan完了イベント・所見観測・人のstatus変更・抑制を別イベントとして保持。v1はSQLite不採用。
- event_id/schema_versionを持ち、案件IDのpath traversalを拒否。単一writerとプロセス間排他で追記し、同時実行は安全に拒否可能にする。最終行の途中書き込みは警告付きで回復し、途中行の破損を黙って無視しない。
- finding_idは案件・対象・rule・正規化locationから生成。Webはmethod/path/parameter/認証の役割/テストオブジェクトの識別を保持し、異なる所有物を安易に統合しない。認証tokenはキーにしない。コードは相対pathと関数名等を用い、行の移動だけで別所見にしない。
- 人の対応statusは`open / fixed / accepted-risk`。抑制は独立した設定で、理由・期限・適用範囲を必須にする。期限切れで表示復帰し台帳から削除しない。`--include-suppressed`で確認可能にする。
- 差分は`NEW / PERSISTING / NOT_OBSERVED / REGRESSED / UNVERIFIED`。同じrule/location/権限contextが正常に再検査された場合のみNOT_OBSERVED。**不在だけで人のfixed状態を自動更新しない**。
- 認証失敗、対象除外、予算切れ、LLM失敗、検出器版の非互換、旧レポートのcoverage不明はUNVERIFIED。REGRESSEDは過去fixedまたは比較可能なNOT_OBSERVEDの後の再検出。
- 関連レポートは同じ抑制フィルターを用い、抑制件数・理由と未検査を確認可能にする。

受け入れ条件: 差分状態、認証/予算失敗による誤った修正判定の防止、抑制期限、同名別案件の分離、重複イベント、破損末尾、同時writerを非LLMで検証する。

2026-10-22 実装済み(P3.2のレポート連携): `Ledger.report_view()`を`scan_result["ledger"]`に付けるとHTML/MD/PDF/JSONが抑制所見を除外(件数・理由・期限は必ず表示)し、直前scanとの差分と所見ごとのstatusを表示する(`tools/test_ledger_reports.py`、selftest 16x2)。CLIからの指定は2026-10-22に配線(下記)。GUIは未配線。

2026-10-22 実装済み(P3.2のCLI配線): `scan`に`--engagement-id`(または案件設定のID)を指定すると、記録後に各結果へ`ledger`(report_view)を付ける。`--format md`は抑制除外・差分表示になり、`--fail-on`の判定は期限内の抑制を除いた所見で行う(JSONの`findings`は落とさない。台帳に記録できなかった場合は全所見で判定=安全側)。抑制は理由と期限が必須で、件数・理由・期限は出力に残る。試験: `tools/test_cli.py`。

2026-10-22 実装済み(P3.2の中核): `core/findings_ledger.py`、`tools/test_findings_ledger.py`(20試験・非LLM)、CLI
`scan ... --engagement-id ID`(完了結果を`reports/engagements/<id>/events.jsonl`へ追記。案件設定の`engagement_id`でも有効)、
`diff --before --after --engagement-id`、`mark FINDING_ID {open,fixed,accepted-risk} --reason`、
`suppress FINDING_ID --reason --until`、`findings [--include-suppressed]`。仕様書の`status`コマンド名は既存のRun状態確認`status`と
衝突するため`mark`にした。要点:
- finding_idは案件・対象host・rule・正規化位置・認証役割から生成(メソッド/origin/query/行番号/空白の揺れを吸収。tokenは使わない)。
  **位置はLLMが書いた表記に依存するため、表記が大きく揺れると別所見(NEW)になりうる**(NOT_OBSERVEDには検査証拠が要るので誤fixedにはならない)。
- NOT_OBSERVEDは、WEB FUZZの同じ検査単位(path+parameter)が**全カテゴリtested**、検出器版が一致(`core.settings.DETECTOR_VERSIONS`)、
  認証役割が一致しanonymous/authenticatedと確認済み、の全てを満たす場合だけ。それ以外(予算切れ・失敗・認証期限切れ/不明・旧coverage・
  IDOR集約項目・検出器版変更・LLM推論の3モード)はUNVERIFIED。REGRESSEDは過去fixed、または比較可能な再検査で未観測だった後の再検出。
- 差分は人のstatusを自動更新しない。抑制は理由・未来の期限が必須で、期限切れで表示に復帰(イベントは削除しない)。
- 追記は排他ロック(非ブロッキング)で、別writerがいればLedgerBusyで拒否。途中行の破損はLedgerCorrupt、最終行の不完全書き込みは警告し次回追記時に除去。
  event_id重複は無視して警告。台帳には応答本文・coverage理由・snippetを保存しない。
**未実装**: 関連レポート(HTML/MD/PDF/JSON)への抑制フィルター・差分表示、`--include-suppressed`のレポート側対応、
GUI、複数案件をまたぐ集計、台帳のローテーション/圧縮、実環境での長期運用確認。

## 8. P4: 検査範囲の拡張

### P4.1 OpenAPI入力

新規`tools/openapi_loader.py`でまずOpenAPI 3.0/3.1のローカルJSONを入力し、endpoint・method・parameter候補へ変換する。ローカル`$ref`は深さ/循環制限付き、外部`$ref`・非対応形式は明示エラー。serversのURLやoperation一覧は送信許可ではない。
初期版はユーザーが選択した読み取り用GETとquery parameterを既存fuzzerへ渡す。JSON body、path parameterの生成、破壊的GET、POST等は自動探索対象にしない。GETだけで非破壊を保証できるとは説明しない。
テスト: 外部servers/$refへの通信ゼロ、operation除外、循環参照、上限、HTMLリンクのない許可APIがcoverageへ現れること。

2026-10-22 実装済み(P4.1初期版): `tools/openapi_loader.py`(ローカルJSON(追補でYAMLも可: safe_load・alias拒否)のOpenAPI 3.0/3.1・2MB/500 operation/50 parameter上限・
ローカル$refは深さ16/循環検出、外部$refと不正は明示エラー)、`tools/test_openapi_loader.py`(selftest 16y)。
CLI: `openapi FILE`(operation一覧。通信しない)、`scan fuzz --openapi FILE --openapi-op ID...[--openapi-exclude ID]`。
**operationは明示選択のみ**(全自動選択なし)。選択可能なのはGET・query parameterあり・path parameterなし・requestBodyなしのもの。
送信先は`--target`のorigin固定で、OpenAPIの`servers`は使わない。選択した注入点は`WebFuzzer.seed_points`としてクロール結果へ合流し、
重複はクロール側を優先、同一origin外は取り込まず`seed_rejected`→`errors`に残して`partial`にする。HTMLリンクの無いAPIも
`WEB_FUZZ_*`のcoverageに現れる(CLI試験で確認)。再開用にseed_pointsはprofile_json/profile_hashへ含める。
**未実装/限界**: `$ref`を含む複雑なschema(allOf/oneOf)からのサンプル生成、path parameter・JSON body・POST等、`--targets-file`との併用(拒否)、
旧FuzzAgent(GUI)経路、認証が必要なAPIのsecurityScheme解釈。GETだけで非破壊とは限らないため、利用者が読み取り用と判断したものだけを選ぶこと。

### P4.2 Python複数ファイル監査

新規`tools/code_index.py`でリポジトリ内のPython AST/import/関数/呼出し関係を索引化。入口→認可→DB操作に関係する関数を優先し、ファイル名・行・省略箇所を付けてLLMへ渡す。`audit_agent.py`と`orchestrator.py`で共有する。
対象コードをimport/実行しない。`.venv`・生成物・秘密ファイルを除外し、symlinkによる対象root外への逸脱を防ぐ。ファイル数/サイズ/文脈量の上限を持ち、動的importや解決不能の呼出しは解析済みにしない。単一ファイル入力は維持する。
テスト: 複数ファイルに分割した脆弱例と正常な認可例、行移動、循環import、root外symlink、解析上限を確認。多言語化は別計画。

2026-10-22 実装済み(P4.2の初期版・標準エンジンのみ): `tools/code_index.py`(AST索引・関数/呼出し/import・循環import検出・優先付き文脈生成)、
`AuditAgent._run_project`(ディレクトリ入力時のみ。単一ファイル経路は無変更)、`cli.py scan audit --target DIR`、`tools/test_code_index.py`(selftest 16aa)。
- 対象コードはimport/実行しない(ast.parseのみ)。`.venv`等・秘密ファイル(.env/*.pem/secrets*等)は除外、**symlinkは辿らない**(root外への逸脱防止)。
  上限: 200ファイル/1ファイル200KB/合計2MB/文脈12000文字。超過・構文エラー・動的import・解決不能の呼出しはcoverage(skipped)とerrorsへ明示し、
  上限や未解析があればcompletedにせずpartialにする。文脈には「見ていないコードを安全と見なさない」注記を入れる。
- 優先順位は入口(route/get/post等のデコレータ)→認可らしい名前→DB操作→危険呼出し、入口から名前一致で辿れる関数(+1)。**呼出し解決は名前一致の近似で、
  優先付け専用**(到達可能性や脆弱性の主張には使わない)。機密名リテラルの値は送信前にマスク(行数不変)。
**未実装/限界**: GUIのディレクトリ選択(LangGraph版は追補で対応済み・モックLLM検証のみ)、ASTプリスキャン/証拠保存/CVE照合(プロジェクト監査では未対応で、証拠は「なし」)、
クラス継承・メソッド解決・動的ディスパッチ、Python以外、実LLMでの検出品質評価(ベンチマーク未作成)。

### P4.3 実ログとローテーション

`tools/log_watcher.py`でファイル識別子とsizeを追跡し、置換/縮小で位置を補正。未完の最終行は次回まで保持する。旧ファイルに残る行の扱いと取りこぼし得る条件を明記し、exactly-onceを保証したと主張しない。
JSONLを構造化し、不正行は件数/理由を表示して継続する。`monitor_agent.py`の分類入力へ接続し、未知のMITRE IDを確定タグとして出力しない。既存テキスト入力とサンプル生成を残す。journald/syslogはこの基盤の後にadapterとして追加する。
テスト: rename-create、copytruncate、部分行、ファイル一時不在、STOP、正常JSON/不正JSONを一時ディレクトリで検証する。

2026-10-22 実装済み(P4.3の中核): `tools/log_watcher.py`(inode+サイズ追跡・部分行保持・rename-create/copytruncate/一時不在・`stats`)、
JSONL平坦化`normalize_log_line()`、`core/mitre.py`、`agents/monitor_agent.py`への接続、`tools/test_log_watcher.py`(16試験・selftest 16z)。
- rename-createは新ファイルを開けてから旧ファイルの残りを読み切り、旧ファイルの不完全な最終行は1行として確定して処理する。
- copytruncate/縮小は先頭から読み直す。**縮小前に読めなかった行は取りこぼし得る**ため、`stats`の縮小・不完全行破棄が1回でもあればDEFENSEの状態をpartialにし、
  errorsに注記する(exactly-onceは保証しない。ポーリング間隔内の複数回回転、縮小後に元サイズまで書き戻された場合は検知できない)。
- JSONLは全スカラー値を`key=value`へ平坦化して既存シグネチャ検知へ渡す。不正行は件数をerrorsに出しつつ**生テキストのまま検知へ回す**(不正行に紛れた攻撃を見逃さない)。
- MITRE: LLMのIDは`core/mitre.KNOWN_TECHNIQUES`(部分集合・権威ある一覧ではない)に無ければ「未確認:Txxxx」と表示し、確定タグにしない(削除はしない)。プロンプトにも推測禁止を追記。
**未実装**: journald/syslog adapter、gzipローテーション、巨大ログのバックプレッシャー、Windowsでのinode相当の検証、実LLMでのMITRE出力確認、
`--duration`、実運用ログでの長時間検証。

## 9. 保留する作業と判断理由

- SSRF/OAST、CORS、open redirect、secret検出、takeover候補、GraphQL: P2の品質評価後に別途選定。introspection有効だけで脆弱性としない。CORSのヘッダー組合せだけでブラウザからの読取可能性を断定しない。
- Reconの共通HTTP層への移行: WEB FUZZでP0を安定化した後、現行Reconのscope/転送挙動を調査して別変更とする。P0完了だけで全モードの通信を保護したと記載しない。
- Webhook/Slack: 要約でも外部送信である。ローカル保存方針の例外を自動解釈しない。ユーザーが通知を依頼した時点で送信内容・宛先・有効化を定義する。失敗を無言で握りつぶす案は採用しない。
- チェックポイント: P3のscan/coverage確定後。再開時にscope・認証を再検査し、新しい実行として予算を管理する仕様を先に定める。
- JS/TS等の多言語化、外部プラットフォームAPI、CTF能動機能の強化、自動モデル切替、FASTへの専門推論移行: 本計画に含めない。
- 旧READMEの速度改善案（並列化、GUIバッファリング、非同期保存等）は計測後に再検討。根拠のない短縮率・コスト削減率を受け入れ条件にしない。保存完了を待たないfire-and-forgetは証拠保全と両立しない。
- 過去scan/investigationとの類似参照: 着想は別プロジェクト（Huginn、ローカルLLMエージェント）での実装から得た。埋め込みモデル・ベクトルDBを使わずキーワード＋文書頻度加重の全文検索だけで、既存資料を出典付きで参照する挙動を確認している（対象コーパスは数十ファイル規模）。ただし本リポジトリの`reports/investigation/*.md`は証拠・coverage不明の非構造データ（P1.2参照）であり、これを直接検索してLLM入力へ混ぜると、未検証の過去記述を新しい所見の根拠として扱うリスクがある。P3.2の`findings_ledger`でverification_stateを保持した構造化記録ができた後、そこを対象にした参照検索として再検討する。参照結果は`verification_state`を上書きせず、常に「未確認の参考情報」として入力に明示する。効果（精度・幻覚抑制）の測定はP2のベンチマーク基盤に依存し、本項目単独では主張しない。

## 10. 実装時の共通手順と完了条件

1. AGENTS/CLAUDEと本書の対象項目を読み、git statusと現行コードを確認。ユーザーが選んだ項目、未指定なら依存順で最初の未完了項目を一つ実装する。
2. 変更対象・保持する互換性・検証する契約を短く示して着手する。通常の実装判断で承認待ちを増やさない。本書だけを根拠に外部ターゲットの走査・通知・課金を伴う実走を開始しない。
3. EventBus経由のGUI更新、STRONG/FASTの役割、少数意見の保持、既存CTFの分離を維持する。新トグルのOFF互換と、既存仕様の境界違反の修正を区別する。
4. 必須の回帰確認は[CLAUDE.md](../CLAUDE.md)の開発ループに従う。新しい固定テストは実LLM・外部ネットワークを不要にする。既存`SELFTEST_NON_LLM_ONLY=1`にも外部通信項目があるため、オフライン完全対応と説明しない。
5. ロジック→イベント→保存→GUI/各レポートまで追跡して検証。テストPASSだけでLLM精度や実ターゲットの再現性を保証しない。未実施項目と失敗理由を記録する。
6. 完了したIDだけ本書の状態を更新し、AGENTS §4と現行操作説明を同期する。新規ファイルが実在してからAGENTSのディレクトリ構成に追加する。文書更新だけで実装を完了扱いにしない。

文書のみの変更ではリンク・差分・未実装表記の整合性を確認する。コード変更のない今回の整理のために、外部通信や課金を伴うセルフテストを走らせる必要はない。

## 11. 旧計画からの移行メモ

2026-09-02版のCLI先行案を本書で置換した。重複した別ロードマップは維持しない。

| 旧項目 | 新しい配置・変更点 |
|---|---|
| 1.1 CLI | P3.1。agent無変更の前提を撤回し、先に実行状態を構造化 |
| 1.2 所見台帳 | P3.2。案件別イベント、coverageによる差分、不在でfixedにしない |
| 1.3 profile | P3.1。除外優先・実行設定分離を追加 |
| 2.1 benchmark | P2.1。CLI非依存・固定評価をCIへ、実LLM評価は分離 |
| 2.2 検出クラス追加 | P2.2の既存品質改善を先行、新クラスは§9で保留 |
| 2.3 証拠/レート | P0.2/P1.2へ前倒し。保存前マスク、保存は既存設定でOFF |
| 3.1 実ログ | P4.3。ローテーションと部分行対応を追加 |
| 3.2 通知 / 3.3 再開 | §9で保留。外部送信の無条件許容を撤回 |

設計参考: [OWASP IDOR検査](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)、[ZAP exitStatus](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-exitstatus/)。
参照元の終了コードや機能をそのまま複製せず、本書の契約を実装する。

## 付録: 実LLM評価の記録 (P2.1)

### 2026-10-22 AUDIT (`minimax/minimax-m3.1-flash:free`、OpenRouter無料枠、effort=speed、3回)
`python tools/live_eval.py audit --model MODEL --runs N --max-calls K --timeout 900`。入力は`samples/target_code.py`から**全コメントとdocstringを除いた版**
(行番号は不変)。正解`testlab/benchmark/ground_truth_audit.json`の8件は、サンプルの設計意図から付けたもので、LLMの出力を見て付けていない。
結果(`testlab/baselines/live_audit_minimax-m3.1-flash-free_2026-10-22.json`):
- 再現率は3回で **1.0 / 1.0 / 0.375**。同じ入力でも大きくぶれる(1回の結果を実力としない)。
- 所見数17 / 8 / 15、LLM呼出しは各1回(speedは検証パスなし)、所要約465〜500秒/回(無料枠は遅い。タイムアウトを延ばさないと空応答になった: 既定180秒では268秒後に空応答)。
- 未ラベル所見は各1件: `init_db`のSQLに埋め込まれた管理者の既定資格情報。ラベルに入れていなかった実在の問題で、誤検知とは断定しない。
- 限界: 行範囲の重なりで照合するため、複数行にまたがる所見は複数の正解に当たりうる(再現率は上振れしうる)。出力に韓国語の断片が混ざる等、モデル由来の揺れがある。
  verify_pass(quality)・STRONGモデル・トークン数は未評価。無料枠の提供側が入力を学習に使う可能性があるため、送ったのはサンプルコード(秘密値なし)のみ。

### 2026-10-22 実LLMでの動作確認(同モデル・各1回の小規模確認。評価ではなく「動いた」ことの確認)
- **証拠ID引用(P1.2)**: `save_evidence`ON・2関数の小ファイルでAUDIT。モデルは2所見に実在する証拠IDを引用し(`pickle.loads`行・`os.system`行・`import pickle`行)、未知IDの除外は0件。引用の意味的な正しさは今回は目視で一致を確認しただけで、保証ではない。
- **`--effort auto`(P3.1)**: 自明なprint文は`speed`、複数の欠陥を匂わせる認証コードは`quality`に分類。各1.5秒。
- **DEFENSE(P4.3)**: 攻撃ログ8行(UNION SELECT、トラバーサル+sqlmap UA、wp-login)の1回走査。3所見、うち2件に実在のMITRE ID `T1190`、1件は`UNSPECIFIED`(IDを付けなかった)。未収録IDの「未確認」表示は今回は発火していない。
- **WEB FUZZ(P2.1)**: ラボのfixtureに対し`scan fuzz`を実行。SQLi(`/item?id`)とXSS(`/search?q`)の2件をobservedで報告し、エスケープ済み/安全ページは報告なし。約15秒。
いずれも1回のみでぶれ幅は未測定。AUDITのように3回で再現率が1.0〜0.375とぶれた例があるため、これらを品質の保証として扱わない。

### 2026-10-22 WEB FUZZ・DEFENSEの3回測定(同モデル・effort=speed・各3回。参考値)
- **WEB FUZZ**(ラボfixture・`--max-requests 120`・各20〜81秒): 3回とも `completed`・errors空・所見2件で、SQLi(CWE-89 `/item?id`)とXSS(CWE-79 `/search?q`)を報告。エスケープ済み/安全ページの所見は3回とも0件。揺れたのは重大度のみ(XSSがHIGH/MEDIUM/HIGH、SQLiがHIGH/HIGH/MEDIUM)。fixtureは小さく、罠の種類も限られる。ベンチマーク全体(`web_benchmark.py`)での実LLM評価ではない。
- **DEFENSE**(攻撃ログ8行・同一送信元・各113〜158秒): 3回とも `completed`・errors空・所見3件。単一の攻撃連鎖が3件に分割されて報告され(SQLi / LFI / wp-login偵察が混在)、所見の切り分けは回ごとに異なり、重大度もCRITICAL×3 / HIGH,HIGH,CRITICAL / CRITICAL,CRITICAL,HIGH とぶれた。MITRE IDは全所見に付いた(T1190、T1595、T1083)。**3回目に `T1595.003` が「未確認:」付きで表示**され、収録外IDを確定タグにしない経路が実LLM出力で発火した(1回目の確認では未発火だった)。モデルは送信元が文書用IP帯(TEST-NET-3)であることにも毎回言及した。
- 所見の件数・切り分け・重大度はモデルの揺れの範囲で、3回では分散の推定として足りない。この結果から品質の主張はしない。
