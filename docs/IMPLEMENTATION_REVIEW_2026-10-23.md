# 実装・計画レビュー（2026-10-23）

## 1. 結論と対象

優先すべき改善は、機能数を増やすことよりも、**未検査・不完全な観測を陰性にしないこと、証拠の欠落を下流まで伝えること、現在の進捗を一意に読めること**である。既存のGate・Journal・RunStore・送信予算・構造化結果は維持し、その境界の不整合を小さく修正する。その後に決定論方式とLLM助言を比較し、有効性を示せた範囲だけ統合するのが妥当である。

対象は HEAD `45ca42278b82d9dd5f6168f2e9bf81c72ca104a5` と、レビュー開始時に存在した未コミット変更・未追跡のlab実装を含む作業ツリー。HEADだけの評価ではない。実装は変更していない。本書は改善提案であり、ロードマップの完了判定や未承認の機能拡張を行うものではない。

重点的に確認した経路:

- `HttpTransport → WebFuzzer → AutonomousFuzzAgent → coverage → Ledger`
- `EvidenceStore → 通常レポート / labレポート`
- `lab_workflow → 対照・仮説判定 → 優先順位・連鎖候補`
- CLI・GUIと台帳の接続、CI設定、実践/自律化/labの計画・評価記録

全コード・全モードの網羅監査ではない。とくにCTF能動探索、全LLMプロンプト、認証・再開の全分岐は今回の網羅検証対象外。

## 2. 維持したい設計

- LLMの提案と実行権限を分け、登録済みcapabilityと決定論Gateで制限する構造。labでは候補IDの選択だけを許すため、任意の操作へ直接つながらない。
- Journal・RunStoreの再開契約とunknown_outcome。成功/失敗の二値で押し切らず、実行結果不明を保持する方向は適切。
- 実行状態・所見の確認状態・人の対応statusを分離し、不在だけでfixedにしない設計。
- detector固定評価、LLM解釈評価、テスト選択の評価を分けた点。モデル名だけで品質を推定せず実測する姿勢。
- labの連鎖を`hypothesized`に留め、実行・確認済みとしない点。名前空間を使う隔離と、正解をワーカーから隠す仕組みも有用。ただし今回隔離の実動作は再実行していない。

## 3. 実装上の指摘

優先度は本レビュー内の着手順位であり、脆弱性の深刻度ではない。P1は結果の信頼性・利用可否、P2は堅牢性・運用性。再現済みと静的確認・提案を区別する。

### R1 / P1 / 再現済み: カテゴリ欠落を「全カテゴリ検査済み」にできる

**根拠:** [core/findings_ledger.py](../core/findings_ledger.py) `_coverage_summary` は、存在するcoverage行の`all(oks)`だけでtested_unitsを作る。`Ledger.diff.absent_proof`はその単位が含まれていれば不在を認定する。必要なカテゴリ集合との照合はない。[agents/fuzz_capabilities.py](../agents/fuzz_capabilities.py) `_autonomy_coverage` のカテゴリは`ctx.probes`のキーに依存する。

**再現:** 同じ対象・検出器版・認証状態で、前回SQLI所見あり、今回はXSSだけtested・所見なしと記録すると、SQLIが`NOT_OBSERVED`になった。SQLIのskipped行を明記する既存試験はあるが、行そのものが欠ける場合を防げない。台帳APIの最小入力で確認したもので、実LLMがこの入力を生成する頻度は未測定。

**影響:** 「検査したが見つからない」と「その種類は検査していない」が混同され、再発判定にも波及する。人のfixed状態を自動変更する問題とは別。

**改善:** 実行計画の検査集合と、完了した検査集合を別々に記録する。単位はorigin・method・path・parameter・category・認証contextを明示し、所見ruleとの対応が不明ならUNVERIFIED。プローブ集合の指紋/版も比較可能性に含める。

**受け入れ条件:** カテゴリ欠落・空集合・別method・プローブ計画変更はUNVERIFIED。比較可能な必要検査の完遂だけがNOT_OBSERVED。過去形式は安全側に読み取る。

### R2 / P1 / 再現済み＋静的追跡: 応答の途中切断・切り詰めが下流で失われる

**根拠:** [core/http_transport.py](../core/http_transport.py) `_cap_response_body` は`RequestException`を捕捉して継続するが、例外時に`truncated=True`を設定しない。`_send_one`はその後`last_error=None`にする。

**再現:** `iter_content`が`b'partial'`を返した後に`ChunkedEncodingError`を送出する模擬応答で、保存された本文は`b'partial'`、`fz_truncated=False`だった。ネットワーク送信は行っていない。

**追加の静的所見:** `fz_truncated`はWebFuzzerや証拠保存へ伝播していない。`WebFuzzer._fuzz_point`は本文を`_EVIDENCE_BODY_CAP`で先に切り、`EvidenceStore.save_http_evidence`は渡された文字列の長さだけで切り詰めを判定する。このため、上流で失われた情報を保存層だけでは把握できない。

**改善:** 応答ごとの結果に`body_complete`・打ち切り理由・読取量を付け、検出記録・coverage・証拠まで伝える。部分本文に兆候が見えていれば観測として残せるが、兆候が無いことを陰性の根拠にしない。共有`last_error`だけで並列リクエストの成否を判断しない。

**受け入れ条件:** 途中切断・サイズ上限・読取時間超過・上流抜粋の各ケースで不完全性がJSON/MDまで残る。正常な空本文と通信失敗を区別する。実ソケットを使う低速応答時の停止時間は別途計測する。

### R3 / P1 / 静的確認: 一部のプローブ失敗でもカテゴリcompletedになる

**根拠:** [tools/web_fuzzer.py](../tools/web_fuzzer.py) `_fuzz_point` は、`attempted >= planned`の際に「全試行がエラー」の場合だけ`transport_error`、一部成功・一部失敗なら`completed`にする。自律経路はこれをcoverageのtestedへ変換する。

**影響:** 兆候なし・一部通信失敗という結果が、台帳の不在証明に利用され得る。R1でカテゴリ集合を直しても、カテゴリ内部の未完遂は残る。

**改善:** 「兆候を得たため早期終了」と「陰性を判断できるほど完遂した」を別状態にする。必須プローブの失敗はpartial/inconclusiveとし、成功数・失敗数・未実行数を保持する。SSTIの追加確認失敗も同じ契約で扱う。

**受け入れ条件:** 2件中1件失敗・兆候なし、ベースライン失敗、SSTI確認不能で陰性を認定しない。first_signalによる正当な早期終了は維持する。今回この経路の実行再現は未実施。

### R4 / P1 / 静的確認: 台帳のfcntl依存がWindowsへの入口を壊す

**根拠:** [core/findings_ledger.py](../core/findings_ledger.py) が`fcntl`を無条件importし、[cli.py](../cli.py) は起動時に同モジュールをimportする。GUIもRESULT処理で`gui.ledger_util`をimportするため、案件ID未設定でもモジュールのimport自体は発生する。`attach_ledger`内部の例外処理より前の問題である。

**改善:** [core/autonomy/journal.py](../core/autonomy/journal.py) のようにOS別ロックを扱う小さな共通部品を設ける。遅延importだけで隠すのではなく、台帳の排他契約自体をWindowsで満たす。LinuxのみとするならREADME・ランチャーの対応表を明確に変更する判断が必要。

**受け入れ条件:** WindowsでCLI `--help`、台帳未設定でのGUI RESULT、台帳の二重writer拒否・異常終了後の解放を確認する。CIにWindowsの該当試験を追加する。今回Windows実機での再現は未実施。

### R5 / P2 / 再現済み: 台帳の改行なし最終行だけ検証が弱い

**根拠:** `Ledger.read`は通常行にschema_version・engagement_idを要求する一方、改行なし末尾はdictとevent_id重複だけを確認して採用する。

**再現:** 既存台帳末尾へ、改行なしで`schema_version='999'`・別engagement_idのJSONを追加すると、そのイベントを受理した。一時ディレクトリ内だけで実施。

**改善:** 行末の有無とイベント妥当性検査を分離し、同じ検証関数を使う。構文的に完成したJSONであっても、別案件・未対応版・必須キー欠落は採用しない。Run Journalとの共通化は、両者の末尾回復契約の違いを固定してから行う。

**受け入れ条件:** 上記不正イベントを改行あり/なしの双方で拒否する。有効な改行なし最終行の回復方針を明文化し、追記後にも破損しない。

### R6 / P2 / 再現済み・仕様見直し: 所見IDが異なるoriginを同一視する

**根拠:** `finding_id`はURLの`netloc`だけを対象キーに使いschemeを捨てる。同じ案件・rule・位置・roleでは`http://example.test`と`https://example.test`が同じIDになった。現ロードマップもhost基準なので、単純な実装逸脱ではなく契約の見直しである。

**影響:** `diff`には対象文字列の一致検査があるが、status・抑制はfinding_id単位なので、HTTP側の抑制がHTTPS側へ共有され得る。認証roleもanonymous/authenticatedという粗い分類で、別アカウントの比較可能性には不足する。

**改善:** 正規化origin・明示的な非秘密の認証context IDを採用する。コード監査の同一ファイル内の複数所見が行番号除去でまとまる設計も合わせて検討する。ID変更は既存抑制の適用先を変えるため、版管理・移行手順が必要。

**受け入れ条件:** 異なるscheme/contextには抑制を継承しない。既定portの省略・明示は同一とし、コード行の単なる移動には安定性を保つ。秘密値そのものを識別子へ使わない。

### R7 / P2 / 静的確認・性能未測定: GUIスレッドで台帳全読込・fsyncを行う

**根拠:** 各panelの`dispatch(RESULT)`から`attach_ledger`が同期実行され、record_scan・report_viewがJSONLを読み直す。台帳は全件読み込み、追記でfsyncする。[core/event_bus.py](../core/event_bus.py) のキューも無制限。

**改善:** 台帳I/Oをバックグラウンドへ移し、結果をEventBusで返す。scan_idを照合して古い結果が新しいスキャン表示を上書きしないようにする。長期的には索引/スナップショット、ログ表示のまとめ処理と上限を検討する。DONE/RESULTをログと一緒に捨てない。

**受け入れ条件:** 大きな台帳・遅いストレージ・高頻度ログの条件でUI操作とSTOP応答時間を測定する。目標値は試験前に決める。今回フリーズは実測しておらず、構造から見たリスクである。

## 4. 計画の改善提案

### A. Phase Dの最小検証をC1より前へ移す

[自律化設計](AUTONOMOUS_PLATFORM_DESIGN.md) はC→Dの順だが、対照・不完全観測・確認状態の契約はPlannerの選択順によらず成立すべきである。D全体や承認UIを先行する必要はない。R1〜R3と「対照未実施では何を主張できるか」をD0として先に固定する。

[lab_workflow.py](../core/autonomy/lab_workflow.py) `hyp_status`は、probe逸脱があればcontrol未実施でもsupportedにできる。これは[lab評価 §6.7〜6.8](LOCAL_LAB_EVAL.md)で偽陽性として既知で、対照先行5a/5bは再現率低下により不採用となっている。

**見解:** 常に対照を先に実行するか、誤検知を許容するか、という二択にしない。探索順は自由に保ち、報告状態を「逸脱観測」「対照未確認」「裏付けあり」に分ける。対照が必要な仮説は、未実施のまま強い所見や連鎖の根拠へ昇格させない。評価も候補発見率と裏付け済み再現率を分け、予算不足は未確定として出す。結果を見る前に定義を固定し、旧値は別系列で残す。

### B. C0を既定に保ち、C1は条件付きの追加支出にする

保存済み評価では、LLM助言の再現率・偽陽性・遅延にトレードオフがあり、一貫した上乗せは示されていない。これは既存文書の評価結果であり、今回の再測定ではない。

- 決定論スコアが近い候補、未知の状態など、LLMを呼ぶ条件を事前定義する。
- 毎手呼ぶ方式に加え、条件付き呼出・複数候補の一括順位付けを比較する。観測変化後は古い順位を再検討する。
- 同じHTTP予算だけでなく、壁時計・LLM費用・fallback率を揃えて比較する。遅いモデルで試行数が減った結果を、選択の正確さだけの問題としない。
- 再現率だけで採用しない。正常例の誤報、未確定率、裏付け取得率、追加費用を含む受け入れ条件を事前に決める。改善しなければ任意機能のままでよい。

### C. 保留ケースと実験版を厳密に管理する

現labのholdout指紋はワークフロー変更を検知しないと文書に明記されている。結果を見た後の調整に同じケースを使うなら、開発用へ降格させる。

実験manifestにコードSHAとdirty差分の指紋・案件/採点器/プロンプト版・モデル設定・seed・予算・再試行設定を保存する。モデル名だけのファイル名では、今回のように同日に変更が多い場合の再現性が不足する。候補方式を凍結してから未使用ケースで評価し、同じケース/seedを対応付けて比較する。少数の反復を独立した多数の案件と数えない。

labは人が定義した仮説・期待値・固定操作の選択問題であり、未知の欠陥を自由に発見する能力の証明ではない。この区別はREADMEにも維持する。

### D. DNS境界は接続先まで拘束する契約にする

Phase C前の解決先IP検査という既存方針は維持する。ただし「先にDNSを検査し、requestsが再度名前解決する」だけでは、検査先と接続先の一致を保証できない。

設計単位として、許可ホスト/許可IPの意味、IPv4/IPv6、プロキシ環境変数、redirect、TLSの名前検証を定義し、検査した接続先へ実際に接続する方法を決める。ローカルfixtureで解決結果変化と範囲外canaryを試す。今回DNS付け替えや範囲外通信は再現しておらず、現在の脆弱性として断定しない。

### E. 証拠の健全性チェックはPhase F全体を待たない

通常[report_generator.py](../tools/report_generator.py)は証拠IDの形式からリンクを作り、保存物の現存/ハッシュ一致を検査しない。labレポートは`EvidenceStore.verify`を使う。既知の制限だが、既存部品を使った小さな改善として前倒しできる。

出力時点の`valid/missing/hash_mismatch/truncated/legacy_unknown`を表示する。ハッシュ一致は意味的な裏付けの正しさではない。証拠が欠けた際に所見を無言で削除せず、参照状態を下げる。Phase Fの統合推論・防御連携は後続のままでよい。

### F. 進捗の正本を一つにし、「実装済み」と「評価済み」を分ける

確認できた食い違い:

| 文書 | 古い/曖昧な記述 | 現在の根拠 |
|---|---|---|
| AGENTS §4・自律化実装計画 §4 | lab実LLM未実施、隔離未実装など | LOCAL_LAB_EVAL §6.5以降とtools/lab_isolation.pyに実装・評価記録 |
| PRACTICAL_ROADMAP §7.2 | レポート反映・GUIを未実装と記載 | report_generator.py・gui/ledger_util.py・ledger_dialog.pyに実装あり |
| LOCAL_LAB_EVAL §9 | CLIはlab_eval.pyのみ、統合未着手と読める | 同文書§6.6とcli.pyにlabコマンド実装あり。GUI/既存FUZZ連携は別途未実装 |
| LOCAL_LAB_EVAL §9導入 | 方式間の差が測れる案件がない | 同文書の後続評価には方式差が記録されている |

機能IDごとに`実装済み / 固定試験済み / 実LLM評価済み / GUI・OS確認済み / 残課題`を持つ短い現在表を用意し、過去の測定は日付つき記録へ分離する。AGENTSはそこへのリンクと当面の注意だけにする。記述の古さを根拠に再実装しない。本レビューでは既存の履歴や完了状態を書き換えていない。

## 5. 推奨する着手順序

| 順 | 作業 | 完了の判定 |
|---|---|---|
| 1 | R1〜R3: 観測完全性と不在証明の契約・実装 | 部分失敗/カテゴリ欠落が全経路で未確定になり、既存正常例が退行しない |
| 2 | R4・R5: OS互換と台帳入力検証 | Windowsの入口・排他、末尾検証が通る |
| 3 | R6・通常レポートの証拠健全性 | ID移行を含め抑制の誤共有がなく、証拠欠落を表示できる |
| 4 | D0: 対照と報告状態の分離、評価定義の凍結 | 対照未実施を裏付け済みにしない。旧/新指標を混ぜない |
| 5 | C0/C1比較と接続先境界 | 保留ケース・費用/時間を含む事前条件で判断。範囲外canary受信0 |
| 6 | R7・GUI・WEB FUZZ統合 | 長期/大量データの応答性、旧経路と新経路の表示・結果の整合 |

進捗表の整理は各段階と同時に行う。Worker並列化、資産グラフ、全モード統合はこの信頼性確認の後でよい。既存CTF機能をPlannerへ公開する権限拡張は提案しない。

## 6. 今回の検証と再現手順

実行した検証:

- `.venv/bin/python3 -m unittest tools.test_findings_ledger tools.test_evidence_provenance -q` → **27 tests / OK**。
- R1・R2・R5・R6の最小例 → 下記の問題挙動を確認。実際の台帳は変更せず、TemporaryDirectoryと模擬応答だけを使用。
- 文書内の相対ファイルリンクと今回の文書差分を検査。

既存テストが通ったことは、今回指摘した境界が正しいことを意味しない。テスト・アサーションを変更/削除/skipしていない。

リポジトリ直下での再現:

```bash
.venv/bin/python3 - <<'PY'
import json
import tempfile
import requests
from core.findings_ledger import Ledger, finding_id
from core.http_transport import HttpTransport
from tools.test_findings_ledger import scan, finding, unit_cov

with tempfile.TemporaryDirectory() as root:
    ledger = Ledger('review', root)
    ledger.record_scan(scan('before', [finding('/b id', 'SQLI')], unit_cov('/b', 'id')))
    ledger.record_scan(scan('after', [], unit_cov('/b', 'id', cats=('XSS',))))
    print('R1:', ledger.diff('before', 'after')['items'][0]['state'])
    bad = {'schema_version': '999', 'engagement_id': 'other',
           'event_id': 'bad', 'type': 'scan_recorded'}
    with open(ledger.path, 'ab') as stream:
        stream.write(json.dumps(bad).encode())
    print('R5:', ledger.read()[0][-1] == bad)

print('R6:', finding_id('e', 'http://example.test', 'SQLI', '/a q', 'anonymous') ==
      finding_id('e', 'https://example.test', 'SQLI', '/a q', 'anonymous'))

class BrokenBody:
    def iter_content(self, chunk_size):
        yield b'partial'
        raise requests.exceptions.ChunkedEncodingError('synthetic interruption')
    def close(self):
        pass

response = BrokenBody()
HttpTransport(1)._cap_response_body(response)
print('R2:', response._content, response.fz_truncated)
PY
```

今回の出力: `R1: NOT_OBSERVED`、`R5: True`、`R6: True`、`R2: b'partial' False`。

未実施: 全selftest、実LLM・有料API、外部ターゲット走査、GUI目視、Windows/macOS実機、長時間/大量データ試験、隔離と再開の全回帰、保存済みベースラインの再採点。labの正解ディレクトリは権限を変更せず、保留ケースも実行していない。保存済み評価の数値・結論は文書の記録として参照したもので、今回独立に再検証した値ではない。

## 7. 指摘対応後の再レビュー（2026-10-23）

対象: 利用者から提示されたR1〜R5対応後の作業ツリー。実装は編集していない。以下は前節の初回指摘を置き換える現在評価であり、初回の再現結果は履歴として保持する。

### 7.1 判定

- **R1:** 当初の「SQLIの後にXSSだけ再検査」の欠落は修正され、旧形式をUNVERIFIEDにする方針も適切。ただし記録しているのはその単位に列挙されたカテゴリ集合であり、所見ruleとの対応・method・payload計画の同一性ではない。「比較可能性全体が完成」とはしない。
- **R2:** プローブ応答の途中切断を明示する経路は改善。ただし下記F1/F2が残り、完了扱いにはできない。
- **R3:** 陰性側の一部失敗をpartialにする方向は適切。first_signalの維持も妥当。ただし観測ありの場合にも対照の不完全性を保存する必要がある（F2）。
- **R4:** 台帳の無条件fcntl依存は解消。今回の試験はLinux上であり、Windows対応は実装済み・実機未確認という状態を維持する。Run Journalのロックを無理に共通化する必要はない。
- **R5:** schema/案件/共通キーの検査を共有し、当初の不正末尾を採用しないことは改善。イベント種別ごとの完全なスキーマ検証とは別である。

### 7.2 次の区切りより前に修正する点

**F1 / P1: 新規エラー文字列に未マスクURLが入る（最小例で再現）**

`agents/fuzz_agent.py:_save_evidence` は「証拠の本文が不完全」へ `a['url']` を直接埋め込む。ダミーの `?token=DUMMY_REVIEW_SECRET` とknown_secretsを渡すと、証拠ファイルのURLはマスクされる一方、返されたerrorsに秘密値が残った。通常FuzzAgentはそのerrorsを再マスクせず `_finish → BaseAgent._finalize` に渡す。自律経路には最終errorsのマスクがあるため、経路を区別する。

修正: 共通の `_save_evidence` から返す時点で既知の秘密値とURLパラメータをマスクする。受け入れ試験は証拠ファイルだけでなく、通常FuzzAgentのRESULT・JSON/MDのerrorsにもダミー秘密値が出ないこと。実際の秘密値は今回使用していない。

**F2 / P1: baseline・IDOR・SSTI追加確認の不完全性が証拠へ渡らない**

`tools/web_fuzzer.py:_fuzz_point` のanomalyは主応答の不完全理由だけを持つ。baselineの途中切断や上流抜粋は含まれない。模擬baselineをread_error、主応答を正常な兆候ありにすると、`completed(first_signal)`、`response_incomplete=None`、保存証拠`truncated=False`、errors空となった。実ネットワーク不使用で再現。

IDORの両方向も不完全性フィールドを作らず、`_save_evidence`のIDOR側はsource_incompleteを渡さない（静的確認）。SSTI追加確認も部分本文で期待値が見えた場合は肯定のtupleだけを返し、その確認応答の不完全性が失われる（静的確認）。

修正: 主応答・baseline・追加確認ごとに完全性と理由を保持する。兆候は捨てず、観測を支持する証拠の制約を報告する。証拠保存OFFでも観測の不完全性が消えない設計にする。受け入れ試験は各経路について、部分本文で兆候あり/なし、baselineだけ不完全、上流の抜粋上限を含める。

### 7.3 R6の判断

読み取り専用で確認した範囲では、`reports/engagements`自体が存在せず、`reports/`配下にも`events.jsonl`は0件。別cwd・`--ledger-root`で指定した外部パス・他PCの運用台帳の有無は未確認。「運用台帳が絶対に存在しない」とは断定しない。

推奨は**新規IDをv2にし、旧イベントを上書きしない**こと。正規化origin（scheme/host/実効port）とID版を明示する。既存台帳がない場合の実装を移行ツールの完成待ちにしない。旧台帳が入力された場合は警告し、旧status/抑制を曖昧に新IDへ継承しない。

後続の移行はdry-runとバックアップを前提に、scan_recordedのtargetを使って旧ID→新originの対応を算出する。一対一と確認できる対応だけを移行対象にし、複数originへ分裂する旧IDの抑制・fixed/accepted-riskは人が適用先を選ぶ。別originへ抑制を複製する自動移行はしない。旧記録・元イベントID・移行理由を保持し、冪等にする。今回移行は実施していない。

### 7.4 D0の判断

本命の対処として賛成。ただし表示ラベルやchainのフィルターだけでは不足する。現行`LabState.corroborated`は**probeが2件逸脱すればcontrol未実施でもTrue**になる。ここを据え置いて「corroboratedだけ連鎖に使う」としても抜け道が残る。

小さく3段階に分ける:

1. **判定契約:** 生の観測状態と検証状態を分離する。`control_state=not_run/passed/failed/inconclusive/not_required`等を持ち、仮説ごとに必要な対照と裏付け条件を定義する。必要な対照未実施・失敗・不明はprobe数に関係なくcorroboratedへ上げない。対照不要は明示的な検証契約として扱う。
2. **報告・連鎖:** 未確認の逸脱は候補として残す。裏付け済みメンバーだけを正式な連鎖候補の材料にし、残りは探索候補として区別する。メンバーが裏付け済みでも連鎖そのものは引き続きhypothesized。陰性側のrefutedにも必要な対照条件を適用する。
3. **評価:** 候補発見率と裏付け済み再現率を別系列で採点し、FP・未確定率・費用も併記する。旧評価は旧版として保存する。まず既存の開発/使用済みケースで状態遷移・採点器を固定試験し、新規の未使用ケースによる最終評価はその後に行う。

新しい保留ケースの準備や実LLM課金はD0の実装開始を妨げる前提ではない。既存の保留結果は回帰の材料に使えるが、調整後の汎化性能の主張には新規未使用ケースが必要。同じfixtureのIDや数値だけを変えたものに偏らず、正常対照の紛らわしさ等の失敗パターンも変える。

### 7.5 後回しの判断と順序

- **R7:** 現ローカルに台帳がなく、フリーズも未実測なので後回しでよい。大量台帳・長時間GUI運用に入る前の受け入れ項目として残す。
- **通常レポートの証拠健全性:** D0の実装より後でよいが、Phase F全体まで延ばす必要はない。外部提出用に使う前にmissing/hash_mismatch/truncated/legacy_unknownを表示する小単位として行う。
- **推奨順:** F1/F2 → R6のID版と旧形式の扱い → D0の契約・固定試験 → 通常レポートの健全性 → 未使用ケースで比較 → R7/GUI統合。R1のmethod・プローブ指紋は、不在判定の正式運用前に実施する。

### 7.6 再検証

`.venv/bin/python3 -m unittest tools.test_findings_ledger tools.test_fuzz_execution_record tools.test_evidence_provenance -q`

結果: **51 tests / OK（9.867秒）**。加えてF1/F2の最小例をTemporaryDirectory・模擬応答で再現。全selftestの176 PASSは他エージェントの申告であり、今回は再実行していない。Windows・GUI・実LLM・実ネットワークでの途中切断・保留ケースの再評価は未実施。実装・既存テスト・運用データは変更していない。

## 8. D0・F1/F2・R6対応後のレビュー（2026-10-23）

対象コミット: `45becbf`。実装は変更せず、関連コード・保存済み開発ベースライン・固定試験を確認した。結論は、**D0の確認条件を維持し、係数調整より先に出力と証拠の契約を完成させる**。

### 8.1 改善を確認した点

F1/F2はURLのマスク、baseline・SSTI追加確認・IDORの不完全性伝播、保存OFF時の通知が実装され、関連試験が通った。R6はoriginを含むv2 IDと旧記録を残す方式になった。D0は必要な対照の未実施・失敗・判定不能をcorroboratedへ上げないようになり、候補と所見を分離している。これらを再現率回復のために緩めない。

### 8.2 次の作業前に直す小さな不整合

**G1: CLI JSONが候補詳細を落とす（再現済み）**

`cli.py:lab_command`は`result['lab']`を手組みする際、`candidates`を含めていない。開発billing案件の予算3で内部候補1件の結果を作り、その結果をCLI組立に渡すと、内部候補は1件だがCLIにはcandidatesキーが存在しなかった。hypotheses/untestedには状態が残るものの、候補の逸脱内容・証拠IDをJSON利用者が受け取れない。

対応: 候補詳細を明示的にJSONへ渡す。所見・台帳へは昇格させない。受け入れ試験はCLI出力を通して候補の理由・証拠参照が残ること、findings/台帳には混ざらないこと。report-dirの有無でも同じ候補を参照できること。

**G2: 必要な対照の証拠が無くてもevidence_complete=True（再現済み）**

`core/autonomy/lab_workflow.py:_assemble`のevidence_completeはdev(probe)の証拠だけをallで検査し、ctl(control)を検査しない。開発shop案件を固定順・予算30で実行し、最初の対照` t-orders-own `の保存だけを模擬失敗させた。対照evidence_id=None、全逸脱probeの証拠ありでも、所見は`corroborated`・`evidence_complete=True`になった。

観測時に対照を実行できた事実と、第三者が保存証拠から検証できることは別である。verification_stateを機械的に消す必要はないが、必要な対照が保存されていなければevidence_completeはFalseとし、採点の「証拠付き成功」に含めない。複数対照の一部欠落・容量上限による省略も固定試験にする。

**関連する静的所見:** labのexecuteはHttpTransportのfz_truncatedをevaluateへ渡さず、save_http_evidenceにもsource_incompleteを渡していない。WebFuzzer側のF2修正だけではlabの読取失敗を覆えない。本文依存の期待値を不完全本文でconforms/refutedと判定しない契約を追加する。ステータス/ヘッダーだけの観測と本文依存の判定は区別できる。今回このlab経路の実切断再現は未実施。

### 8.3 D0の代償を先に調整するか

**係数調整は今は行わず、レポートの証拠健全性へ進む方針を推奨する。** 開発ベースラインの決定論方式はrecall=0.636、candidate_recall=0.773。候補として発見したが裏付けが不足するものと、候補自体を発見していないものが混在する。

ただし「0.864→0.636が全部対照の通信コストによる低下」という原因の断定は避ける。旧版は対照未確認を所見に含め、新版は除外するため指標が変わっている。さらにbase_valueはunverified_deviationへの加点を追加しており、探索順も同一とは限らない。LOCAL_LAB_EVAL §6.10の「旧定義とは比較しない」と、その直後の旧新差を代償とする記述は整理する。

改善が必要かを判断する最小分析:

1. 既存の開発案件の**同じ観測履歴**を旧/新判定で採点し直し、判定定義だけによる差を分離する。必要な履歴が保存されていなければ開発案件・モックだけで取得し直す。
2. 新判定を固定して、旧/新の選択履歴を比較する。未達を「未発見」「対照未実施」「対照失敗/不明」「証拠不足」に分解する。対照の残コストと残予算も記録する。
3. 改善するなら係数の場当たり調整より、仮説の確認完了までの残コストを優先度へ考慮する案を一つだけ比較する。予算切れ直前に確認不能な候補を増やすか、既存候補を裏付けるかという選択を測る。固定予算の成績は維持し、予算を増やす感度分析は別系列にする。

開発bankの失敗はD0以前からあるため、D0の回帰と一括りにしない。過去に結果を見たholdoutは開発診断に使えても未使用評価には戻らない。新規評価ケースの実行前に判定・選択方式・指標・予算・採用基準を凍結する。

### 8.4 証拠健全性タスクの仕様案

単一のgood/bad状態にまとめず、**保存物の整合性**（ok/missing/hash_mismatch/no_hash等）と**取得内容の完全性**（complete/truncated/unknown）を別フィールドにする。EvidenceStore.verifyがTrueでもtruncatedはあり得る。ハッシュ一致を意味的な裏付けの正しさとは表示しない。

JSONとMDで同じ判定結果を共有し、HTML/PDFにも整合する表示を行う。検査時点と検査不能を明示し、欠落した所見を無言で削除しない。読取だけの検査で証拠を作成・修復しない。保存先をcwdから推測せず、出力側から指定できるようにする。

推奨順: G1/G2とlab不完全本文の扱い → 通常レポートの証拠健全性 → 開発履歴の差分分析 → 必要なら選択方式1案の比較 → 凍結 → 新規未使用ケースで評価。R7とWindows実機は未確認のまま別枠で管理する。

### 8.5 検証

以下は **76 tests / OK（11.608秒）**:

```bash
.venv/bin/python3 -m unittest tools.test_findings_ledger tools.test_fuzz_execution_record tools.test_evidence_provenance tools.test_lab.StateAndSelectionTest tools.test_lab.D0ReportingTest tools.test_lab.GraderTest -q
```

最初の実行ではレビュアーがクラス名をStateTestと誤指定し、テストロードエラー1件となった。実装の失敗ではなく、正しいStateAndSelectionTestで再実行した結果が上記。既存テストを変更・弱体化していない。

G1/G2は開発案件のloopback fixture・一時保存先・モックを使って追加確認。全selftest、実LLM、GUI、Windows、未使用ケース評価は未実施。数値比較は保存済みの開発ベースラインから確認し、評価マトリクス全体は再測定していない。レビュー文書は作業開始時から未追跡のままのため、引き継ぎ時には追加対象から漏らさないこと。

## 9. G1/G2・証拠健全性対応後のレビュー

対象: `45becbf`に対する未コミット変更。実装は変更していない。

### 改善を確認した点

CLI candidates/finding_details、必要な対照を含む証拠充足、lab本文不完全性、通常レポートの2軸表示は実装されている。GUI export_utilも4形式へevidence_rootを渡す。関連固定試験を再実行した。

### 残る指摘

1. **判定契約変更に対してlabの版が据え置き（優先）**
   `LAB_ENGINE_VERSION`は依然`lab-workflow/5`。今回body_complete/incomplete_reasonを追加して判定を変更したが、再開のprofile_hashは同じ版を使い、復元結果ではbody_complete欠落をTrueとして扱う。変更前の保存結果は不完全性を記録していないため、変更前後の再開を安全に互換と扱えない。版を上げて旧Runを拒否するか、旧結果をunknownとして扱う明示的な移行契約が必要。同版での新しいクラッシュ再開試験だけでは旧版互換を検証したことにならない。今回は旧プロセスからの再開実験は未実施（静的確認）。

2. **形式不正の証拠IDはレポートで黙って消える（再現済み）**
   `_report_data`がIDの正規表現を通らない参照をinspect_evidenceへ渡す前に除外する。`../../bad`を含む所見をJSON出力すると所見は残るがevidence=[]、performed=Trueとなり、invalid_referenceは表示されなかった。symlink参照の試験は通るが、形式不正の参照は別経路。リンクは作らず、不正参照があった事実と理由を安全な表示で残す。未保存と不正入力を区別する。

3. **GUIはRESULTの制約を表示しない（仮想GUIで確認）**
   WEB FUZZのdispatch(RESULT)へstate=partial、errorsにダミー証拠不足メッセージを渡しても、outputは変化せず注意が表示されなかった。最終結果は保持されるが、所見・保存の制約はレポートを開かなければ見落とし得る。完了/一部完了/失敗/中断と、errorsの概要をGUIへ表示し、詳細へ到達できるようにする。errorsのURL・秘密値は表示前提のマスク契約を維持する。今回確認したのはWEB FUZZパネルで、他パネルの全動作を再検証していない。

4. **GUIの同期I/Oは証拠検査にも広がっている（静的確認）**
   出力ボタンから証拠ファイル読込・ハッシュ計算・PDF生成・保存をGUIスレッドで実行する。既存R7の台帳全読込/fsyncと合わせ、遅い保存先や大量出力でイベント処理・STOP操作を止める構造。今回実負荷で停止時間は計測していない。結果スナップショットと保存先を固定してworkerへ渡し、完了/失敗だけをEventBusで戻す。出力中の重複操作を防ぎ、終了時は必ずボタンを戻す。稼働中の出力を許す場合は「途中結果」と明示する。

### GUI確認範囲・検証

- `xvfb-run -a .venv/bin/python3 -m unittest tools.test_gui_layout tools.test_gui_ledger tools.test_structured_reports -q`: **23件OK（5.182秒）**。
- `tools.test_lab.G2EvidenceCompletenessTest / LabIncompleteBodyTest / G1CliCandidatesTest`: **13件OK（7.893秒）**。テスト内のjson.load(open(...))にResourceWarningが4箇所出た。製品の失敗ではないがwith openへ整理する。
- 1000×700の仮想画面へWEB FUZZパネルを配置: PDF/HTML/MD/JSONの4ボタンはmapped、所定幅で表示。スクリーンショット目視ではなくウィジェット配置の確認。
- GUI確認の初回はレビュアーがLLMClientへ空APIキーを渡したため生成時エラー。ダミーキーへ直し、外部通信せず再確認した。
- 全selftest・実LLM・Windows/DPI・実画面・HTMLのブラウザ目視・実ソケット切断・重い出力時の応答時間は未検証。

判定: G1/G2の方向は適切。上記1/2を修正し、GUIの結果状態表示を小さく追加してから、予定どおり開発履歴の差分分析へ進める。R7は独立したGUI作業として管理し、係数調整のために今回の証拠/対照条件を緩めない。記憶への書込みは利用者が明示的に依頼した場合だけ行う。本レビューでは記憶を更新していない。
