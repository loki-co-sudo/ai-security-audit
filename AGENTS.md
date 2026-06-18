# AI Agent Guidelines: AI Security Audit System

## 1. プロジェクトの概要と目的

**対象ユーザー:** セキュリティ専門家・研究者・ホワイトハッカー志望のエンジニア（ポートフォリオ用途を兼ねる）

**目的:** シグネチャ（既知パターン）に依存しない、LLM推論による自律型ペネトレーションテスト＆脆弱性露出管理プラットフォームの開発。CVEデータベースに載っていない設計上の論理的欠陥・未知のゼロデイ表面を発見することが技術的な差別化ポイント。

**3つの動作モード:**
- `CODE AUDIT` — Pythonソースをセマンティック解析し、SQL Injection・IDOR・競合状態・認可ロジック欠陥などを発見
- `ATTACK MODE` — 許可されたターゲットへのポートスキャン・Web列挙・AIによる攻撃仮説生成（偵察フェーズのみ）
- `DEFENSE MODE` — アクセスログのリアルタイム監視・MITRE ATT&CK分類・即時アラート生成

**セキュリティポリシー（絶対遵守）:**
- 脆弱性の「発見」に特化。実際のエクスプロイト送信機能は実装しない
- スキャン結果はローカルにのみ保存。外部への自動送信は行わない
- ブルートフォース攻撃・DoS・C2通信・マルウェア生成機能は実装しない
- ATTACK MODEには認可チェックボックスによる倫理ゲートを必ず維持する

---

## 2. 技術スタックとアーキテクチャ

### 言語・フレームワーク・主要ライブラリ

| カテゴリ | 技術 |
|---|---|
| 言語 | Python 3.10+（3.14推奨） |
| GUI | CustomTkinter 5.2.2（ダークモード、`ctk.set_appearance_mode("dark")`） |
| LLM | OpenAI互換API（`openai` ライブラリ）— Ollama または OpenAI |
| ネットワーク | `socket`（標準ライブラリのみ、nmap不要）、`requests` |
| 並行処理 | `threading`、`concurrent.futures.ThreadPoolExecutor` |

### ディレクトリ構成と役割

```
AI-Security-tool/
├── main.py                      # エントリポイント。dirs/init確保→config.load()→App起動
├── config.json                  # 実行時LLM設定（gitignore済み。APIキーを含む可能性あり）
├── requirements.txt             # pip install -r requirements.txt
├── core/
│   ├── settings.py              # 全定数（色・フォント・LLMデフォルト値・スキャン設定）
│   ├── config.py                # config.jsonの読み書き。settings.pyをデフォルトとしてフォールバック
│   ├── event_bus.py             # スレッドセーフUIイベントバス（queue.Queue基盤）
│   └── llm_client.py            # LLMClient。update()でホットリロード可能
├── agents/
│   ├── base_agent.py            # 抽象基底クラス。threading.Eventで停止管理、EventBusヘルパー群
│   ├── audit_agent.py           # CODE AUDITエージェント（7ステップ）
│   ├── recon_agent.py           # ATTACK MODEエージェント（7ステップ）
│   └── monitor_agent.py         # DEFENSE MODEエージェント（ログ監視+バッチAI分析）
├── tools/
│   ├── network_scanner.py       # socket-basedポートスキャナ、SSL証明書取得
│   ├── web_prober.py            # HTTP探査、技術スタック指紋、センシティブパス列挙
│   └── log_watcher.py           # tailf式ログ追跡ジェネレータ、サンプルログ生成
├── gui/
│   ├── app.py                   # メインウィンドウ。DPI対応、3タブ、30msポーリング
│   ├── dialogs/
│   │   └── settings_dialog.py   # LLM設定モーダル（接続テスト・config.json保存）
│   ├── widgets/
│   │   ├── output_box.py        # カラータグ付きスクロールテキストボックス
│   │   └── progress_steps.py    # ステップ進捗＋深刻度カウンターウィジェット
│   └── panels/
│       ├── audit_panel.py       # CODE AUDITタブ（シアン系）
│       ├── attack_panel.py      # ATTACK MODEタブ（レッド系）
│       └── defense_panel.py     # DEFENSE MODEタブ（グリーン系）
└── reports/                     # スキャン結果出力先（ローカル保存のみ）
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
- タブカラー: CODE AUDIT=`CYAN(#00D4FF)`, ATTACK=`RED_C(#FF3B3B)`, DEFENSE=`GREEN(#00FF88)`
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

6. **セキュリティ機能の削除禁止**: ATTACK MODEの認可チェックボックス、エクスプロイト送信の非実装、ローカル保存のみ、という3つのポリシーに反するコードを生成しない。

7. **新しいパネルを追加する場合**: `ctk.CTkFrame` を継承し、`dispatch(event: ev.Event)` メソッドを実装する。`app.py` に新しい EventBus とタブボタンを追加する。

### 命名規則
- クラス: `PascalCase`（例: `AuditAgent`, `OutputBox`）
- メソッド・変数: `snake_case`
- プライベートメソッド: `_snake_case`（先頭アンダースコア1つ）
- 定数: `UPPER_SNAKE_CASE`（`settings.py` に集約）
- イベント種別定数: `core/event_bus.py` に定義済みの定数を使う（文字列リテラルを直書きしない）

### 禁止事項
- `threading.sleep()` をGUIスレッド（メインスレッド）で使わない（フリーズする）
- `bus.flush()` をエージェント起動前以外で呼ばない（進行中のイベントが消える）
- `config.json` をgitにコミットしない（`.gitignore` 設定済み）
- `reports/` 配下のログ・HTMLをgitにコミットしない（`.gitignore` 設定済み）

---

## 4. 現在の開発フェーズとロードマップ

### 実装済み（v2.0.0）

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
- [x] `tools/network_scanner.py` — socket-based ポートスキャナ（26ポート、SSL取得、バナーグラブ）
- [x] `tools/web_prober.py` — 19技術スタック検出・セキュリティヘッダー評価・センシティブパス列挙
- [x] `tools/log_watcher.py` — tailf式ジェネレータ・200エントリのサンプルログ生成

**GUI**
- [x] `gui/app.py` — DPI対応メインウィンドウ、3タブ、30msポーリング、⚙ 設定ボタン
- [x] `gui/dialogs/settings_dialog.py` — LLM設定モーダル（プリセット・接続テスト・config.json保存）
- [x] `gui/widgets/output_box.py` — 13種カラータグ付きテキストボックス
- [x] `gui/widgets/progress_steps.py` — ステップリスト・プログレスバー・深刻度カウンター
- [x] `gui/panels/audit_panel.py` / `attack_panel.py` / `defense_panel.py` — 各タブパネル

**その他**
- [x] `requirements.txt`
- [x] `README.md`（ポートフォリオ品質、スクリーンショット3枚付き）
- [x] `起動.bat` / `起動_silent.bat`（Explorerダブルクリック起動）
- [x] GitHub プライベートリポジトリ（`turara-coder/ai-security-audit`）

### 未実装（ロードマップ）

**次のフェーズ（優先度高）**
- [ ] HTMLレポート自動生成（`reports/` 配下への出力。応用情報・セキスペ基準準拠フォーマット）
  - スキャン結果を `reports/report_YYYYMMDD_HHMMSS.html` に保存
  - 深刻度別の脆弱性リスト・対策サマリー・エグゼクティブサマリーを含む
- [ ] CVEデータベース連携（NVD APIまたはローカルキャッシュ）
  - 検出バナーのバージョン情報と照合し、既知CVEとの相関分析を行う

**中期（優先度中）**
- [ ] LangGraphマルチエージェントオーケストレーション
  - 現在の単発エージェントをグラフで接続し、偵察→監査→防御の自動連携を実現
- [ ] 拡張ポートスキャン（UDP対応、OS検出ヒューリスティック）
- [ ] Webファジングエージェント（クローリング→入力フィールド特定→AIによるペイロード生成）

**長期**
- [ ] Docker対応（ポータブルな配布パッケージ）
- [ ] CI/CD統合（GitHub Actionsでの自動脆弱性スキャン）

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
