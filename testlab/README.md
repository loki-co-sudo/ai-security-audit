# testlab — ローカル検証用の脆弱ターゲット

このツール（WEB FUZZ / ATTACK MODE / web_prober）を**安全に手元で試す**ための、
意図的に脆弱なローカル Web サーバです。

- 標準ライブラリのみで動作（追加インストール不要）
- `127.0.0.1` のみにバインド（外部公開されない）
- ⚠️ 学習・動作確認専用。実在のサービスには絶対に使わないこと。

## 起動

```bash
python testlab/vuln_server.py          # http://127.0.0.1:8000
python testlab/vuln_server.py 8081     # ポート変更
```

起動したまま、別ターミナルで本体 `python main.py` を起動します。

## ツールでの試し方

| モード | ターゲット指定 | 期待される検出 |
|---|---|---|
| WEB FUZZ | `http://127.0.0.1:8000` | SQLi / XSS / SSTI / パストラバーサル |
| ATTACK MODE | `127.0.0.1`（recon/ポートスキャン） | 8000番ポート、機微パス、ヘッダ欠如 |

## 再現している脆弱性

- **SQLインジェクション兆候** … `'` を含む入力で MySQL エラー署名を返す
- **反射型 XSS** … 入力を未エスケープでそのまま反射
- **パストラバーサル** … `../etc/passwd` で `/etc/passwd` 風の内容を返す
- **SSTI** … `{{7*7}}` を `49` と評価したように返す
- **セキュリティヘッダ欠如** … CSP / HSTS / X-Frame-Options 等を一切付けない
- **機微パス露出** … `/.env` `/.git/HEAD` `/admin` `/backup.zip` 等が 200
- **安全でない Cookie** … `Secure` / `HttpOnly` なし
- **技術スタック露出** … `Server: Apache` / `X-Powered-By: PHP` / jQuery 等

## 動作確認済み（参考）

本体の WebProber / WebFuzzer を実行すると、注入点4つに対し SQLi・XSS・
SSTI（HIGH）とパストラバーサル（CRITICAL）を検出し、ヘッダ欠如7件・
機微パス9件・安全でない Cookie も報告されます。
