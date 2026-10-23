import json, os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")
def T(tid, feat, hyp, path, role="anonymous", params=None, expect=None, info=0.5, purpose="", kind="probe",
      inc=None, unlock=None, corr=False, cost=1):
    d = {"test_id": tid, "feature": feat, "hypothesis": hyp, "role": role, "method": "GET", "path": path,
         "params": params or {}, "cost": cost, "info_value": info, "purpose": purpose, "kind": kind,
         "expect": expect}
    if inc is not None: d["inconclusive_statuses"] = inc
    if unlock: d["unlocked_by"] = unlock
    if corr: d["corroborates"] = True
    return d
def H(hid, feat, rule, title, prior, sev, rem, prov=None):
    d = {"hypothesis_id": hid, "feature": feat, "rule_id": rule, "title": title, "prior_value": prior,
         "severity_hint": sev, "remediation": rem}
    if prov:
        d["provides"] = prov
    return d
def case(cid, split, title, target_ref, accounts, features, hyps, tests, budget, normal, oos=None, notes=None):
    return {"schema": "ai-security-audit-lab-case", "schema_version": "1", "case_id": cid, "split": split,
            "title": title, "target_ref": target_ref,
            "scope": {"allowed_hosts": ["127.0.0.1"], "excluded_paths": ["/logout", "/admin/reset"]},
            "side_effects_allowed": ["T1", "T2"], "accounts": accounts,
            "features": [{"feature_id": k, "title": v[0], "description": v[1]} for k, v in features.items()],
            "hypotheses": hyps, "tests": tests, "normal_behavior": normal,
            "budget": budget, "stop_conditions": {"min_score": 0.05, "stop_when_all_hypotheses_resolved": True},
            "evidence": {"save": True}, "out_of_scope": oos or [], "notes": notes or []}
ACC = {"user_a": "cred:user_a", "user_b": "cred:user_b", "user_expired": "cred:user_expired"}
BUD = lambda n: {"max_requests": n, "max_seconds": 60, "max_llm_calls": 8, "max_llm_input_chars": 8000}
D403 = [403, 404]


# ── 宣言順の機械的規則(新規ケース共通。手で並べ替えない) ─────────────────────────
# 機能は feature_id の辞書順。機能内は control → navigation → probe → corroborate(裏付け)の順、同順位は test_id 順。
_KIND = {"control": 0, "navigation": 1, "probe": 2}
def ordered(tests):
    feats = sorted({t["feature"] for t in tests})
    return sorted(tests, key=lambda t: (feats.index(t["feature"]), 3 if t.get("corroborates") else _KIND[t["kind"]], t["test_id"]))
def feats_sorted(d):
    return {k: d[k] for k in sorted(d)}

bank = case("lab-bank-01", "dev", "模擬オンラインバンク", "app:bank", ACC,
  feats_sorted({"accounts": ("口座残高", "利用者は自分の口座だけ参照できる"), "statements": ("取引明細", "利用者は自分の口座だけ参照できる"),
   "limits": ("利用限度額", "利用者は自分の口座の限度額だけ参照できる"), "receipts": ("領収書", "ログインした所有者だけが取得できる"),
   "rates": ("為替レート", "公開情報(誰でも参照できる)")}),
  [H("h-acct-authz", "accounts", "IDOR", "他人の口座残高を参照できないか", 0.9, "HIGH", "口座取得時に所有者を照合する"),
   H("h-stmt-authz", "statements", "IDOR", "他人の取引明細を参照できないか", 0.8, "HIGH", "明細取得時に所有者を照合する"),
   H("h-limits-authz", "limits", "IDOR", "他人の利用限度額を参照できないか", 0.2, "MEDIUM", "限度額取得時に所有者を照合する"),
   H("h-receipt-auth", "receipts", "BROKEN_ACCESS_CONTROL", "領収書が未ログインで取得できないか", 0.15, "MEDIUM", "領収書取得に認証と所有者検査を追加する"),
   H("h-rates-info", "rates", "INFO_DISCLOSURE", "公開レートに内部情報が含まれないか", 0.4, "LOW", "公開項目を許可リストで制限する")],
  ordered([
   T("t-acct-own", "accounts", "h-acct-authz", "/api/accounts", "user_a", {"id": "1"}, {"status": 200, "body_contains": ["balance"]}, 0.3, "自分の口座が取得できる(対照)", "control"),
   T("t-acct-cross", "accounts", "h-acct-authz", "/api/accounts", "user_a", {"id": "2"}, {"status": D403, "body_not_contains": ["balance"]}, 0.9, "他人の口座IDで拒否されるか"),
   T("t-acct-cross-b", "accounts", "h-acct-authz", "/api/accounts", "user_b", {"id": "1"}, {"status": D403, "body_not_contains": ["balance"]}, 0.6, "逆方向でも拒否されるか(裏付け)", corr=True),
   T("t-stmt-own", "statements", "h-stmt-authz", "/api/statements", "user_a", {"acct": "1"}, {"status": 200, "body_contains": ["statement"]}, 0.3, "自分の明細が取得できる(対照)", "control"),
   T("t-stmt-cross", "statements", "h-stmt-authz", "/api/statements", "user_a", {"acct": "2"}, {"status": D403, "body_not_contains": ["statement"]}, 0.8, "他人の口座の明細が拒否されるか"),
   T("t-stmt-cross-b", "statements", "h-stmt-authz", "/api/statements", "user_b", {"acct": "1"}, {"status": D403, "body_not_contains": ["statement"]}, 0.6, "逆方向でも拒否されるか(裏付け)", corr=True),
   T("t-limits-own", "limits", "h-limits-authz", "/api/limits", "user_a", {"acct": "1"}, {"status": 200, "body_contains": ["daily_limit"]}, 0.3, "自分の限度額が取得できる(対照)", "control"),
   T("t-limits-cross", "limits", "h-limits-authz", "/api/limits", "user_a", {"acct": "2"}, {"status": D403, "body_not_contains": ["daily_limit"]}, 0.6, "他人の口座の限度額が拒否されるか"),
   T("t-limits-cross-b", "limits", "h-limits-authz", "/api/limits", "user_b", {"acct": "1"}, {"status": D403, "body_not_contains": ["daily_limit"]}, 0.5, "逆方向でも拒否されるか(裏付け)", corr=True),
   T("t-receipt-user", "receipts", "h-receipt-auth", "/receipts/1001", "user_a", expect={"status": 200, "body_contains": ["receipt"]}, info=0.2, purpose="ログイン利用者が領収書を取得できる(対照)", kind="control"),
   T("t-receipt-anon", "receipts", "h-receipt-auth", "/receipts/1001", expect={"status": [401, 403]}, info=0.6, purpose="未ログインで拒否されるか", inc=[]),
   T("t-receipt-anon-2", "receipts", "h-receipt-auth", "/receipts/1002", expect={"status": [401, 403]}, info=0.5, purpose="別の領収書でも拒否されるか(裏付け)", corr=True, inc=[]),
   T("t-rates", "rates", "h-rates-info", "/api/rates", expect={"status": 200, "body_not_contains": ["internal", "key"]}, info=0.4, purpose="公開レートの内容")]),
  BUD(6), ["口座・明細・限度額は所有者だけが参照できる", "領収書はログインした所有者だけ", "為替レートは公開"],
  oos=[{"feature": "accounts", "title": "送金の認可・CSRF", "reason": "状態を変更する操作(T3)で、固定テスト操作に含めない"}])

wiki = case("lab-wiki-01", "dev", "模擬社内Wiki", "app:wiki", ACC,
  feats_sorted({"history": ("編集履歴", "編集者の個人情報を公開しない"), "meta": ("robots.txt", "秘密のパスを列挙しない"),
   "pages": ("ページ", "内部ページは認証が必要"), "search": ("検索", "入力値は無害化して表示する"),
   "spaces": ("スペース出力", "スペースのメンバーだけがエクスポートできる(トップ→スペース一覧→エクスポートの順に辿る)")}),
  [H("h-history-leak", "history", "INFO_DISCLOSURE", "編集履歴が編集者のメールを公開しないか", 0.5, "MEDIUM", "公開履歴から連絡先を除く"),
   H("h-robots", "meta", "INFO_DISCLOSURE", "robots.txtが秘密のパスを列挙しないか", 0.2, "LOW", "機密パスをrobots.txtに書かない"),
   H("h-private-authz", "pages", "BROKEN_ACCESS_CONTROL", "内部ページが未ログインで見えないか", 0.6, "HIGH", "内部ページに認証を要求する"),
   H("h-search-xss", "search", "XSS", "検索語が無害化されて表示されるか", 0.4, "MEDIUM", "出力時にHTMLエスケープする"),
   H("h-space-export", "spaces", "BROKEN_ACCESS_CONTROL", "スペースのエクスポートを非メンバーが使えないか", 0.7, "HIGH", "エクスポートにメンバー検査を追加する")],
  ordered([
   T("t-hist-anon", "history", "h-history-leak", "/pages/1/history", expect={"status": 200, "body_not_contains": ["@"]}, info=0.8, purpose="公開履歴にメールが含まれないか"),
   T("t-robots", "meta", "h-robots", "/robots.txt", expect={"status": 200, "body_not_contains": ["secret", "internal", "admin"]}, info=0.3, purpose="robots.txtの内容"),
   T("t-page-public", "pages", "h-private-authz", "/pages", params={"id": "1"}, expect={"status": 200, "body_contains": ["Welcome"]}, info=0.2, purpose="公開ページが取得できる(対照)", kind="control"),
   T("t-page-internal", "pages", "h-private-authz", "/pages/internal", expect={"status": [401, 403]}, info=0.6, purpose="内部ページが未ログインで拒否されるか", inc=[]),
   T("t-search-plain", "search", "h-search-xss", "/search", params={"q": "hello"}, expect={"status": 200, "body_contains": ["hello"]}, info=0.2, purpose="通常の検索語が表示される(対照)", kind="control"),
   T("t-search-reflect", "search", "h-search-xss", "/search", params={"q": "<script>1</script>"}, expect={"status": 200, "body_not_contains": ["<script>1</script>"]}, info=0.6, purpose="スクリプト断片がそのまま反射されないか"),
   T("t-space-anon", "spaces", "h-space-export", "/spaces/team/export", expect={"status": [401, 403]}, info=0.2, purpose="未ログインで拒否されるか(対照)", kind="control", inc=[]),
   T("t-home", "spaces", "h-space-export", "/", expect={"status": 200}, info=0.3, purpose="トップのリンク構成を観測する", kind="navigation"),
   T("t-spaces", "spaces", "h-space-export", "/spaces", "user_a", expect={"status": 200}, info=0.3, purpose="ログイン後のスペース一覧のリンク構成を観測する", kind="navigation", unlock={"test_id": "t-home", "body_contains": "/spaces"}),
   T("t-space-export", "spaces", "h-space-export", "/spaces/team/export", "user_a", expect={"status": D403}, info=0.9, purpose="非メンバーがエクスポートできないか", unlock={"test_id": "t-spaces", "body_contains": "/spaces/team/export"})]),
  BUD(6), ["内部ページは認証が必要", "robots.txtにはスペース一覧の入口が載る(仕様どおり)"])

billing = case("lab-billing-01", "dev", "模擬請求システム", "app:billing", ACC,
  feats_sorted({"invoices": ("請求書", "利用者は自分の請求書だけ参照できる"), "legacy": ("旧管理画面", "撤去済みで404を返す"),
   "reports": ("売上サマリー", "管理者だけが参照できる"), "session": ("セッション", "有効なセッションで自分の情報を返す")}),
  [H("h-invoice-authz", "invoices", "IDOR", "他人の請求書を参照できないか", 0.7, "HIGH", "請求書取得時に所有者を照合する"),
   H("h-legacy-admin", "legacy", "BROKEN_ACCESS_CONTROL", "撤去済みの旧管理画面が残っていないか", 0.5, "HIGH", "旧管理画面のルートを削除する"),
   H("h-report-authz", "reports", "BROKEN_ACCESS_CONTROL", "売上サマリーを一般利用者が参照できないか", 0.6, "HIGH", "管理者権限の検査を追加する"),
   H("h-session-expiry", "session", "SESSION", "期限切れのセッションで情報が返らないか", 0.3, "MEDIUM", "期限切れトークンを拒否する")],
  ordered([
   T("t-inv-own", "invoices", "h-invoice-authz", "/api/invoices/9001", "user_a", expect={"status": 200, "body_contains": ["invoice"]}, info=0.3, purpose="自分の請求書が取得できる(対照)", kind="control"),
   T("t-inv-cross", "invoices", "h-invoice-authz", "/api/invoices/9002", "user_a", expect={"status": D403, "body_not_contains": ["total"]}, info=0.9, purpose="他人の請求書が拒否されるか"),
   T("t-inv-cross-b", "invoices", "h-invoice-authz", "/api/invoices/9001", "user_b", expect={"status": D403, "body_not_contains": ["total"]}, info=0.5, purpose="逆方向でも拒否されるか(裏付け)", corr=True),
   T("t-legacy-ctl", "legacy", "h-legacy-admin", "/zz-nonexistent", expect={"status": 404}, info=0.3, purpose="存在しないパスが404を返す(環境の判別力の対照)", kind="control", inc=[]),
   T("t-legacy-probe", "legacy", "h-legacy-admin", "/admin-legacy/", expect={"status": 404}, info=0.7, purpose="旧管理画面のパスが404を返すか", inc=[]),
   T("t-report-user", "reports", "h-report-authz", "/api/reports/summary", "user_a", expect={"status": D403, "body_not_contains": ["revenue"]}, info=0.8, purpose="一般利用者が拒否されるか"),
   T("t-me-a", "session", "h-session-expiry", "/api/me", "user_a", expect={"status": 200, "body_contains": ["user_a"]}, info=0.3, purpose="有効なセッションで自分の情報が返る"),
   T("t-me-expired", "session", "h-session-expiry", "/api/me", "user_expired", expect={"status": 401}, info=0.4, purpose="期限切れセッションが拒否されるか", inc=[])]),
  BUD(6), ["請求書は所有者だけ", "売上サマリーは管理者のみ", "旧管理画面は撤去済み(404)"])

forum = case("lab-forum-01", "dev", "模擬フォーラム", "app:forum", ACC,
  feats_sorted({"avatars": ("アバター画像", "技術情報ヘッダーを出さない"), "moderation": ("モデレーション画面", "モデレーターだけが利用できる"),
   "profile": ("公開プロフィール", "メールアドレスを公開しない"), "search": ("検索", "入力値は無害化して表示する"),
   "threads": ("スレッド", "下書きは作成者だけが参照できる")}),
  [H("h-avatar-headers", "avatars", "INFO_DISCLOSURE", "画像応答が技術情報ヘッダーを出さないか", 0.1, "LOW", "不要なヘッダーを削除する"),
   H("h-mod-authz", "moderation", "BROKEN_ACCESS_CONTROL", "モデレーション画面を一般利用者が使えないか", 0.8, "HIGH", "モデレーター権限の検査を追加する"),
   H("h-profile-exposure", "profile", "EXCESSIVE_DATA_EXPOSURE", "公開プロフィールがメールを返さないか", 0.2, "LOW", "公開項目を許可リストで制限する"),
   H("h-search-xss", "search", "XSS", "検索語が無害化されて表示されるか", 0.3, "MEDIUM", "出力時にHTMLエスケープする"),
   H("h-thread-draft", "threads", "IDOR", "他人の下書きスレッドを参照できないか", 0.8, "HIGH", "下書きは作成者だけに返す")],
  ordered([
   T("t-avatar", "avatars", "h-avatar-headers", "/avatars/1.png", expect={"status": 200, "header_absent": ["X-Powered-By"]}, info=0.2, purpose="画像応答のヘッダー"),
   T("t-mod-anon", "moderation", "h-mod-authz", "/mod/queue", expect={"status": [401, 403]}, info=0.3, purpose="未ログインで拒否されるか(対照)", kind="control", inc=[]),
   T("t-mod-user", "moderation", "h-mod-authz", "/mod/queue", "user_a", expect={"status": D403, "body_not_contains": ["queue"]}, info=0.9, purpose="一般利用者が拒否されるか"),
   T("t-mod-user-b", "moderation", "h-mod-authz", "/mod/queue", "user_b", expect={"status": D403, "body_not_contains": ["queue"]}, info=0.5, purpose="別の利用者でも拒否されるか(裏付け)", corr=True),
   T("t-profile", "profile", "h-profile-exposure", "/u/alice", expect={"status": 200, "body_not_contains": ["email"]}, info=0.3, purpose="公開プロフィールの内容"),
   T("t-search-reflect", "search", "h-search-xss", "/search", params={"q": "<script>1</script>"}, expect={"status": 200, "body_not_contains": ["<script>1</script>"]}, info=0.5, purpose="スクリプト断片がそのまま反射されないか"),
   T("t-thread-public", "threads", "h-thread-draft", "/threads", params={"id": "1"}, expect={"status": 200, "body_contains": ["title"]}, info=0.2, purpose="公開スレッドが取得できる(対照)", kind="control"),
   T("t-thread-draft", "threads", "h-thread-draft", "/threads", "user_a", {"id": "3"}, {"status": D403, "body_not_contains": ["draft"]}, 0.9, "他人の下書きが拒否されるか"),
   T("t-thread-draft-anon", "threads", "h-thread-draft", "/threads", params={"id": "3"}, expect={"status": [401, 403]}, info=0.4, purpose="未ログインで下書きが拒否されるか", inc=[])]),
  BUD(6), ["下書きは作成者だけ", "モデレーション画面はモデレーターのみ", "公開プロフィールにメールは載らない"])

NEW = {"lab-bank-01": bank, "lab-wiki-01": wiki, "lab-billing-01": billing, "lab-forum-01": forum}

hold2 = case("lab-holdout-02", "holdout", "模擬在庫管理(保留)", "app:inventory", ACC,
  feats_sorted({"costs": ("原価情報", "原価は管理者だけが参照できる"), "health": ("稼働確認", "内部情報を返さない"),
   "labels": ("ラベル印刷", "公開してよい項目だけ"), "stock": ("倉庫別在庫", "利用者は自分の倉庫だけ参照できる"),
   "suppliers": ("仕入先エクスポート", "購買担当だけが出力できる(トップ→仕入先一覧→エクスポートの順に辿る)")}),
  [H("h-cost-exposure", "costs", "EXCESSIVE_DATA_EXPOSURE", "商品情報が原価を返さないか", 0.3, "MEDIUM", "応答項目を許可リストで制限する"),
   H("h-health-info", "health", "INFO_DISCLOSURE", "稼働確認が内部情報を返さないか", 0.2, "LOW", "稼働確認の応答を最小化する"),
   H("h-label-info", "labels", "INFO_DISCLOSURE", "ラベルに仕入先情報が含まれないか", 0.2, "LOW", "ラベルの項目を限定する"),
   H("h-stock-authz", "stock", "IDOR", "他人の倉庫の在庫を参照できないか", 0.6, "HIGH", "倉庫取得時に所属を照合する"),
   H("h-supplier-export", "suppliers", "BROKEN_ACCESS_CONTROL", "仕入先エクスポートを一般利用者が使えないか", 0.7, "HIGH", "購買権限の検査を追加する")],
  ordered([
   T("t-item-ctl", "costs", "h-cost-exposure", "/items", "user_a", {"id": "2"}, {"status": 200, "body_contains": ["name"]}, 0.2, "商品情報が取得できる(対照)", "control"),
   T("t-item-cost", "costs", "h-cost-exposure", "/items", "user_a", {"id": "1"}, {"status": 200, "body_not_contains": ["cost"]}, 0.7, "原価が含まれないか"),
   T("t-health", "health", "h-health-info", "/health", expect={"status": 200, "body_not_contains": ["version", "internal"]}, info=0.3, purpose="稼働確認の内容"),
   T("t-label", "labels", "h-label-info", "/labels/print", params={"id": "1"}, expect={"status": 200, "body_not_contains": ["supplier"]}, info=0.3, purpose="ラベルの内容"),
   T("t-stock-own", "stock", "h-stock-authz", "/stock", "user_a", {"warehouse": "1"}, {"status": 200, "body_contains": ["units"]}, 0.3, "自分の倉庫の在庫が取得できる(対照)", "control"),
   T("t-stock-cross", "stock", "h-stock-authz", "/stock", "user_a", {"warehouse": "2"}, {"status": D403, "body_not_contains": ["units"]}, 0.9, "他人の倉庫の在庫が拒否されるか"),
   T("t-stock-cross-b", "stock", "h-stock-authz", "/stock", "user_b", {"warehouse": "1"}, {"status": D403, "body_not_contains": ["units"]}, 0.5, "逆方向でも拒否されるか(裏付け)", corr=True),
   T("t-home", "suppliers", "h-supplier-export", "/", expect={"status": 200}, info=0.3, purpose="トップのリンク構成を観測する", kind="navigation"),
   T("t-suppliers", "suppliers", "h-supplier-export", "/suppliers", "user_a", expect={"status": 200}, info=0.3, purpose="仕入先一覧のリンク構成を観測する", kind="navigation", unlock={"test_id": "t-home", "body_contains": "/suppliers"}),
   T("t-supplier-export", "suppliers", "h-supplier-export", "/suppliers/export", "user_a", expect={"status": D403}, info=0.9, purpose="一般利用者がエクスポートできないか", unlock={"test_id": "t-suppliers", "body_contains": "/suppliers/export"})]),
  BUD(5), ["倉庫の在庫は所属者だけ", "仕入先エクスポートは購買担当のみ"])

hold3 = case("lab-holdout-03", "holdout", "模擬サポート窓口(保留)", "app:support", ACC,
  feats_sorted({"export": ("チケットCSV", "自分のチケットだけ出力できる"), "kb": ("ナレッジベース", "旧FAQは撤去済みで404を返す"),
   "notes": ("担当者メモ", "担当者だけが参照できる"), "profile": ("自分の情報", "有効なセッションで自分の情報を返す"),
   "stats": ("統計", "管理者だけが参照できる")}),
  [H("h-export-scope", "export", "BROKEN_ACCESS_CONTROL", "CSV出力が他人のチケットを含まないか", 0.4, "HIGH", "出力範囲を本人のチケットに限る"),
   H("h-kb-legacy", "kb", "BROKEN_ACCESS_CONTROL", "撤去済みの旧FAQが残っていないか", 0.5, "MEDIUM", "旧FAQのルートを削除する"),
   H("h-notes-authz", "notes", "IDOR", "担当者メモを依頼者が参照できないか", 0.7, "HIGH", "メモ取得に担当者権限の検査を追加する"),
   H("h-profile-session", "profile", "SESSION", "期限切れセッションで情報が返らないか", 0.3, "MEDIUM", "期限切れトークンを拒否する"),
   H("h-stats-authz", "stats", "BROKEN_ACCESS_CONTROL", "統計を一般利用者が参照できないか", 0.5, "MEDIUM", "管理者権限の検査を追加する")],
  ordered([
   T("t-export-own", "export", "h-export-scope", "/tickets/export.csv", "user_a", {"scope": "mine"}, {"status": 200, "body_contains": ["id"]}, 0.2, "自分のチケットが出力できる(対照)", "control"),
   T("t-export-all", "export", "h-export-scope", "/tickets/export.csv", "user_a", {"scope": "all"}, {"status": D403, "body_not_contains": ["user_b"]}, 0.8, "全件出力が拒否されるか"),
   T("t-kb-ctl", "kb", "h-kb-legacy", "/kb/zz-none", expect={"status": 404}, info=0.3, purpose="存在しないパスが404を返す(環境の判別力の対照)", kind="control", inc=[]),
   T("t-kb-legacy", "kb", "h-kb-legacy", "/kb/old-faq", expect={"status": 404}, info=0.7, purpose="旧FAQが404を返すか", inc=[]),
   T("t-notes-a", "notes", "h-notes-authz", "/tickets/5/notes", "user_a", expect={"status": D403, "body_not_contains": ["internal"]}, info=0.9, purpose="依頼者がメモを参照できないか"),
   T("t-notes-b", "notes", "h-notes-authz", "/tickets/5/notes", "user_b", expect={"status": D403, "body_not_contains": ["internal"]}, info=0.5, purpose="別の利用者でも拒否されるか(裏付け)", corr=True),
   T("t-me-a", "profile", "h-profile-session", "/api/me", "user_a", expect={"status": 200, "body_contains": ["user_a"]}, info=0.3, purpose="有効なセッションで自分の情報が返る"),
   T("t-me-expired", "profile", "h-profile-session", "/api/me", "user_expired", expect={"status": 401}, info=0.4, purpose="期限切れセッションが拒否されるか", inc=[]),
   T("t-stats", "stats", "h-stats-authz", "/api/stats", "user_a", expect={"status": D403, "body_not_contains": ["open_tickets"]}, info=0.8, purpose="一般利用者が拒否されるか")]),
  BUD(5), ["担当者メモは担当者のみ", "統計は管理者のみ", "旧FAQは撤去済み(404)"])

hold4 = case("lab-holdout-04", "holdout", "模擬給与システム(保留)", "app:payroll", ACC,
  feats_sorted({"directory": ("社員名簿", "人事担当だけが出力できる(トップ→人事→レポート→名簿の順に辿る)"), "help": ("ヘルプ", "公開"),
   "payslips": ("給与明細", "利用者は自分の明細だけ参照できる"), "summary": ("年間サマリー", "利用者は自分の集計だけ参照できる"),
   "tax": ("源泉徴収票", "利用者は自分の票だけ参照できる")}),
  [H("h-directory-authz", "directory", "BROKEN_ACCESS_CONTROL", "社員名簿を一般利用者が出力できないか", 0.3, "HIGH", "人事権限の検査を追加する"),
   H("h-help-info", "help", "INFO_DISCLOSURE", "ヘルプに内部情報が含まれないか", 0.2, "LOW", "公開項目に限定する"),
   H("h-payslip-authz", "payslips", "IDOR", "他人の給与明細を参照できないか", 0.9, "HIGH", "明細取得時に所有者を照合する"),
   H("h-summary-scope", "summary", "IDOR", "年間サマリーが全社分を返さないか", 0.2, "MEDIUM", "本人分の集計だけ返す"),
   H("h-tax-authz", "tax", "IDOR", "他人の源泉徴収票を参照できないか", 0.6, "HIGH", "票取得時に所有者を照合する")],
  ordered([
   T("t-home", "directory", "h-directory-authz", "/", expect={"status": 200}, info=0.3, purpose="トップのリンク構成を観測する", kind="navigation"),
   T("t-hr", "directory", "h-directory-authz", "/hr", "user_a", expect={"status": 200}, info=0.3, purpose="人事ページのリンク構成を観測する", kind="navigation", unlock={"test_id": "t-home", "body_contains": "/hr"}),
   T("t-hr-reports", "directory", "h-directory-authz", "/hr/reports", "user_a", expect={"status": 200}, info=0.3, purpose="レポート一覧のリンク構成を観測する", kind="navigation", unlock={"test_id": "t-hr", "body_contains": "/hr/reports"}),
   T("t-directory", "directory", "h-directory-authz", "/hr/reports/directory.csv", "user_a", expect={"status": D403}, info=0.9, purpose="一般利用者が名簿を出力できないか", unlock={"test_id": "t-hr-reports", "body_contains": "directory.csv"}),
   T("t-help", "help", "h-help-info", "/help", expect={"status": 200, "body_not_contains": ["internal", "password"]}, info=0.3, purpose="ヘルプの内容"),
   T("t-slip-own", "payslips", "h-payslip-authz", "/api/payslips", "user_a", {"id": "1"}, {"status": 200, "body_contains": ["net_pay"]}, 0.3, "自分の明細が取得できる(対照)", "control"),
   T("t-slip-cross", "payslips", "h-payslip-authz", "/api/payslips", "user_a", {"id": "2"}, {"status": D403, "body_not_contains": ["net_pay"]}, 0.9, "他人の明細が拒否されるか"),
   T("t-slip-cross-b", "payslips", "h-payslip-authz", "/api/payslips", "user_b", {"id": "1"}, {"status": D403, "body_not_contains": ["net_pay"]}, 0.6, "逆方向でも拒否されるか(裏付け)", corr=True),
   T("t-summary", "summary", "h-summary-scope", "/api/payslips/summary", "user_a", {"year": "2025"}, {"status": 200, "body_not_contains": ["company_total"]}, 0.7, "全社分の集計が含まれないか"),
   T("t-tax-own", "tax", "h-tax-authz", "/api/tax", "user_a", {"id": "1"}, {"status": 200, "body_contains": ["withheld"]}, 0.3, "自分の票が取得できる(対照)", "control"),
   T("t-tax-cross", "tax", "h-tax-authz", "/api/tax", "user_a", {"id": "2"}, {"status": D403, "body_not_contains": ["withheld"]}, 0.8, "他人の票が拒否されるか")]),
  BUD(6), ["給与明細・源泉徴収票は所有者だけ", "社員名簿は人事のみ"])

NEW_HOLDOUT = {"lab-holdout-02": hold2, "lab-holdout-03": hold3, "lab-holdout-04": hold4}

chain1 = case("lab-chain-01", "dev", "模擬ブログ(連鎖あり)", "app:chainblog", ACC,
  feats_sorted({"cookies": ("Cookie", "セッションCookieはスクリプトから読めない"), "posts": ("非公開投稿", "所有者だけが参照できる"),
   "preview": ("プレビュー", "入力値は無害化して表示する"), "search": ("検索", "入力値は無害化して表示する"),
   "users": ("利用者一覧", "利用者の識別子を公開しない")}),
  [H("h-cookie-api", "cookies", "COOKIE_FLAGS", "API用CookieにHttpOnly/Secureが付くか", 0.3, "MEDIUM", "Set-CookieにHttpOnly/Secureを付ける", ["cookie_script_readable"]),
   H("h-cookie-sid", "cookies", "COOKIE_FLAGS", "セッションCookieにHttpOnlyが付くか", 0.4, "MEDIUM", "Set-CookieにHttpOnlyを付ける", ["cookie_script_readable"]),
   H("h-posts-idor", "posts", "IDOR", "他人の非公開投稿を参照できないか", 0.7, "HIGH", "投稿取得時に所有者を照合する", ["read_other_user_object"]),
   H("h-preview-xss", "preview", "XSS", "プレビューが入力を無害化して表示するか", 0.4, "MEDIUM", "出力時にHTMLエスケープする", ["xss_reflected"]),
   H("h-search-xss", "search", "XSS", "検索語が無害化されて表示されるか", 0.5, "MEDIUM", "出力時にHTMLエスケープする", ["xss_reflected"]),
   H("h-user-list", "users", "INFO_DISCLOSURE", "利用者一覧が識別子を公開しないか", 0.3, "LOW", "一覧を非公開にする", ["exposes_user_identifier"])],
  ordered([
   T("t-api-cookie", "cookies", "h-cookie-api", "/api/login", expect={"status": 200, "header_contains": {"Set-Cookie": "HttpOnly"}}, info=0.5, purpose="API用Set-CookieのHttpOnly属性"),
   T("t-sid-cookie", "cookies", "h-cookie-sid", "/login", expect={"status": 200, "header_contains": {"Set-Cookie": "HttpOnly"}}, info=0.6, purpose="セッションCookieのHttpOnly属性"),
   T("t-post-own", "posts", "h-posts-idor", "/posts", "user_a", {"uid": "user_a"}, {"status": 200, "body_contains": ["private"]}, 0.2, "自分の投稿が取得できる(対照)", "control"),
   T("t-post-cross", "posts", "h-posts-idor", "/posts", "user_a", {"uid": "user_b"}, {"status": D403, "body_not_contains": ["private"]}, 0.9, "他人の投稿が拒否されるか"),
   T("t-preview", "preview", "h-preview-xss", "/preview", params={"text": "<script>1</script>"}, expect={"status": 200, "body_not_contains": ["<script>1</script>"]}, info=0.6, purpose="スクリプト断片がそのまま反射されないか"),
   T("t-search-plain", "search", "h-search-xss", "/search", params={"q": "hello"}, expect={"status": 200, "body_contains": ["hello"]}, info=0.2, purpose="通常の検索語が表示される(対照)", kind="control"),
   T("t-search-reflect", "search", "h-search-xss", "/search", params={"q": "<script>1</script>"}, expect={"status": 200, "body_not_contains": ["<script>1</script>"]}, info=0.6, purpose="スクリプト断片がそのまま反射されないか"),
   T("t-users", "users", "h-user-list", "/users", expect={"status": [401, 403]}, info=0.5, purpose="利用者一覧が未ログインで拒否されるか", inc=[])]),
  BUD(6), ["非公開投稿は所有者だけ", "検索・プレビューは入力を無害化して表示する"])

chain2 = case("lab-chain-02", "dev", "模擬ドキュメントサイト(連鎖と非連鎖)", "app:chaindocs", ACC,
  feats_sorted({"admin": ("管理エクスポート", "管理者だけが利用できる"), "cookies": ("Cookie", "セッションCookieはスクリプトから読めない"),
   "oldexport": ("旧エクスポート", "撤去済みで利用できない"), "query": ("検索", "入力値は無害化して表示する"),
   "robots": ("robots.txt", "内部パスを列挙しない"), "sitemap": ("sitemap.xml", "公開ページだけ列挙する")}),
  [H("h-admin-authz", "admin", "BROKEN_ACCESS_CONTROL", "管理エクスポートを未ログインで使えないか", 0.6, "HIGH", "管理者権限の検査を維持する", ["missing_function_authz"]),
   H("h-cookie-ok", "cookies", "COOKIE_FLAGS", "セッションCookieにHttpOnlyが付くか", 0.3, "MEDIUM", "現状の設定を維持する", ["cookie_script_readable"]),
   H("h-oldexport-authz", "oldexport", "BROKEN_ACCESS_CONTROL", "撤去済みの旧エクスポートが認可なしで使えないか", 0.5, "HIGH", "旧エクスポートのルートを削除する", ["missing_function_authz"]),
   H("h-q-xss", "query", "XSS", "検索語が無害化されて表示されるか", 0.4, "MEDIUM", "出力時にHTMLエスケープする", ["xss_reflected"]),
   H("h-robots-leak", "robots", "INFO_DISCLOSURE", "robots.txtが内部パスを列挙しないか", 0.3, "LOW", "内部パスをrobots.txtに書かない", ["reveals_internal_path"]),
   H("h-sitemap-leak", "sitemap", "INFO_DISCLOSURE", "sitemap.xmlが内部パスを列挙しないか", 0.2, "LOW", "公開ページだけを載せる", ["reveals_internal_path"])],
  ordered([
   T("t-admin-anon", "admin", "h-admin-authz", "/admin/export", expect={"status": [401, 403]}, info=0.7, purpose="未ログインで管理エクスポートが拒否されるか", inc=[]),
   T("t-login-cookie", "cookies", "h-cookie-ok", "/login", expect={"status": 200, "header_contains": {"Set-Cookie": "HttpOnly"}}, info=0.5, purpose="セッションCookieのHttpOnly属性"),
   T("t-old-anon", "oldexport", "h-oldexport-authz", "/admin-old/export", expect={"status": [401, 403, 404]}, info=0.8, purpose="旧エクスポートが認可なしで使えないか", inc=[]),
   T("t-q-plain", "query", "h-q-xss", "/q", params={"s": "hello"}, expect={"status": 200, "body_contains": ["hello"]}, info=0.2, purpose="通常の検索語が表示される(対照)", kind="control"),
   T("t-q-reflect", "query", "h-q-xss", "/q", params={"s": "<script>1</script>"}, expect={"status": 200, "body_not_contains": ["<script>1</script>"]}, info=0.6, purpose="スクリプト断片がそのまま反射されないか"),
   T("t-robots", "robots", "h-robots-leak", "/robots.txt", expect={"status": 200, "body_not_contains": ["admin"]}, info=0.5, purpose="robots.txtが内部パスを含まないか"),
   T("t-sitemap", "sitemap", "h-sitemap-leak", "/sitemap.xml", expect={"status": 200, "body_not_contains": ["admin"]}, info=0.4, purpose="sitemap.xmlが内部パスを含まないか")]),
  BUD(5), ["管理エクスポートは管理者のみ", "旧エクスポートは撤去済み"])

hold5 = case("lab-holdout-05", "holdout", "模擬ショップ(連鎖3種・保留)", "app:chainshop", ACC,
  feats_sorted({"admin": ("管理コンソール", "管理者だけが利用できる"), "comments": ("コメント", "入力値は無害化して表示する"),
   "invoices": ("請求書", "所有者だけが参照できる"), "members": ("会員一覧", "会員の識別子を公開しない"),
   "notes": ("メモ", "入力値は無害化して表示する"), "prefs": ("設定Cookie", "Cookieはスクリプトから読めない"),
   "session": ("セッション", "セッションCookieはスクリプトから読めない"), "sitemap": ("サイトマップ", "内部パスを列挙しない"),
   "tools": ("内部ツール", "運用者だけが利用できる")}),
  [H("h-admin-authz", "admin", "BROKEN_ACCESS_CONTROL", "管理コンソールを一般利用者が使えないか", 0.6, "HIGH", "管理者権限の検査を維持する", ["missing_function_authz"]),
   H("h-comment-xss", "comments", "XSS", "コメント欄が入力を無害化して表示するか", 0.4, "MEDIUM", "出力時にHTMLエスケープする", ["xss_reflected"]),
   H("h-invoice-idor", "invoices", "IDOR", "他人の請求書を参照できないか", 0.7, "HIGH", "請求書取得時に所有者を照合する", ["read_other_user_object"]),
   H("h-member-list", "members", "INFO_DISCLOSURE", "会員一覧が識別子を公開しないか", 0.3, "LOW", "一覧を非公開にする", ["exposes_user_identifier"]),
   H("h-notes-xss", "notes", "XSS", "メモ欄が入力を無害化して表示するか", 0.4, "MEDIUM", "現状のエスケープを維持する", ["xss_reflected"]),
   H("h-prefs-cookie", "prefs", "COOKIE_FLAGS", "設定CookieにHttpOnlyが付くか", 0.3, "LOW", "現状の設定を維持する", ["cookie_script_readable"]),
   H("h-session-cookie", "session", "COOKIE_FLAGS", "セッションCookieにHttpOnlyが付くか", 0.4, "MEDIUM", "Set-CookieにHttpOnlyを付ける", ["cookie_script_readable"]),
   H("h-sitemap-leak", "sitemap", "INFO_DISCLOSURE", "サイトマップが内部パスを列挙しないか", 0.3, "LOW", "内部パスを載せない", ["reveals_internal_path"]),
   H("h-tools-authz", "tools", "BROKEN_ACCESS_CONTROL", "内部ツールを認可なしで使えないか", 0.5, "HIGH", "運用者権限の検査を追加する", ["missing_function_authz"])],
  ordered([
   T("t-admin", "admin", "h-admin-authz", "/admin/console", "user_a", expect={"status": D403}, info=0.6, purpose="一般利用者が管理コンソールを使えないか"),
   T("t-comment", "comments", "h-comment-xss", "/comments", params={"c": "<script>1</script>"}, expect={"status": 200, "body_not_contains": ["<script>1</script>"]}, info=0.6, purpose="スクリプト断片がそのまま反射されないか"),
   T("t-invoice-own", "invoices", "h-invoice-idor", "/invoices", "user_a", {"member": "user_a"}, {"status": 200, "body_contains": ["inv-user_a"]}, 0.2, "自分の請求書が取得できる(対照)", "control"),
   T("t-invoice-cross", "invoices", "h-invoice-idor", "/invoices", "user_a", {"member": "user_b"}, {"status": D403, "body_not_contains": ["inv-user_b"]}, 0.9, "他人の請求書が拒否されるか"),
   T("t-members", "members", "h-member-list", "/members.csv", expect={"status": [401, 403]}, info=0.5, purpose="会員一覧が未ログインで拒否されるか", inc=[]),
   T("t-note", "notes", "h-notes-xss", "/notes", params={"n": "<script>1</script>"}, expect={"status": 200, "body_not_contains": ["<script>1</script>"]}, info=0.5, purpose="スクリプト断片がそのまま反射されないか"),
   T("t-prefs", "prefs", "h-prefs-cookie", "/prefs", expect={"status": 200, "header_contains": {"Set-Cookie": "HttpOnly"}}, info=0.4, purpose="設定CookieのHttpOnly属性"),
   T("t-session", "session", "h-session-cookie", "/session", expect={"status": 200, "header_contains": {"Set-Cookie": "HttpOnly"}}, info=0.6, purpose="セッションCookieのHttpOnly属性"),
   T("t-sitemap", "sitemap", "h-sitemap-leak", "/sitemap", expect={"status": 200, "body_not_contains": ["internal"]}, info=0.5, purpose="サイトマップが内部パスを含まないか"),
   T("t-tools", "tools", "h-tools-authz", "/internal/tools", expect={"status": [401, 403]}, info=0.8, purpose="内部ツールが認可なしで使えないか", inc=[])]),
  BUD(7), ["管理コンソールは管理者のみ", "請求書は所有者のみ"])

NEW["lab-chain-01"] = chain1
NEW["lab-chain-02"] = chain2
NEW_HOLDOUT["lab-holdout-05"] = hold5

def write(cases, only=None):
    """既存ファイルは内容が同一のときだけ許可し、異なる内容で上書きしない(保留ケースのフィンガープリント保護)。"""
    for c in cases:
        if only and c["case_id"] not in only:
            continue
        path = os.path.join(OUT, c["case_id"] + ".json")
        text = json.dumps(c, ensure_ascii=False, indent=1) + "\n"
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                same = f.read() == text
            if not same:
                raise SystemExit(f"既存の案件ファイルと内容が異なるため上書きしません: {path}")
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote", path)

if __name__ == "__main__":
    import sys
    write(list(NEW.values()) + list(NEW_HOLDOUT.values()) if "NEW_HOLDOUT" in globals() else list(NEW.values()), only=set(sys.argv[1:]) or None)
