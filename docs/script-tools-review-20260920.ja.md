# スクリプトツールのリリースレビュー（2026-09-20）

更新: 問題1は待機時間設定を適用して修正しました。問題2・3に関係するスクリプトのSHA-256計算・検査・APIは、ユーザー指定の仕様変更として撤去しました。起動時コピーは維持しています。[変更後の検証結果](script-tools-fixes-20260920.ja.md)を参照してください。以下は変更前のレビュー記録です。

対象は v1.0.0 の `list_scripts`、`get_script_info`、`run_script` と、それらが使用するカタログ、プロバイダー、実行・トランザクション・排他制御・後処理です。リリース前に修正を推奨する P2 の問題を3件確認しました。このレビューでは製品コードは変更していません。

## 1. P2: 後続のスクリプト実行にロック待機の上限が適用されない

箇所: `src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/core_execution.py:39`

`exclusive=True` の呼び出しは `SCRIPT_BARRIER.write_lock()` を引数なしで取得します。writer の既定値は `timeout=None` なので、別のプロジェクトでスクリプトが実行中の場合、後続の `run_script` は `--lock-timeout-seconds` を超えても待ち続けます。`timeout_seconds` の計測もスクリプトをロードした後にしか始まりません。読み取り側や `close_all` に追加された待機上限は、この経路には適用されません。

実機テストでは、プロセスバリアを別の実行が占有する状態を作り、待機上限を 0.05 秒に設定して公開 `run_script` を呼びました。0.502773 秒後も呼び出しは完了せず、バリア解放後に `QUEUED_SCRIPT_EXECUTED` を出力して成功しました。したがって、クライアントが待機を打ち切った後で変更が実行される可能性があります。先行スクリプトが終了しなければ、コード上、この待機にも上限がありません。

修正方針: 公開操作が取得する writer にも設定された待機時間を渡し、上限を超えた要求は実行せず `LOCK_TIMEOUT` を返す。同じ引数なしの取得がある `runtime/sync_locking.py` の exclusive 経路も確認する。

再現テスト: `test_script_queue_obeys_configured_lock_timeout`。

## 2. P2: 別ルートの子スクリプトはスナップショット検査を通らず実行される

箇所: `src/ghidra_mcp/application/services/script_service.py:391`、`script_catalog.py:572`

カタログから選んだ親スクリプトの整合性検査は、その親が属するルートだけを確認します。一方、実行要求には全ルートが渡され、`runScript()` は他のルートの子スクリプトも検索できます。また、インライン実行はカタログのルートを検査しません。このため、別ルートの子スクリプトが起動時のコピーから変化していても実行されます。

実機で、`helpers:ReviewChild.py` の私有スナップショットだけを変更しました。子を直接実行すると `SCRIPT_SNAPSHOT_CORRUPT` で拒否される一方、別ルートの親とインラインの親から同じ子を呼ぶと、いずれも `CHANGED_CHILD_EXECUTED` を出力し、`CHANGED_CHILD_EDIT` というプログラムのコメント変更をコミットしました。

これは私有スナップショットが変化した場合の整合性保証の欠落です。起動前の元ディレクトリ編集や、権限のない利用者による任意コード実行の問題とは区別しています。

修正方針: インライン実行を含め、その実行が子スクリプトの検索に利用する全スナップショットルートを検査する。呼び出し先が実行時に決まるため、親だけの検査では保証できません。

再現テスト: `test_reject_changed_child_in_another_root[False]`、同 `[True]`。

## 3. P2: SHA-256 の検査と実行の間にソースが変化しても検出しない

箇所: `src/ghidra_mcp/application/services/script_service.py:396`

`_resolve_runnable()` がスナップショットと `expected_sha256` を検査した後で、アプリケーションのロックとランタイムのプロセスバリアを取得します。実行直前には再検査しません。したがって、ロック待機中に先行スクリプトなどが私有コピーを書き換えると、変更後のソースを実行しながら、応答には変更前の SHA-256 を返します。検査対象を全ルートに広げるだけでは、この競合は解消しません。

再現テストでは競合を決定的に起こすため、ロック取得への入口にファイル変更を挿入しました。その後のスクリプト実行は実Ghidraで行い、`expected_sha256` を指定しても `CHANGED_PARENT_EXECUTED` が出力されることを確認しました。実際の同時要求のタイミングを偶然に依存して再現したテストではありません。

応答の SHA-256 は `6eb1c1d801214145a0004733e6046af9f82f8676ba1ed2809cb55b2a62521420`、実行したソースの SHA-256 は `d708a56e76dba28551e4e8ae8cc55153cf1e687e01f4ff9a46a5ceb8e2221360` でした。

修正方針: プロセス全体の排他バリアを取得した後、ロード・実行する前に、ソースと依存ルートの検査を行う。アプリケーションのターゲットロック内へ移すだけでは、別ターゲットの先行スクリプトを待つ間の競合が残ります。

再現テスト: `test_verified_parent_cannot_change_while_waiting_for_its_lock`。

## 検証範囲

- 関連単体テスト: `test_script_catalog.py`、`test_script_service.py`、`test_script_runtime_check.py`、`test_script_execution_units.py`、`test_script_barrier.py`。MCP 非推奨警告をエラー扱いにして **107 passed**。
- 追加した実機再現テスト: **4件とも、期待される保護を検証するアサーションが失敗**。環境起動やテスト収集のエラーではなく、上記3件の問題を示す失敗です。
- 実機環境: macOS arm64、Python 3.12.11、Java 21、Ghidra 12.1.3、PyGhidra 3.2.0 の固定コミット、MCP SDK 2.2.0。専用JVM設定と一時プロジェクトを使用しました。追加再現のスクリプト言語は PyGhidra です。
- 前回修正後に検証したソース・テスト・依存定義184ファイルと SHA-256 が一致することを確認しました。今回、全テストや3言語の全実機ケースを再実行したものではありません。
- 既存のMCPサーバーの再起動、Dockerの起動確認、Windows/Linuxでの実行、公開処理は行っていません。

再現コード・実機ログ・JUnit結果・確認対象のハッシュは [検証資料](script-tools-review-evidence-20260920.zip) に保存しています。`run_native.py` はこの環境のGhidra、Java、Jython拡張への絶対パスを含むため、別環境で実行する場合は調整が必要です。
