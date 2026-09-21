# リリース前コードレビューの継続（2026-09-20）

更新: 以下の2件は[残存スレッド監視の修正](release-thread-fixes-20260920.ja.md)で対処しました。以下は修正前のレビュー記録です。

前回の過剰処理4件の修正後を対象にレビューを継続し、スクリプトの残存スレッド監視と復旧に関する **P2を2件**、実Ghidraで確認しました。今回のリリース前に修正を勧めます。製品ソース・既存テスト184ファイルはレビュー開始時と同一で、修正は行っていません。

## 1. P2: 隔離情報の更新で生存スレッドの記録が消え、復旧時のcloseを通過する

対象: `src/ghidra_headless/handlers/core_runtime.py:67–71`

`mark_execution_invalid()` は隔離情報全体を新しい辞書で置き換えます。スクリプト終了時に残存スレッドを検出すると、最初は `reason=script_run` と `stray_threads` が保存されます。しかし、そのスレッドが後からトランザクションを開始すると、TransactionListenerが `reason=stray_transaction`、説明、スレッド名だけで情報を置き換え、元の `stray_threads` が消えます。

`runtime/target_lifecycle.py:610–613` の復旧処理は、`stray_threads` が空なら生存確認を省略します。このため、まだ実行中のスレッドがあるのに `close_session(discard_changes=true)` が成功し、そのスレッドが使うプログラムを解放できます。

実機再現:

1. Javaスクリプトの `run()` が通常のJavaスレッドを開始し、スクリプト本体は終了する。
2. 残存スレッドを検知して `SCRIPT_FAILED` / `execution_state=invalid` となる。最初のdiscard-closeは `RUNTIME_DEGRADED` で正しく拒否される。
3. 残存スレッドにシグナルを送り、プログラム上でトランザクションを開始・終了させ、その後も待機させる。
4. `reason` が `stray_transaction` に変わり、`stray_threads` が消える。
5. 同じdiscard-closeが成功する。終了直後に **`worker.isAlive() == true` と `program.isClosed() == true`** を確認した。

再現ではプログラム解放後の読み書きは行っていません。クラッシュやデータ破損を観測したという意味ではなく、それらを避けるための既存の生存確認を通過してしまう問題です。

修正方針: 隔離理由の追加・更新でも、復旧に必要な残存スレッド情報を保持する。複数回の報告がある場合はIDやPythonのtokenで統合し、生存中の記録を上書きで失わないようにする。復旧時に最初の拒否が後続イベントで解除されないことを回帰テストにする。

再現テスト: `test_quarantine_must_retain_live_thread_evidence_after_later_transaction`。観察結果は `quarantine-thread-evidence.json`。

## 2. P2: Javaスクリプトのコンストラクターで開始したスレッドを検知しない

対象: `src/ghidra_headless/scripts/execution.py:503–510`。インスタンス生成は同ファイル469行。

スレッドの開始前スナップショットは `provider.getScriptInstance()` の後で取得されます。しかし、Javaスクリプトのコンストラクターは `getScriptInstance()` の中で既に実行されます。その中で開始したスレッドは「実行前からいたスレッド」として扱われ、終了時の差分から除外されます。

実機では、コンストラクターで `review-constructor-worker` という通常のJavaスレッドを開始し、CountDownLatchで待機させました。`run()` は `println()` だけで終了させています。スレッドが生存しているのに、結果は以下でした。

```json
{
  "status": "ok",
  "transaction_outcome": "unchanged",
  "execution_state": "valid",
  "stray_threads": []
}
```

ターゲットの隔離情報も `null` でした。検証用スレッドはプール・仮想スレッドではなく、名前による除外条件にも該当しません。通常のJavaスレッドを同じ実行内で開始しても、コンストラクターか `run()` かによって監視結果が変わります。

修正方針: ユーザーコードが実行されるインスタンス生成より前から監視し、ロード失敗時にも生成済みの残存スレッドを確認する。Ghidra/OSGiが生成する内部スレッドとの区別は維持する。コンストラクターで開始したワーカーが残るケースを回帰テストに加える。

再現テスト: `test_java_constructor_worker_must_not_escape_thread_observation`。観察結果は `constructor-thread-observation.json`。

## 確認範囲

| 検証 | 結果 |
| --- | --- |
| MCPの構築・構造化結果・HTTP契約、スクリプト、バリア、バッチ読み取りの対象単体テスト | **173 passed / 6 skipped**。6件は次行で実行した実機専用ケース |
| stdio / HTTPの実MCP通信、セッション・エクスポート・デコンパイラー解放 | **10 passed**。PyGhidra / Jythonの編集とロールバックを含む |
| 今回追加した2件の期待動作の検証 | **2 failed**（9.16秒）。期待する検知・close拒否にならず失敗。実測結果をJSONに保存 |
| MCP非推奨警告 | 上記pytest実行で `MCPDeprecationWarning` をエラー化 |
| Ruff check / format | 成功。184ファイルの整形を確認 |
| lockfile / whitespace | 既存の依存キャッシュを用いた `uv lock --check --offline`、`git diff --check` 成功 |
| 製品コード・既存テストの変更確認 | レビュー開始時の184ファイルと内容が一致 |

最初の再現テスト起動では、テスト側がJVM起動前にGhidraクラスをimportしたため収集後の準備段階で失敗しました。importをJVM起動後に移してから上記2件を確認しており、準備エラーは不具合の根拠に含めていません。lockfile確認も新しい空のキャッシュではオフライン解決できなかったため、以前の検証で取得済みの依存キャッシュを使用しました。

環境はmacOS arm64、Python 3.12.11、Java 21、Ghidra 12.1.3、MCP SDK 2.2.0、Jython拡張あり。専用JVMと一時プロジェクトを使用し、検証用スレッドは終了シグナルとjoinで回収しました。稼働中のMCPサーバーへの変更や再起動、リリース操作は行っていません。

今回、全テスト一括実行、配布物の再ビルド、Docker・他OS・別Pythonバージョン、外部BSimと共有リポジトリ接続は再検証していません。前回までの結果と今回の確認範囲を混同せず、上記2件を修正した後にリリース判断を更新する必要があります。

再現コード、ログ、JUnit XML、観察結果は[検証資料](release-continuation-evidence-20260920.zip)に保存しています。
