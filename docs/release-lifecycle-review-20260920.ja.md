# リリース前レビューの継続: ターゲット状態とインポート（2026-09-20）

更新: 以下のP2の2件は[ターゲット状態・インポートの修正](release-lifecycle-fixes-20260920.ja.md)で修正済みです。以下は修正前のレビュー記録です。

自動インポートの公開API移行後をレビューし、追加で **P2を2件** 確認しました。いずれも製品のツール呼び出し経路と実Ghidraを使って再現しています。製品コードと既存テストは変更していません。

## P2: open_programのロックタイムアウトでターゲットの参照先が変わる

対象: `src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py:143–148`

`_create_session_locked()` はターゲットとプロジェクトのロックを取得する前に、`target_projects[name]` を要求先のプロジェクトへ書き換えます。登録状態を復元する例外処理はロック取得後のブロック内にあるため、取得時の `LOCK_TIMEOUT` では実行されません。

隔離した2つのプロジェクト `original` / `busy` を作成し、実際のプロジェクトロックを別スレッドで保持して再現しました。ロックを置き換えるモックは使用していません。

1. `subject` を `original` に登録する。
2. `busy` のロックを保持した状態で、`open_program(target="subject", project_name="busy", ...)` を呼ぶ。
3. 呼び出しは `LOCK_TIMEOUT` / `retryable=true` で失敗し、セッションも作成されない。
4. しかし `list_targets` では `subject` の参照先が `busy` に変わり、その後の `list_project_programs(target="subject")` も `busy` のプログラムを返す。

未登録のターゲット名でも、失敗後に新しい登録が残ります。再試行可能な失敗を返した後に状態が変わるため、既存ターゲットを使った後続操作が意図しないプロジェクトを対象にします。

修正方針: 必要なロックを取得してから登録を公開するか、取得失敗も含めて既存の参照先・新規登録を復元する。既存ターゲットと未登録ターゲットの両方を回帰テストに含める。

再現テスト `test_open_timeout.py` の2ケースが、失敗前後の登録状態の一致を検査して失敗しました。実測値は `registered-timeout.json` / `new-target-timeout.json` に保存しています。

## P2: 上位64ビットアドレスをentry_addressに指定するとインポートに失敗する

対象: `src/ghidra_headless/session/project_handle.py:1512`（呼び出し元: 1447–1448行）

`entry_address` はPythonの整数に変換した後、`AddressSpace.getAddress(long)` に渡されます。`0x8000000000000000` 以上の正の整数はJavaの符号付き `long` に収まらず、JPypeが `OverflowError: int too big to convert` を送出します。Ghidraでは扱える64ビットアドレスでも、この経路で失敗します。

実Ghidraで、6バイトのx86-64コードを次の条件でインポートしました。

```json
{
  "import_mode": "raw_binary",
  "language_id": "x86:LE:64:default",
  "base_address": "0xffff800000001000",
  "entry_address": "0xffff800000001000",
  "analyze_imported": false
}
```

結果は後処理の失敗で、ツールには `OPERATION_FAILED` が返りました。インポート済みファイルはロールバックで削除され、`partial_import=false` / `rollback_deleted=true` でした。

対照として同じコード・ベースアドレスで `entry_address` を `entry_offset=0` に置き換えると成功しました。保存したプログラムを再オープンし、アドレス `ffff800000001000` に関数が作成されていることも確認しています。したがって、高位アドレス自体やバイナリの形式の制約ではなく、明示アドレスの数値変換が原因です。カーネル等の高位アドレスで、開始位置を明示する利用に影響します。

修正方針: Ghidraの公開アドレス解析API、またはアドレス幅と範囲を考慮した変換を利用する。非推奨APIへの移行や、範囲外の入力を無条件に切り捨てる処理は不要です。上位64ビットアドレスと通常の低位アドレスを回帰テストに含める。

再現テスト `test_high_entry.py` は明示アドレスのケースが失敗し、オフセットのケースは成功しました。実測値は `entry_address.json` / `entry_offset.json` に保存しています。

## 確認範囲と結果

今回はターゲットの登録・オープン・クローズ、失敗時の状態復元、インポートの後処理とリソース解放、MCPへのエラー伝播を重点的に確認しました。

| 検証 | 結果 |
| --- | --- |
| 関連する既存オフラインテスト | **338 passed**（5.05秒） |
| 実Ghidraの既存回帰テスト | **12 passed**。リソース解放等8件（直前の自動インポート修正2件を含む）、MCP通信4件 |
| ロックタイムアウトの状態復元検査 | **2 failed**。新規・既存ターゲットで上記P2を再現 |
| 高位アドレスの検査 | **1 passed / 1 failed**。オフセット指定は成功、明示アドレス指定で上記P2を再現 |
| Ruff check / format、`git diff --check` | 成功。Python 185ファイルの整形を確認 |
| ソース・既存テストの変更確認 | 開始時の185ファイルと内容が一致 |

実Ghidra検証の合計は **13 passed / 3 failed** です。失敗3件はこのレビュー用に一時ディレクトリへ追加した検査で、既存の回帰テストの失敗ではありません。通常のテストと実Ghidra検証の両方で `MCPDeprecationWarning` をエラー化しました。

環境はmacOS arm64、Ghidra 12.1.3、Java 21、既存のプロジェクト仮想環境です。専用JVM・一時プロジェクトを使用しています。既存回帰テストにはstdio / HTTPのMCP通信が含まれますが、今回の不具合再現自体は同じツール実装を直接呼び出しています。

全体テスト、Docker・他OS・別Pythonバージョン、外部BSim・共有リポジトリ接続、配布物のビルドは今回再実行していません。この2件を修正し、再現テストが成功することを確認してからリリースすることを推奨します。

再現コード、実測JSON、実行ログ、JUnit XML、チェック結果は[検証資料](release-lifecycle-review-evidence-20260920.zip)に保存しています。
