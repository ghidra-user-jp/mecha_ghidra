# Base Addressの数値表記の正規化（2026-09-20）

[直前のレビュー](release-numeric-review-20260920.ja.md)で指摘した、`base_address` の表記によって配置先が変わるP2を修正しました。

`ProjectHandle._import_program_raw_locked()` で、`Base Address` を `format(int(value, 0), "x")` により正規化してから `ProgramLoader.addLoaderArg()` に渡します。公開入力の検証と同じ数値解釈で、Ghidraが読む16進文字列へ変換します。製品側の変更はこの引数変換に収めています。

`"4096"`、`"0x1000"`、`"0o10000"`、`"0b1000000000000"` はすべて `"1000"` となり、Ghidraでは `0x1000` に配置されます。依存追加や新しいGhidra APIの使用はありません。

## 検証結果

| 検証 | 結果 |
| --- | --- |
| 関連するオフラインテスト | **181 passed**（0.73秒）。ProjectHandle、入力仕様、ターゲットサービス・ライフサイクル |
| 実Ghidraの数値表記・開始位置指定 | **16 passed**。4種類の表記 × 低位・上位64ビットアドレス × entry_address・entry_offset |
| 実Ghidraの既存回帰 | **13 passed**。ロック待ち失敗・再試行2件、範囲外のentry_address拒否3件、リソース解放等8件 |
| 前回の配置先再現テスト | **3 passed**。16進・10進・8進表記がすべて0x1000に配置される |
| 実Ghidraの実行合計 | **32 passed / 2 deselected**（33.01秒）。除外2件は前回のOverlay確認で、今回の正規化修正の対象外 |
| Ruff check / format、git diff --check | 成功。Python 186ファイルの整形を確認 |
| 変更範囲 | 製品1ファイル、テスト2ファイル。その他の既存Python 183ファイルは開始時と一致 |

実Ghidraの16ケースでは保存したプログラムを2回開き直し、実際の配置先、開始位置の関数・エントリーポイント、クローズ後の解放を確認しました。上位64ビットは `0xffff800000001000` を使用しています。単体テストには大文字の16進接頭辞と、空白・正符号を伴う10進表記も含めています。

pytestでは `MCPDeprecationWarning` をエラー化しました。実Ghidra検証はmacOS arm64、Ghidra 12.1.3、Java 21の専用JVM・一時プロジェクトで、製品のツール実装を直接呼び出しています。今回は関連するテストを選択して実行し、全体テスト・MCP通信・Docker・他OS・外部BSim・共有リポジトリ接続・配布物のビルドは再実行していません。

修正差分、実測JSON、実行ログ、JUnit XML、再現コードは[検証資料](release-numeric-fix-evidence-20260920.zip)に保存しています。
