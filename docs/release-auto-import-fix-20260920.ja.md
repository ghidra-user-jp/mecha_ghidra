# 自動インポートの公開APIへの移行（2026-09-20）

[前回のレビュー](release-api-review-20260920.ja.md)で指摘した、自動インポートの非推奨API依存を修正しました。

## 変更内容

`ProjectHandle._import_program_auto_locked()` の `GhidraProject.importProgram(File)` と `saveAs()` を、`pyghidra.program_loader()` によるロードと `Loaded.save()` に置き換えました。loaderやlanguageを明示せず、形式・言語の自動判定をGhidraに委ねます。保存先プロジェクト、フォルダー、ファイル名と既存のTaskMonitorをbuilderへ渡します。

取得した `LoadResults` は保存成功・保存失敗・primary未取得のいずれでも `finally` でcloseします。従来のGhidraProjectへのconsumer追加は行いません。ロード処理自体が失敗して結果を返さない場合は元の例外を伝播します。

以下の既存の診断と復旧動作を維持しています。

- 保存後に解放できなかった場合は、保存済みのdomain pathを含む `PROGRAM_CLOSE_FAILED` を返す。
- 保存と解放の両方が失敗した場合は、両方の原因を含め、保存失敗を例外のcauseとして保持する。
- 保存後の解析などの後処理が失敗した場合は、従来どおり作成済みのdomain fileをロールバックする。
- 後処理中のProgram解放が失敗した場合は、使用中のdomain fileを削除せず `IMPORT_CLOSE_FAILED` を返す。

raw binary側の実装や依存バージョンは変更していません。今回の変更は製品コード1ファイル、既存テスト2ファイルです。その他182件のPythonソース・テストは着手前と内容が一致しています。

## 検証

| 検証 | 結果 |
| --- | --- |
| ProjectHandle単体テスト | **88 passed** |
| 全体のオフラインテスト | **1,487 passed / 121 skipped**（42.17秒） |
| 最終の実Ghidra検証 | **20 passed / 0 skipped**（67.07秒） |
| Ruff check / format、`git diff --check` | 成功。Python 185ファイルの整形を確認 |
| 非推奨APIへの逆戻りの検査 | 修正前のソースにテストを適用すると対象8件が旧API呼び出しの禁止で失敗。修正後は成功 |

単体テストは既存の保存・解放・後処理エラーのケースを新APIに対応させ、保存だけの失敗、primary未取得、load自体の失敗を追加しました。修正前のソースの検証では別ディレクトリを使用し、実際のimport元がそのディレクトリであることを確認しました。旧コードのJava File生成のみを代替してJVM不要にしています。

実Ghidraの20ケースは以下です。

- 自動インポートの追加2ケース: 解析あり／なしで、公開builderの利用、形式の自動判定、結果のcloseとProgram解放を確認。保存したProgramを2回開閉し、形式・メモリーの維持と開いたままのトランザクションがないことを確認する。
- 既存のリソース保護・解放6ケース、残存スレッド監視6ケース、stdio / HTTPのMCP通信4ケース。
- 前回のレビューの検査2ケース: 製品の自動インポートが非推奨メソッドを呼ばないこと、および公開APIでの自動判定・保存・再オープン。

最初の実機実行では18件成功・2件失敗でした。追加テストで `samples/hello.bin` をELFと仮定していましたが、実際はMach-Oで、自動判定は正しく機能していました。検体形式を固定せず、Raw Binaryにフォールバックしていないことと、検出した形式が保存・再オープン後も維持されることを確認するテストに直し、20件を再実行して成功しました。この修正に伴う製品コードの追加変更はありません。

環境はmacOS arm64、Python 3.12.11、Java 21、Ghidra 12.1.3、MCP SDK / mcp-types 2.2.0、PyGhidra 3.2.0の固定コミット版、Jython拡張あり。pytestではMCP非推奨警告をエラー化し、実機検証には専用JVMと一時プロジェクトを使用しました。オフラインテストのskipは実ランタイム等の条件付きケースです。他OS・Docker・外部BSim・共有リポジトリ接続の再検証は今回の範囲に含みません。

差分、回帰テスト、実行ログとJUnit XMLは[検証資料](release-auto-import-fix-evidence-20260920.zip)に保存しています。
