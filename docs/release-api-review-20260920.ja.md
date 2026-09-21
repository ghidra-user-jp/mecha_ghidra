# リリース前レビューの継続: 自動インポートAPI（2026-09-20）

更新: 以下のP2は[自動インポートの公開APIへの移行](release-auto-import-fix-20260920.ja.md)で修正済みです。以下は修正前のレビュー記録です。

前回の残存スレッド監視2件の修正後をレビューし、追加で **P2を1件** 確認しました。自動インポートは現在のGhidraでは成功しますが、「非推奨APIを使用しない」というリリース条件を満たしていません。製品コードと既存テストは変更していません。

## P2: 通常の自動インポートが削除予定のAPIを呼んでいる

対象: `src/ghidra_headless/session/project_handle.py:1265–1266`

`import_program` のデフォルトである `import_mode="auto"` は、`_import_program_auto_locked()` から `GhidraProject.importProgram(java.io.File)` を呼びます。Ghidra 12.1.3の同梱ソースでは、このオーバーロードに `@Deprecated(since = "12.0", forRemoval = true)` が付いており、代替として `ProgramLoader` が指定されています。

既に公開APIへ移行した `raw_binary` の経路とは別で、自動判定する通常のインポートに旧APIが残っています。同名の別クラスのメソッドや、引数の異なる非推奨でないオーバーロードを誤検出したものではありません。

実Ghidra検証では、Python側のProject参照を呼び出し記録用の委譲オブジェクトで包み、処理は実際のGhidraProjectへ渡しました。製品の `ProjectHandle.import_program()` に既定引数で `samples/hello.bin` を渡した結果は以下です。

```json
{
  "domain_path": "/hello.bin",
  "method": "GhidraProject.importProgram(java.io.File)",
  "deprecated": true,
  "since": "12.0",
  "for_removal": true
}
```

非推奨情報は稼働中JVMの公開Reflection APIで取得しました。インポート自体の失敗ではなく、「製品の自動インポートが非推奨APIを呼ばない」という検査が失敗しています。

修正方針: `raw_binary` と同様に、公開APIの `pyghidra.program_loader()` / `ProgramLoader` でロードし、保存後に `LoadResults.close()` で解放する。自動判定ではloaderを明示しない。保存失敗・解放失敗時の既存の診断や部分成功情報を維持すること。

隔離した別の一時プロジェクトで、この公開APIによる自動判定・保存・再オープンと、再オープン後にメモリーが存在することを確認しました。これは置換先の実現性の検証であり、製品への修正はまだ適用していません。

`tests/test_project_handle.py:2075` の既存テストは旧APIの呼び出しを期待しているため、移行時にはこのテストと関連する保存・解放失敗のテストも更新する必要があります。MCPの非推奨警告をエラー化しても、GhidraのJava側の非推奨APIは検出できません。

一次資料: インストール済み `Ghidra/Features/Base/lib/Base-src.zip` 内の `ghidra/base/project/GhidraProject.java:734–762`。同メソッドの内部実装も `ProgramLoader.builder()` に委譲しています。

## 確認範囲と結果

起動・終了時の処理、スクリプト実行と隔離・復旧、MCPの構造化応答・大きな結果・エラー変換を読み直しました。Ghidra同梱ソースにある非推奨メソッド宣言とPython側の呼び出し名を突き合わせ、候補について受信オブジェクトと引数を確認しています。コメント、thunk、checkinなどの同名候補は、変更済みの正式なオーバーロード等であり、追加指摘には含めていません。

| 検証 | 結果 |
| --- | --- |
| 全体のオフラインテスト | **1,484 passed / 119 skipped**（41.93秒）。skipは実ランタイム等の条件付きテスト |
| 実Ghidraの既存回帰テスト | **16 passed**。前回追加のスレッド監視6件、リソース解放等6件、stdio / HTTPのMCP通信4件 |
| 公開APIによる自動インポートの代替検証 | **1 passed**。保存・再オープンまで成功 |
| 製品の自動インポートで非推奨APIを禁止する検査 | **1 failed**。上記指摘を検出 |
| 実Ghidra検証の合計 | **17 passed / 1 failed**（62.88秒） |
| Ruff check / format、`git diff --check` | 成功。Python 185ファイルの整形を確認 |
| ソース・既存テストの変更確認 | 開始時の185ファイルと内容が一致 |

pytestでは `MCPDeprecationWarning` をエラー化しています。環境はmacOS arm64、Python 3.12.11、Java 21、Ghidra 12.1.3、MCP SDK / mcp-types 2.2.0、PyGhidra 3.2.0の固定コミット版、Jython拡張あり。専用JVMと一時プロジェクトを使いました。

今回の回帰テストで前回の2件の修正は維持されています。Docker・他OS・別Pythonバージョン、外部BSim・共有リポジトリ接続、配布物の再ビルドは再検証していません。

検査コード、実測JSON、Ghidraソース抜粋、実行ログ、JUnit XMLは[検証資料](release-api-review-evidence-20260920.zip)に保存しています。
