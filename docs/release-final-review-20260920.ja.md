# v1.0.0 製品リリース前の再レビュー（2026-09-20）

**追記：以下の3件は修正済み。** 修正内容と通常1,465件・実機89ケースの検証結果は[修正後の検証記録](release-review-fixes-20260920.ja.md)を参照。以下は修正前のレビュー記録として保持する。

**修正前判定：現状のままの製品リリースは見送る。** 子スクリプトの失敗を成功として返し、変更を確定する問題を実機で再現した。加えて、排他制御のタイムアウトと、非推奨APIを使わないという要件に未解決事項がある。

対象は `536c8010a4ae3868aa0ea0fb2d78ed6ccf80aff1` に未コミット変更を加えた、このワークスペースの `1.0.0`。MCP SDK / mcp-types は `2.2.0`、PyGhidra は upstream commit `263160cf57db21a9e25f1e0a8bc42fde5b8824eb` の `3.2.0`。確認対象ファイルのSHA-256とログは[検証記録](release-final-review-evidence-20260920.zip)に含めた。

## 指摘

### 1. [P1] サブディレクトリのJython子スクリプトの例外が握りつぶされる

対象：`src/ghidra_headless/scripts/execution.py:383-399, 510-512`

共有Jythonインタープリターを作るかどうかの判定は、スクリプトルート直下の `.py` だけを調べる。しかし、Ghidraの `runScript("sub/Child.py")` は、そのサブディレクトリにあるファイルも実行できる。カタログに公開されるファイルの範囲と、子スクリプトとして実行できる範囲が一致していない。

再現した構成：

```text
script-root/
  ExternalParent.java
  sub/
    ExternalFailure.py  # @runtime Jython
```

親Javaはコメントを `PARENT_BEFORE` に変更し、`runScript("sub/ExternalFailure.py")` を呼び、続けて `PARENT_AFTER` に変更する。子Jythonはコメントを変更した後に `RuntimeError("EXTERNAL_CHILD_FAILURE")` を投げる。

Jythonを一度通常実行して初期化した後、この親を実行した実測結果：

```json
{
  "status": "ok",
  "error": null,
  "transaction_outcome": "committed",
  "execution_state": "valid",
  "stray_threads": []
}
```

実際のコメントも `BASELINE` から `PARENT_AFTER` に変更されていた。子の例外はプロセス側に出力されるが、返却されるエラー情報には含まれない。呼び出し元が失敗を検知できず、不完全な編集を保存し得るため、リリースを止める問題と判断する。

修正では、カタログ直下のファイル有無だけで例外伝播の保証を省略しないこと。利用可能なJython子スクリプトを含む実行全体で共有状態を保証し、この構成で `SCRIPT_FAILED`、`rolled_back`、元のコメントの維持を回帰テストに加える。

記録：`warm-nested-jython-repro/runtime.log`、`warm-nested-jython-repro/result.xml`。初回実行時にも変更の確定を観測したが、Jython初期化由来のスレッド検出が重なったため、判定には初期化後の再現結果を採用した。

### 2. [P2] ScriptBarrierのタイムアウトが実際のロック取得を覆っていない

対象：`src/ghidra_mcp/application/locks.py:69-85`

`_wait_for_writers()` を抜けた後の `fasteners.ReaderWriterLock` の取得には期限がない。次の2条件で、`timeout=0.05` にもかかわらず250ミリ秒後も待機し、相手を明示的に解放した後に成功として取得することを確認した。

- readerの事前確認と実際の取得の間に、script側のwriterが入る。
- readerが実行中に、`write_lock(timeout=...)` を取得する。

前者では通常ツールの応答がスクリプト終了まで止まる。後者では `close_all()` が指定する待ち時間も守られない。実際の取得完了まで単一の期限で制御し、確認と取得の間の競合をなくす必要がある。

記録：`barrier-repros.log`、`barrier-repros.xml`。競合の再現では事前確認後のスケジューリングだけをイベントで制御し、実際のReaderWriterLockは置き換えていない。

### 3. [P2] コメント操作に削除予定の旧Ghidra APIが残っている

対象：

- `src/ghidra_headless/handlers/commands/program_tools.py:85-86`
- `src/ghidra_headless/handlers/commands/batch_edits.py:27-28`
- `src/ghidra_headless/handlers/commands/mutating_symbols.py:172-193`
- `src/ghidra_headless/handlers/commands/read_only_decompile.py:22`

`CodeUnit.*_COMMENT` の整数定数、および整数を受け取る `Listing.getComment` / `Listing.setComment` / `CodeUnit.getComment` を使用している。インストール済みGhidra 12.1.3の公式ソース同梱ZIPで、これらの `@Deprecated(forRemoval = true, since = "11.4")` を確認した。

現在の12.1.3では動くが、「非推奨APIを利用しない」というリリース条件は未達。`CommentType` と、その型を受け取る正式なオーバーロードに移行し、各コメント種類の読み書きを実機で確認する必要がある。

## 検証結果

| 検証 | 結果 |
| --- | --- |
| 全体の通常テスト | 1,456成功、88スキップ、38.82秒 |
| Ghidra実機回帰テスト | 81成功、131.82秒 |
| 一時プロジェクト作成の追加実機テスト | 1成功 |
| MCP非推奨警告 | 上記テストで `MCPDeprecationWarning` をエラー化し、失敗なし |
| 指摘1の追加実機再現 | 期待する失敗・ロールバックにならず、テスト失敗 |
| 指摘2の追加再現 | 2条件ともタイムアウトを守らず、テスト失敗 |
| Ruff check / format | 成功、format対象182ファイル |
| `uv lock --check --offline` / `git diff --check` | 成功 |
| wheel / sdistのビルド | `1.0.0` として成功 |
| 配布物の内容 | バージョン、Apache-2.0ライセンス、109個のPythonソースがワークスペースと一致 |
| wheelの読み込み・CLI help | 別venvにwheelをインストールし、wheel側からのimportとhelpの終了コード0を確認。依存ライブラリは既存venvを参照 |
| `docker compose config --quiet` | 成功 |

実機環境は macOS arm64、Python 3.12.11、Temurin Java 21、Ghidra 12.1.3、Jython拡張あり。専用設定と一時プロジェクトを使用した。81件にはstdio / HTTPでのMCP通信、編集・ロールバック、Java / PyGhidra / Jython間の既存の呼び出しパターンが含まれる。

通常テストでスキップされた88件のうち82件を今回実機で実行した。残る6件は外部BSimデータベースを使う5件と共有リポジトリの統合テスト1件。これらの外部接続は今回再検証していない。Dockerイメージの再ビルド・起動、Windows/Linux実機、Python 3.10 / 3.14の実行も今回の検証範囲に含まれない。

PyPI公開は予定しないという方針に従い、PyGhidraの固定コミットへの直接依存をPyPI配布上の阻害事項として扱っていない。製品コードの修正やリリース操作は行っていない。上記3件の修正と再検証を終えてから、改めてリリースを判断する。
