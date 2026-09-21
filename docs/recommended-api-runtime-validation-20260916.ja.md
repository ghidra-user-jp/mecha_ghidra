# 推奨API移行後の実機検証（2026-09-16〜17）

現在の作業ツリーを実Ghidraで検証した。9月16日の初回検証では対象範囲に問題を認めなかったが、Jythonは未導入だった。9月17日までのJython追試で`sys.exit(0)`を失敗と誤判定する不具合を発見・修正し、修正後の関連実機テスト23件がスキップなしで成功した。詳細は[追試結果](#jython-follow-up)を参照。MCPの別プロセス・実HTTP通信を継続して検証できるよう、[実機テスト](../tests/test_runtime_mcp_transport.py)も追加した。

## 環境

| 項目 | 実測バージョン |
| --- | --- |
| ホスト | macOS / Apple Silicon（arm64） |
| Ghidra | 12.1.2 PUBLIC（ローカルの既存インストール） |
| JDK | Temurin 21.0.8-beta |
| Python | 3.12.11 |
| MCP / MCP Types | 2.1.1 / 2.1.1 |
| PyGhidra / JPype | 3.1.0 / 1.5.2 |
| Pydantic / AnyIO | 2.13.4 / 4.14.1 |
| JSON Schema / Uvicorn / Starlette | 4.26.0 / 0.51.0 / 1.3.1 |
| BSim PostgreSQL | 15.13（Ghidra同梱拡張を含むローカルビルド） |

対象は未コミットの変更を含む作業ツリーで、インストール済みの配布物や既存Dockerイメージの更新は行っていない。既存のベンチマークとGhidra Serverを再起動せず、専用の一時プロジェクト、DB、共有リポジトリを使用した。

## 初回の結果（9月16日）

| 検証 | 成功 | スキップ | 時間 |
| --- | ---: | ---: | ---: |
| 実Ghidraのローカル機能 | 29 | 1 | 44.33秒 |
| 実MCPプロセス：stdio / HTTP | 2 | 0 | 38.99秒 |
| 実BSim / Ghidra共有同期 | 6 | 0 | 10.19秒 |
| 通常の全テスト | 1,344 | 38 | 9.55秒 |

初回の実機テストは合計37件成功・1件スキップ、失敗0件。通常テストの38件スキップは実機フラグを無効にしたためであり、その38件を別途上段の3回に分けて実行した。初回に残った1件はJython専用テストで、総合テスト内のJython成功実行・例外時ロールバックの分岐も未実行だった。この未検証部分は下記の追試で確認した。

### ローカル機能

- インポート、解析、デコンパイル、関数・型・参照・コメント・メモリの読み取りと変更。
- バッチと個別読み取りの一致、部分失敗、revision不一致、読み取り中の変更検出。
- 型カテゴリ、関数プロトタイプ、変更のロールバック、プロジェクト再オープン。
- Java / PyGhidraスクリプト、ネストしたスクリプト、例外の伝播、タイムアウト、変更のロールバック、大きな失敗結果の保持。
- ワーカースレッドからのインポート・デコンパイル、再読み込み・終了時のネイティブデコンパイラ解放。

### MCP通信

stdioとStreamable HTTPそれぞれで、実際のCLIとJVMを起動し、公式SDKの`Client`から17回のツール呼び出しを実施した。各プロセスのfullプロファイルで80ツールを列挙し、全ツールの入出力スキーマの形式と、呼び出したツールの実際の`structuredContent`を検証した。全80ツールを呼び出したという意味ではない。

空配列、デコンパイル結果、dry-runと変更の適用、バッチの部分失敗、スクリプト失敗後のコメントの復元、結果の圧縮・`read_result`・`search_result`・`resources/read`、不正な入力の拒否を確認した。出力検証が失敗した場合の`presentation_failed`通知も成功として見逃さないようにした。

HTTPでは通常のSDK経由の操作に加え、次を独立した接続で確認した。

- 最初の要求を`tools/call`にし、`initialize`なしで成功。
- JSON応答に`Mcp-Session-Id`がない。
- `server/discover`でGhidraの作業案内・検索案内を含むinstructionsを取得。
- 接続を閉じた後、新しい接続で同じ結果リソースを取得。
- 終了時にHTTPサーバープロセスを停止。

この検証は通信セッションが不要であることを確認している。Ghidraのターゲットや結果キャッシュはサーバープロセス内に保持されるため、別プロセスへの切り替えやサーバー再起動をまたぐ状態共有を保証するものではない。

### BSim・共有同期

localhost限定の一時PostgreSQLとGhidra Serverに、無害な自作Cプログラム2個を登録した。ランダムな専用認証情報を使い、既存DB・リポジトリを対象にしなかった。

BSimの状態取得、実行ファイル一覧、カテゴリ・メタデータの変更、関数検索、共有リポジトリからの一致元読み込みとデコンパイルが成功した。共有同期ではcheckout、commit、別キャッシュでの更新取得、競合・変更状態の保護、試験ファイルの削除まで成功した。ここでの6件は実Javaバックエンドを通す統合テストであり、MCPの通信テストとは別に実施した。

検証後に一時サービスを停止し、15432および13140–13142のポートが閉じていることを確認した。

## 再実行と証跡

実機テストの環境変数・サービス条件は[開発ガイド](development.ja.md#実機検証)を参照。今回のローカル実行では`GHIDRA_RUNTIME_VALIDATION=1`、`GHIDRA_RUNTIME_BINARY_PATH=/bin/ls`を指定し、次を実行した。

```bash
.venv/bin/python -m pytest -q -rA \
  tests/test_runtime_readonly_commands.py \
  tests/test_runtime_mutating_commands.py \
  tests/test_runtime_resource_safety.py \
  tests/test_runtime_batch_read.py \
  tests/test_runtime_tool_revision.py \
  tests/test_runtime_script_commands.py \
  tests/test_runtime_worker_thread.py \
  tests/test_runtime_registry_shared_sync_commands.py::test_runtime_create_project_success

.venv/bin/python -m pytest -q -rA tests/test_runtime_mcp_transport.py
```

JUnit XMLと実行ログは検証端末の`/private/tmp/mecha-recommended-runtime-20260916/`に保存した。`local-runtime`、`mcp-runtime`、`integration-runtime`、`offline`がそれぞれの試験に対応する。各`.xml`と`.log`、一時サービスの停止結果を含む`integration-driver.log`を確認できる。これらは一時ファイルであり、永続的なリポジトリ成果物ではない。

<a id="jython-follow-up"></a>

## Jython追試と修正（9月17日）

Ghidra 12.1.2に同梱された公式のJython拡張（Jython 2.7.4）を、一時ディレクトリの専用設定領域へ展開した。Javaの`application.settingsdir`と`user.home`をその領域へ向けた別プロセスで実行し、通常のGhidra設定やインストール先の拡張は変更していない。起動後に`Java=True, Jython=True, PyGhidra=True`を確認した。

使用したZIPは`ghidra_12.1.2_PUBLIC_20260605_Jython.zip`、SHA-256は`6a7b74dd1dbef2ec3414f432f0a5215cdd21914bf7326283c4143a30a0258916`。

### 発見した不具合

Jythonの`SystemExit.code`取得に使っていた`__findattr__`はJPypeから呼べず、終了コードが`unknown`になっていた。そのため、正常終了の`sys.exit(0)`も`SCRIPT_FAILED`として扱われ、プログラムへの変更がロールバックされていた。非ゼロ・文字列で終了した場合も、結果に正しい終了コードを保持できていなかった。

[execution.py](../src/ghidra_headless/scripts/execution.py)を修正し、Jythonの公開`invoke` APIから属性を取得するようにした。数値はJavaクラスの継承関係で判別し、`PyLong`の大きな値も32ビットへ縮めず保持する。整数の0と文字列の`"0"`を区別する。PyGhidraの非公開APIを使う例外伝播パッチは変更していない。

### 修正後の結果

| 検証 | 成功 | スキップ | 時間 |
| --- | ---: | ---: | ---: |
| 実スクリプト・MCP通信の関連テスト | 23 | 0 | 51.72秒 |
| 通常の全テスト | 1,353 | 52 | 8.03秒 |

23件は`test_runtime_script_commands.py`の19件と`test_runtime_mcp_transport.py`の4件。通常テストの52件スキップは実機フラグ無効によるもので、上段の23件とは別の実行である。他の実機機能については初回の検証記録を参照。Ruff、フォーマット、`git diff --check`も成功した。

- Javaを先に実行していない状態でのJython子スクリプト呼び出しと繰り返し実行。
- 子の例外を親が捕捉した場合の変更保存、未捕捉の場合のロールバック。
- 通常実行での引数・出力・変更保存、例外時の変更取消。
- 協調的タイムアウトの検出・ロールバックと、その後のスクリプト実行。
- `sys.exit(None)`、整数0、`False`、`0L`の正常終了と変更保存。
- 非ゼロ整数、`True`、大きな`long`、文字列`"0"`・`"failure"`の異常終了と変更取消、終了コードの型・値の保持。
- PyGhidra／Jythonそれぞれをstdio／HTTP経由で実行。各組み合わせで21回のツール呼び出しを行い、インラインソース・子スクリプト・例外・正常／異常終了・大きな出力の取得・返却スキーマを検証。

再実行はJython拡張を導入した設定領域を指定し、次の両フラグを有効にする。この指定ではJythonが利用できなければ失敗となり、未導入のまま成功扱いにしない。

```bash
GHIDRA_RUNTIME_VALIDATION=1 \
GHIDRA_JYTHON_RUNTIME_VALIDATION=1 \
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra \
.venv/bin/python -m pytest -q -rA \
  tests/test_runtime_script_commands.py \
  tests/test_runtime_mcp_transport.py
```

追試の証跡は`/private/tmp/mecha-jython-validation-20260916/`に保存した。`runtime.log`／`runtime.xml`が修正後23件の結果、`offline.log`／`offline.xml`が通常テスト、`prepare.log`が拡張の導入先・ハッシュの記録。`system-exit.log`は修正前に3件の失敗を再現した記録であり、最終結果と区別する。

## 検証範囲の制限

Ghidra 12.1.3、Windows、Linux、Docker配布物、外部クラウドのクライアント、リバースプロキシ越しの認証・複数プロセス構成は今回の実機検証対象外。ここでの結果は上記macOS環境と現在のソースに対するものである。
