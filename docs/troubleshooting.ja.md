[English](troubleshooting.md) | [日本語](troubleshooting.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# トラブルシューティング・移行

ツールの失敗はMCPの `isError: true` で返します。ドメインエラーは `structuredContent.error` と同じ内容のJSONテキストに `code`、`message`、`retryable`、`hint`、`details` を保持します。処理の分岐には固定コードを使い、再試行前に部分的に完了した操作がないか `details` を確認してください。引数検証のエラーにも `structuredContent.error.message` を含みます。一括編集の項目別エラーは正常な応答内の `status` と `results` で確認します。大きな結果の取得は[別項目](configuration.ja.md#large-results)を参照してください。

## 起動・接続の問題

| 症状 | 確認・対応 |
| --- | --- |
| Ghidraが見つからない（`Ghidra installation directory does not exist` または `Failed to start the Ghidra JVM: ...`、終了コード1） | `GHIDRA_INSTALL_DIR` または `--ghidra-path` に展開先ルート（`Ghidra/application.properties` があるディレクトリ）を指定。stdioではクライアントの環境変数にも設定する |
| ネイティブデコンパイラがない・実行できない | OS・CPUに合う `decompile` と `sleigh` を追加。[配布物](usage.ja.md#native-decompiler-artifacts)を確認する |
| プロジェクトがロックされている・使用中 | ほかのプロセスで閉じるか、別の共有キャッシュを使う。有効なロックファイルを削除しない |
| プロジェクト名が不正 | `project_name` の `.gpr` を除く。または既存 `.gpr` パスを `project_location` に指定し、名前を省略する |
| 初回起動でプロジェクトがない | ディレクトリと名前で起動し、`create_project` を呼ぶ。[最初の解析](usage.ja.md#first-analysis)を参照 |
| プログラムが読み込まれていない | `list_project_programs` と `load_project_program` を使う。ターゲット登録だけでは読み込まれない |
| HTTP接続できない | 接続方式、ホスト、ポート、`/mcp`、サーバーログを確認。旧 `/sse` エンドポイントは削除済み |
| ワイルドカード待ち受けでHost/Originが拒否される | 固定ホスト設定とクライアントの接続先を合わせる。[接続設定](configuration.ja.md#transports)を参照 |
| インポート・解析中にクライアントがタイムアウト | クライアント側の実行時間上限を調整。サーバーのロック時間は待機時間だけを制限する |
| 必要なツールが見えない | プロファイル、カテゴリ、個別の有効・無効指定を確認。起動引数変更後はクライアントの一覧を更新・再接続する |

## ツールのエラー

| コード | 意味・次の操作 |
| --- | --- |
| `PATH_NOT_ALLOWED` | シンボリックリンク解決後も許可ルート内になるパスを使う |
| `LOCK_TIMEOUT` | 別の呼び出しがターゲットを使用中、または `run_script` が実行中。`details.script_state` でスクリプトが `running` か、待機中（`queued`、この場合は `retry_after_seconds` 後に再試行）かが分かる。`run_script` 自身が返す場合は、`details.active_readers` 件の操作を `--script-queue-timeout-seconds` だけ待っても開始できなかったことを示し、スクリプトは実行されていない |
| `SCRIPT_RUNTIME_UNAVAILABLE` | providerの導入と起動時の例外伝播チェックのログを確認。チェック失敗時は全言語を使用不可にするため、[固定したPyGhidra依存](development.ja.md#pyghidraの依存バージョンとスクリプト失敗)を導入して再起動する。標準のPyGhidra 3.1.0はこのチェックに失敗する |
| `RAW_LOADER_OPTION_UNAVAILABLE` | 指定した言語・compiler・オプションに対するBinaryLoaderの公開メタデータを取得できなかった。指定値と対応Ghidraバージョンを確認する |
| `AMBIGUOUS_FUNCTION`、`AMBIGUOUS_DATA_TYPE` | `details.candidates` を確認し、関数アドレス・完全修飾名、または型の完全パスを指定する |
| `SESSION_CHANGED` | 最新状態を読み直し、ページ取得や編集の `revision` を更新する |
| `BSIM_MATCH_STALE` | 開いたプログラムのMD5・パス・関数エントリが参照と一致しない。元のプログラムと検索結果を確認する |
| `PROGRAM_NOT_ANALYZED` | ローカル変数名・型の操作前に `analyze_program` を実行する |
| `CHECKOUT_REQUIRED` | バージョン管理された共有ファイルをチェックアウトする |
| `CHECKOUT_UNAVAILABLE` | リポジトリの状態を確認。別ユーザーが排他的チェックアウトを保持している可能性がある |
| `READ_ONLY_PROGRAM` | 過去バージョンを読み込み中。編集するには現在のファイルを開く |
| `MERGE_REQUIRED`、`UNSAFE_MERGE_REQUIRED` | [競合時の手順](shared-projects.ja.md#conflicts)に従う。ヘッドレスのマージは非対応 |
| `JVM_NOT_HEADLESS`、`HEADLESS_UNSUPPORTED` | [JVM起動ルール](development.ja.md)を確認。表示が必要なAPIをheadlessで再試行しない |
| `BSIM_URL_REQUIRED`、`BSIM_URL_INVALID` | 対応するBSim URLを指定する |
| `BSIM_AUTHENTICATION_FAILED`、`BSIM_DATABASE_UNREACHABLE` | バックエンドの認証情報と到達性を確認する |
| `BSIM_PARAMETER_INVALID`、`BSIM_INVALID_MATCHED_REF` | スキーマの範囲内の引数と、改変していない検索結果の参照を使う |
| `BSIM_ALREADY_REGISTERED` | 既存レコードを更新するか、明示的に削除してから再登録する |
| `BSIM_EXECUTABLE_CATEGORY_NOT_CONFIGURED` | 先にカテゴリを追加し、大小文字も一致させる |

ツールごとの全エラーと引数は `ghidra://docs/tools/{tool_name}` にあります。PostgreSQLのビルド・起動・一括登録の問題は[BSim運用保守](bsim-operations.md)を参照してください。

<a id="upgrading"></a>

## 古い設定からの移行

Python配布パッケージ名と起動コマンドを、リポジトリ名・MCP登録名と同じ `mecha_ghidra` に統一しました。チェックアウトの更新後に `uv sync` で新しい名前のパッケージを導入し、`uv run mecha_ghidra` で起動してください。既存の起動コマンドやMCPクライアント設定では、引数をそのままに `ghidra-mcp` を `mecha_ghidra` へ置き換えます。旧コマンドは提供しません。

Docker Composeのサービス名は `mecha_ghidra`、既定のイメージ名は `mecha_ghidra:local` です。既存のDocker環境を更新する場合は、設定の更新前に旧設定で `docker compose down` を実行し、`-v` は付けず、その後[Dockerガイド](docker.ja.md)に沿って再ビルド・起動してください。既存の `ghidra-projects` ボリュームを再利用するため、チェックアウトのディレクトリとComposeプロジェクト名は維持します。

バージョン0.1.5ではGhidra 12.1.3と対応するネイティブファイルを追加しました。[適切な配布物](usage.ja.md#native-decompiler-artifacts)を選び、古い呼び出しを以下に置き換えてください。

| 旧名・旧オプション | 置き換え先 |
| --- | --- |
| `--enable-shared-project-sync` | `--add-category shared_sync` |
| `search_functions_by_name` | `list_functions(filter=...)` |
| `list_classes` | `list_namespaces(classes_only=true)` |
| `reanalyze_program` | `analyze_program(force=true)` |
| `set_decompiler_comment` | `apply_edits`：`kind="set_comment", comment_type="pre"` |
| `set_disassembly_comment` | `apply_edits`：`kind="set_comment", comment_type="eol"` |
| `clear_struct` | `remove_struct_members(clear_all=true)` |
| `delete_struct` | `delete_data_type` |
| `reload_project_program` | 保持中のdomain pathを `load_project_program` で読み込む。`reloaded=true` を確認 |
| `list_bsim_categories` | `get_bsim_database_status` の `categories` と `function_tags` |
| `bsim_set_target_metadata` | 登録時に `bsim_register_target(categories=...)` を使う |
| `add_bookmark(format=...)` | 未使用の `format` 引数を削除 |

### 応答と動作の変更

- `get_function` はシグネチャ、引数、ローカル変数を返します。`list_imports`、`list_exports`、`list_namespaces`、`get_call_edges` は文字列ではなくオブジェクトを返し、相互参照には相手側の関数も含みます。
- `set_function_prototype`、`set_local_variable_type` は関数アドレスと名前の両方に対応します。`search_bytes` は `??` ワイルドカード、`list_strings.filter` は大小文字を区別しない検索に対応します。
- チェックアウトの `exclusive` 省略時はサーバー設定に従います。コミットに `on_conflict="keep"`、差分に `include_details` を追加し、BSim検索では既定で自己一致を除きます。
- 解析・編集ではプログラム情報、undo/redo、エクスポート、コメント取得、シンボル検索、ラベル作成、列挙体編集、C宣言の取り込みを追加しました。BSimでは一致名の適用、シグネチャ・名前の更新、実行ファイル削除を追加しています。[ツール一覧](tools.ja.md)を参照してください。
- `pull_project_program` の出力定義に `checked_out` を追加し、pull成功後の出力検証エラーを防ぎます。BSimの重複登録は `BSIM_ALREADY_REGISTERED`、排他的チェックアウトによる拒否は `CHECKOUT_UNAVAILABLE` を返します。
- 競合時の方針やclear modeをスキーマの列挙値にし、数値の範囲も公開しています。更新後はクライアントがキャッシュしたスキーマを再取得してください。

バージョン0.1.4ではMCP 2.x（`mcp>=2.1.1,<3`）とワーカースレッドでのツール実行へ移行しました。実行環境を変更する場合は[開発ガイドの検証](development.ja.md)に従ってください。

## 問題を報告する

[GitHub Issues](https://github.com/ghidra-user-jp/mecha_ghidra/issues)には、gitリビジョンまたはパッケージバージョン、OS・CPU、GhidraとJavaのバージョン、接続方式、秘匿情報を除いた起動引数、ツール名と引数、エラーコード、最小の再現手順を記載してください。サーバー・ツールのエラーとクライアントのタイムアウトを区別し、パスワードや非公開の検体情報を含めずに関連ログを添えます。
