[English](troubleshooting.md) | [日本語](troubleshooting.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# トラブルシューティング・移行

ツールの失敗はMCPの `isError: true` で返します。ドメインエラーは `structuredContent.error` と同じ内容のJSONテキストに `code`、`message`、`retryable`、`hint`、`details` を保持します。処理の分岐には固定コードを使い、再試行前に部分的に完了した操作がないか `details` を確認してください。入力スキーマが受け付けない引数も `VALIDATION_ERROR` で、スキーマの示す理由を `structuredContent.error.message` に含みます。一括編集の項目別エラーは正常な応答内の `status` と `results` で確認します。大きな結果の取得は[別項目](configuration.ja.md#large-results)を参照してください。

## 起動・接続の問題

| 症状 | 確認・対応 |
| --- | --- |
| Ghidraが見つからない（`Ghidra installation directory does not exist` または `Failed to start the Ghidra JVM: ...`） | `GHIDRA_INSTALL_DIR` または `--ghidra-path` に展開先ルート（`Ghidra/application.properties` があるディレクトリ）を指定。stdioではクライアントの環境変数にも設定する。展開先の誤りは受付を始める前に見つかり、終了コード1で終わる。JDKが見つからないなどJVMの起動そのものの失敗は受付を始めた後に分かり、stdioではツール呼び出しが `STARTUP_FAILED` を返し、HTTPは終了コード1で終わる |
| 接続直後のツール呼び出しに時間がかかる | サーバーはGhidraの起動を待たずに受付を始め、ツール呼び出しだけが起動の完了を待つ。起動にかかった時間はログの `Ghidra ready in ...` で確認できる。`--lock-timeout-seconds` を過ぎても起動中なら `details.lock` が `startup` の `LOCK_TIMEOUT` が返るので、少し待ってから呼び直す |
| ネイティブデコンパイラがない・実行できない | OS・CPUに合う `decompile` と `sleigh` を追加。[配布物](usage.ja.md#native-decompiler-artifacts)を確認する |
| プロジェクトがロックされている・使用中 | ほかのプロセスで閉じるか、別の共有キャッシュを使う。有効なロックファイルを削除しない |
| プロジェクト名が不正 | `project_name` の `.gpr` を除く。または既存 `.gpr` パスを `project_location` に指定し、名前を省略する |
| 初回起動でプロジェクトがない | ディレクトリと名前で起動し、`create_project` を呼ぶ。[最初の解析](usage.ja.md#first-analysis)を参照 |
| プログラムが読み込まれていない（`PROGRAM_NOT_OPEN`） | `list_project_programs` と `load_project_program` を使う。ターゲット登録だけでは読み込まれない |
| HTTP接続できない | 接続方式、ホスト、ポート、`/mcp`、サーバーログを確認。旧 `/sse` エンドポイントは削除済み |
| ワイルドカード待ち受けでHost/Originが拒否される | 固定ホスト設定とクライアントの接続先を合わせる。[接続設定](configuration.ja.md#transports)を参照 |
| 長い呼び出しでクライアントがタイムアウト | どの呼び出しも約50秒を超えて待たせない。ジョブ（`import_program`・`analyze_program`・`run_script`）は`wait_seconds`以内に応答し、それ以外の呼び出しは40秒で終わらなければ`deferred: true`を返す。上限を延ばしたり呼び直したりせず、返された`operation_id`で`get_operation`を呼ぶ。50秒より短い期限では切れることがある（[長い呼び出し](usage.ja.md#long-calls)） |
| 読み込み後に関数がほとんど・まったくない | 読み込みでは解析しない。読み込みの応答が`is_analyzed: false`なら、`analyze_program`を実行してジョブの完了を待つ |
| 必要なツールが見えない | プロファイル、カテゴリ、個別の有効・無効指定を確認。起動引数変更後はクライアントの一覧を更新・再接続する |
| `--backend gui` が引数のエラーで起動しない | stdioでは使えないので `--transport http` を指定する。`--project-location` には既存のProjectが要る。Ghidra Serverの認証のオプションと、別のProjectを指す `--session` は指定できない（[GUIでのライブ共有](gui-live.ja.md#startup)） |
| `--backend gui` で `STARTUP_FAILED`（`details.stage` が `display`） | 画面を表示できる環境で起動する。macOSではログイン中のデスクトップが、Linuxでは応答するXのサーバーを指す `DISPLAY` が要る。GhidraのGUIを起動する前に確かめるので、画面は開かない |
| `--backend gui` で `STARTUP_FAILED`（`details.stage` が `project_lock`） | 別のGhidraかサーバーがそのProjectを開いている（`details.cause_type` は `PROJECT_LOCKED`）。そちらでProjectを閉じてから起動する。有効なロックファイルを削除しない |
| `--backend gui` の起動が進まない | `LOCK_TIMEOUT` の `details.modal_dialogs` にある画面（使用許諾など）が、人間の操作を待っている。GUIで答える。Mechaは代わりに答えない |
| `--backend gui` で、GUIは開いているのに呼び出しが `STARTUP_FAILED` を返し続ける | GUIが立ち上がった後の段階（`details.stage` が `project_open`、`code_browser`、`default_session` など）が失敗した。GUIは人間のために開いたまま残る。`message` で原因を確かめ、Ghidraを終えてから設定を直して起動し直す |

## ツールのエラー

| コード | 意味・次の操作 |
| --- | --- |
| `PATH_NOT_ALLOWED` | シンボリックリンク解決後も許可ルート内になるパスを使う |
| `NOT_FOUND` | `message`に書かれた関数・データ型・変数・データシンボル・ブックマーク・名前空間・リポジトリが存在しない。`hint`が、探すためのツール（`list_functions`、`list_data_types`、`list_namespaces`（または`create_namespace=true`）など）を示す |
| `VALIDATION_ERROR` | `message`が、どの引数をなぜ受け付けなかったかを示す（ファイルのパスは`<path>`と表示）。入力の形の誤り、解析できないCの宣言（`C_PARSE_FAILED`）、名前空間以外を通る名前空間のパス（`INVALID_NAMESPACE_TYPE`）、既にあるかディレクトリのない書き出し先（`EXPORT_TARGET_EXISTS`、`EXPORT_DIRECTORY_MISSING`）など。直して呼び直す |
| `PROGRAM_NOT_OPEN` | targetにプログラムが読み込まれていない。`list_project_programs`で探して`load_project_program`で読み込むか、`import_program`で追加する。`details.reason` が `closed_in_gui` なら、人間がGhidraのGUIでそのタブを閉じたので、`load_project_program`で読み込み直す |
| `TARGET_NOT_REGISTERED` | その名前のtargetはない。`list_targets`で一覧し、`register_target`で追加する |
| `STARTUP_FAILED` | 受付を始めた後の起動処理（JVMの起動、スクリプト実行環境の確認、Ghidra Server認証の設定、起動時のプログラムの読み込み）が失敗した。`details.stage` が失敗した段階、`message` が原因（ホストのパスは`<path>`と表示）で、サーバーログには行の全体がある。再試行では直らない。設定を直してサーバーを再起動する |
| `LOCK_TIMEOUT` | 別の呼び出しがターゲットを使用中、または `run_script` が実行中。`details.lock` が `startup` なら、Ghidraがまだ起動中なので、少し待ってから再試行する。バックグラウンドのジョブか先送りした呼び出しが使用中なら、`details.operation_id`でそれが分かる。`get_operation`で完了を待ってから再試行する。`cancel_operation`で終えたジョブは示さないが、そのワーカーは最大`--lock-timeout-seconds`の間ロックを持ち続けうるので、その後で再試行する。`create_project`も、バックグラウンドの取り込みなど他の操作の実行中はこれを返す（`details.lock`は`runtime`）。それらが終わってから再試行する。`details.script_state` でスクリプトが `running` か、待機中（`queued`、この場合は `retry_after_seconds` 後に再試行）かが分かる。`run_script`のジョブがこれで失敗することはなく、開始できるまで待ち続ける（`phase`は`waiting_for_lock`）。`--backend gui` では、`details.lock` が `program_transaction` なら別のtransaction（`details.transaction`、たとえば自動解析）が開いたままで、何も変えていない。`gui_event_thread` ならGUIのスレッドが応答せず、`details.modal_dialogs` に表示中の画面がある。どちらも、それが終わってから再試行する |
| `SCRIPT_RUNTIME_UNAVAILABLE` | providerの導入と起動時の例外伝播チェックのログを確認。チェック失敗時は全言語を使用不可にするため、[固定したPyGhidra依存](development.ja.md#pyghidraの依存バージョンとスクリプト失敗)を導入して再起動する。標準のPyGhidra 3.1.0はこのチェックに失敗する |
| `RAW_LOADER_OPTION_UNAVAILABLE` | 指定した言語・compiler・オプションに対するBinaryLoaderの公開メタデータを取得できなかった。指定値と対応Ghidraバージョンを確認する。`details.cause_message`がそのオプションを示す |
| `AMBIGUOUS_FUNCTION`、`AMBIGUOUS_DATA_TYPE` | `details.candidates` を確認し、関数アドレス・完全修飾名、または型の完全パスを指定する |
| `SESSION_CHANGED` | 最新状態を読み直し、ページ取得や編集の `revision` を更新する。解析やスクリプトのジョブが返した場合は、開始前にターゲットの再読み込み・クローズ・別プログラムの読み込みがあり、何も実行していない。投入し直す |
| `BSIM_MATCH_STALE` | 開いたプログラムのMD5・パス・関数エントリが参照と一致しない。元のプログラムと検索結果を確認する |
| `PROGRAM_NOT_ANALYZED` | ローカル変数名・型の操作前に `analyze_program` を実行する |
| `CHECKOUT_REQUIRED` | バージョン管理された共有ファイルをチェックアウトする |
| `CHECKOUT_UNAVAILABLE` | リポジトリの状態を確認。別ユーザーが排他的チェックアウトを保持している可能性がある |
| `READ_ONLY_PROGRAM` | 過去バージョンを読み込み中。編集するには現在のファイルを開く |
| `MERGE_REQUIRED` | [競合時の手順](shared-projects.ja.md#conflicts)に従う。ヘッドレスのマージは非対応 |
| `JVM_NOT_HEADLESS`、`HEADLESS_UNSUPPORTED` | [JVM起動ルール](development.ja.md)を確認。表示が必要なAPIをheadlessで再試行しない |
| `GUI_UNSUPPORTED` | GUIのバックエンドが扱わない操作か引数で、何も変えていない。`details.reason` が理由（`dry_run`、`edit_kind_decompiles`、`version`、`discard_changes`、`other_project`、`foreign_undo`、`foreign_redo`、`import`、`version_control`、`delete_file`、`remove_program`）。`hint` の代わりの方法を使うか、GhidraのGUIで行う（[使えない機能](gui-live.ja.md#limits)） |
| `GUI_NAVIGATION_FAILED` | `show_in_gui` がProgramを表示したが、指定の位置へ移動できなかった。アドレスか名前を確かめて呼び直す |
| `SESSION_NOT_FOUND`（`details.reason` が `gui_project_closed`） | 人間がGhidraのGUIでこのサーバーのProjectを閉じたか、別のProjectを開いた。同じProjectを開き直しても、このサーバーは戻らない。Ghidraを終えてから、サーバーを起動し直す |
| `BSIM_URL_REQUIRED`、`BSIM_URL_INVALID` | 対応するBSim URLを指定する |
| `BSIM_AUTHENTICATION_FAILED`、`BSIM_DATABASE_UNREACHABLE` | バックエンドの認証情報と到達性を確認する。データベース自身の報告で判定する。ログインを拒否されたなら`BSIM_AUTHENTICATION_FAILED`で、再試行しても直らない。データベースに届かない場合は再試行可能で、読み取り専用のBSimのツールはそのまま呼び直せる。書き込みは`output_state`が`absent`のときに再試行する |
| `BSIM_DATABASE_INIT_FAILED` | データベースが存在しない、別のプロセスがH2のファイルを使っているなど、接続やログイン以外の理由でBSimのデータベースを開けなかった。`message`にデータベース自身の報告がある。作成するか解放する（[BSimの運用](bsim-operations.md)）。書き込みは`output_state: absent`を返す |
| `IMPORT_IN_PROGRESS` | 別の取り込みが同じ名前のプログラムを書き込み中。`details.operation_id`を`get_operation`で確認する。`retryable`がtrueなら、その取り込みは取り消し中なので、終わってから送り直す |
| `ANALYSIS_IN_PROGRESS` | 同じプログラムに、引数の異なる別の解析のジョブが待機中・実行中。`details.operation_id`を`get_operation`で確認する |
| `IMPORT_OUTPUT_UNCERTAIN` | 同じ名前の以前の取り込みが、後始末を確認できないまま失敗している。`details.operation_id`とプロジェクトを確認する（`details.output_state`は`uncertain`）。このサーバープロセスは再起動までその名前を受け付けない |
| `OPERATION_QUEUE_FULL` | 待機中のジョブが16件ある、またはツール呼び出しの実行枠40件が40秒間すべて使用中だった。何も受け付けず、実行もしていないので、時間をおいて再試行する（`request_id`付きの呼び出しは同じIDで送り直せる） |
| `REQUEST_ID_CONFLICT` | その`request_id`は、別の引数で送った以前のジョブかツールの呼び出しを指している。意図した引数で送り直すか、新しいUUIDを使う |
| `RESULT_DISCARDED` | 再送した呼び出しの最初の実行は成功したが、サーバーのメモリを抑えるためにその返答を捨てた（`details.output_state`は`uncertain`）。呼び出しを送り直さず、変わった内容はプログラムで確かめる。最初の実行が失敗した、または実行されなかった場合は、代わりにそのエラーが返る |
| `OPERATION_NOT_FOUND` | このサーバープロセスにジョブの記録がない（再起動した、または後続のジョブが4,096件を超えて記録が消えた）。プロジェクトを確認してから、ジョブを投入し直す |
| `TARGET_REBOUND` | 受付後にtargetが別のプロジェクトへ登録し直された。何も書き込んでいないので、取り込み直す |
| `OPERATION_CANCELLED` | `cancel_operation`がジョブを止めた。何が残ったかは`details.output_state`で分かる（開始前に止めた場合と巻き戻した場合は`absent`） |
| `OPERATION_SHUTDOWN`、`OPERATION_WORKER_UNAVAILABLE`、`OPERATION_WORKER_FAILED` | サーバーの停止中、またはジョブ用workerの障害。`details.output_state`とサーバーログを確認し、サーバーを再起動する |
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

### バックグラウンドのジョブと読み込み

- `import_program`と`analyze_program`はバックグラウンドのジョブとして実行され、ジョブの記録を返します。`state`が`queued`または`running`の間は`get_operation`を呼びます。これまでの結果は`result`に入ります（取り込みでは`result.program`）。[利用方法](usage.ja.md#saving-and-analysis)を参照してください。
- `import_program`は、形式を問わず既定で解析します。省く場合は`analyze_imported=false`を指定します。
- 読み込みでは解析しません。`load_project_program`と`open_program`は`is_analyzed`を返します。`false`なら`analyze_program`を実行します。解析の結果は`save_project_program`まで保存されません。
- `analyze_program`は`target`が必須になりました。
- ジョブに伴い、次のエラーコードが加わりました。`OPERATION_QUEUE_FULL`、`OPERATION_SHUTDOWN`、`OPERATION_WORKER_UNAVAILABLE`、`OPERATION_WORKER_FAILED`、`OPERATION_NOT_FOUND`、`REQUEST_ID_CONFLICT`、`IMPORT_IN_PROGRESS`、`IMPORT_OUTPUT_UNCERTAIN`、`TARGET_REBOUND`、`ANALYSIS_IN_PROGRESS`（上の表を参照）。実行中のジョブが原因の`LOCK_TIMEOUT`は、`details.operation_id`でそのジョブを示します。
- Docker Composeは停止に120秒まで待ちます（`stop_grace_period`）。キャンセルした解析を巻き戻す時間を確保するためです。
- `run_script`もバックグラウンドのジョブになり、ジョブの記録を返します。スクリプトの結果は`result`に、失敗は`details.output_state`付きの`operation_error`に入ります。待機中・実行中に同じ引数で再送すると、同じジョブを返します。
- それ以外の呼び出しも、40秒で終わらなければ`deferred: true`とジョブの記録を返し、処理を続けます。結果は`get_operation`で受け取ります。そのため、`get_operation`の記録の`kind`には任意のツール名が、`result`には任意のJSONが入ります（[長い呼び出し](usage.ja.md#long-calls)）。
- 待機中・実行中のジョブを取り消す`cancel_operation`を加えました（`OPERATION_CANCELLED`）。
- `list_targets`はターゲットのロックを待たなくなり、ジョブの実行中でもすぐに返ります。
- SIGINTとSIGHUPでも、SIGTERMと同じように止まります。実行中のジョブを取り消して巻き戻し、プロジェクトを閉じて、終了コード130または129で終わります。これまでは、SIGINTではstdioのサーバーが終わらないか後始末なしで終わり、SIGHUPや、JVMの起動中に届いたこれらのシグナルでは後始末なしで終わっていました。
- BSimのツールは、失敗を`error.code`（メッセージの先頭にある`BSIM_...`の名前）と`retryable`で返します。`retryable`がtrueになるのは`BSIM_DATABASE_UNREACHABLE`だけです。一部のコードには`hint`も付きます。メッセージの文言は変わりません。ただし、接続やログイン以外の理由でデータベースを開けなかった場合は、どのBSimのツールでも`BSIM_DATABASE_INIT_FAILED`になります（これまでは`BSIM_LIST_EXECUTABLES_FAILED`などツールごとのコード）。これまではコードが文言の中にしかありませんでした。
- すべてのツールが、ヒントをすべて宣言します。書き込みのツールは`readOnlyHint: false`です。`destructiveHint`は削除・バイトの上書き・リポジトリ操作・スクリプトがtrue、`openWorldHint`はBSim・共有プロジェクト・スクリプトのツールだけがtrueです。これらのヒントで確認を出すかを決めるクライアントでは、通常の編集で確認が減ることがあります。
- プログラムへの書き込みと`bsim_apply_matches`が、どれも`request_id`を受け付けます。同じ`request_id`で送り直すと、再び適用せずに、`replayed: true`を付けた最初の応答を返します（[一括の注釈](tools.ja.md#symbol-comment-edit)）。何も変えずに失敗した書き込み（`output_state: absent`）は、取り消したものを除き、その`request_id`を保たないので、同じIDで送り直せば実行されます。
- 失敗した書き込みは`error.details.output_state`（`absent`・`created`・`uncertain`）を返します。`retryable`がtrueになるのは、何も残っていないときだけです。プロジェクトやリポジトリへの書き込みでは、変更の前に断るエラーなら`absent`、それ以外は`uncertain`です。Ghidraの起動中、入力スキーマの検査、別の引数で使われた`request_id`（`REQUEST_ID_CONFLICT`）のいずれかで断った書き込みと、サーバーが受け付けなかったジョブは`absent`です。`IMPORT_OUTPUT_UNCERTAIN`で断った取り込みは`uncertain`です。`cancel_operation`がジョブの取り消しを断るときは、そのジョブが実行済みでありうるので、何も返しません。最初の実行が成功した後に返答を捨てた再送は`RESULT_DISCARDED`で失敗し、最初の実行が失敗して`request_id`を保っていれば、そのエラーがもう一度返ります。これまではどちらのエラーにも`message`しかありませんでした。
- エラーが詳しくなりました。関数・データ型・変数・ブックマークが見つからなければ`NOT_FOUND`（これまでは`OPERATION_FAILED`）、プログラムを読み込んでいないtargetは`PROGRAM_NOT_OPEN`、存在しないtargetは`TARGET_NOT_REGISTERED`（どちらもこれまでは`SESSION_NOT_FOUND`）です。`NOT_FOUND`と`VALIDATION_ERROR`のメッセージは理由を残します（これまでは固定の文に置き換わっていました）。`hint`は`Check runtime state`ではなく、次に呼ぶツールを示します。Ghidraの中で起きたJavaの例外（NullPointerExceptionなど）は、`VALIDATION_ERROR`ではなく`OPERATION_FAILED`になります。`PROGRAM_NOT_ANALYZED`と`RAW_LOADER_OPTION_UNAVAILABLE`は、それぞれ独立したコードになりました（これまでは`OPERATION_FAILED`と`IMPORT_FAILED`）。原因は`details.cause_message`にあります。入力スキーマが受け付けない引数のエラーにも、`code`（`VALIDATION_ERROR`）と`hint`が付きます。これまでは`message`だけでした。
- 応答の文字列ブロックは詰めたJSONになりました。リストは、1項目ずつ字下げした複数のブロックではなく、1行に1項目の1つのブロックです。`structuredContent`は変わりません。
- BSimの書き込みの失敗も、ほかの書き込みと同じく`error.details.output_state`を示します。`bsim_register_target`と`bsim_update_target_signatures`は、データベースへの書き込みを始めた後の失敗なら`uncertain`です。`BSIM_DATABASE_UNREACHABLE`が再試行可能なのは何も残っていないときだけで、データベースがログインを拒否したなら`BSIM_AUTHENTICATION_FAILED`です。
- 公開のコードを持つヘッドレス側のコードが増えました。`NAMESPACE_NOT_FOUND`と`REPOSITORY_NOT_FOUND`は`NOT_FOUND`、`C_PARSE_FAILED`・`INVALID_NAMESPACE_TYPE`・`EXPORT_TARGET_EXISTS`・`EXPORT_DIRECTORY_MISSING`は`VALIDATION_ERROR`です（以前はどれも`OPERATION_FAILED`）。`apply_edits`と`batch_read`の項目は、それぞれのコードのままです。Ghidra内部で失敗した`batch_read`の項目は、`VALIDATION_ERROR`ではなく`OPERATION_FAILED`です。
- 再送で返すエラーは1つの文字列ブロックのままで、そのJSONに`replayed: true`が入ります。保存した結果の通知は2つのブロックのままです。以前はどちらにも文字列ブロックが1つ増えていました。
- `batch_read`の応答には`source`が付かなくなりました。バッチ自身が`program`と`revision`を示します。先送りした呼び出しの記録は、`result`の横に`source`を持つようになりました。
- 実行枠40件が40秒間すべて使用中だった呼び出しは、際限なく待たずに再試行可能な`OPERATION_QUEUE_FULL`になります。Ghidraの起動中に届いた呼び出しが待つのも最大40秒です。
- ジョブのツールを公開すると、明示的に無効にしない限り`cancel_operation`も公開します。以前はタグでの絞り込みで、`cancel_operation`なしに`run_script`を公開することがありました。
- `open_program`と、ターゲットが既に持つプログラムを読み直した`load_project_program`の`is_analyzed`は、フラグを読めなかった場合に`null`になります。新しく読み込む`load_project_program`でフラグを読めなければ、読み込みを巻き戻して失敗します。`import_program`は`analyze_imported: null`を既定値（`true`）として受け付けます。
- `STARTUP_FAILED`の原因は、ほかの原因と同じく、ホストのパスを`<path>`と表示します。
- `decompile_function`の疑似コードの先頭に、関数の名前とエントリーアドレスを書いたコメントの行（例：`/* entry @ 00401e46 */`）が入ります。
- プログラムを扱うツールの応答は、`structuredContent`の`result`の隣と最後の文字列ブロックに`source`（`target`・`program`・`revision`）を載せます。`structuredContent`を`{"result": ...}`と完全一致で比べているクライアントは、キーが増えることに対応してください。
- `tools/list`の大きさが約半分になりました。各ツールの出力スキーマは、ツール固有の結果の形は完全に示し、全ツールに共通する応答（保存した大きな結果の通知、先送りの応答、エラー）は短い形だけにしました。それらの完全な形は`ghidra://docs/tools/{tool_name}`にあります。応答そのものは変わらず、どちらの形でも検証を通ります。
- JVMは`-Xrs`で起動し、これらのシグナルをサーバーに任せます。`kill -3`（SIGQUIT）では、Javaのスレッドダンプの代わりにPythonのスレッドのスタックを出します。Javaのスレッドは`jcmd <pid> Thread.print`で見られます。

## 問題を報告する

[GitHub Issues](https://github.com/ghidra-user-jp/mecha_ghidra/issues)には、gitリビジョンまたはパッケージバージョン、OS・CPU、GhidraとJavaのバージョン、接続方式、秘匿情報を除いた起動引数、ツール名と引数、エラーコード、最小の再現手順を記載してください。サーバー・ツールのエラーとクライアントのタイムアウトを区別し、パスワードや非公開の検体情報を含めずに関連ログを添えます。
