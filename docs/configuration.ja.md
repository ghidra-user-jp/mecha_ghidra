[English](configuration.md) | [日本語](configuration.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# 設定

サーバーの設定は `uv run mecha_ghidra` の引数で指定します。全オプションは `uv run mecha_ghidra --help` で確認できます。このページでは[接続方式](#transports)、[ターゲット](#targets)、[ファイルアクセス](#file-access)、[ツール公開範囲](#tool-exposure)、[大きな結果](#large-results)を説明します。

<a id="transports"></a>

## 接続方式と認証

| オプション | 既定値 | 用途 |
| --- | --- | --- |
| `--transport` | `stdio` | `stdio`、`http`（別名 `streamable-http`） |
| `--mcp-host` | `127.0.0.1` | HTTPの待ち受けアドレス |
| `--mcp-port` | `8081` | HTTPのポート |
| `--mcp-path` | `/mcp` | Streamable HTTPのエンドポイントパス |
| `--ghidra-path` | `GHIDRA_INSTALL_DIR` | Ghidraのインストール先 |
| `--log-level` | `INFO` | サーバーのログレベル |

Streamable HTTP（`--transport http` または `streamable-http`）は、[公式Python SDKの推奨設定](https://github.com/modelcontextprotocol/python-sdk/blob/main/examples/snippets/servers/streamable_config.py)に合わせて `stateless_http=True`、`json_response=True` に固定しています。MCPのセッションIDを発行せず、各要求にJSONで応答します。ステートフルに戻す互換設定はありません。Ghidraのターゲット・プログラムの変更状態・結果キャッシュはHTTP要求をまたいでサーバープロセス内に保持します。`--session` はGhidraのターゲット設定であり、HTTPセッションとは別です。同じ `target` と返された `result_id` を使って処理を続けてください。再起動すると結果キャッシュは消え、稼働中も既存の容量制限が適用されます。

HTTPは最終結果をJSONで返し、SSEによる進捗・keepaliveイベントは送りません。解析時間に合わせてクライアントとリバースプロキシのタイムアウトを設定してください。応答が失われても変更処理は完了している可能性があるため、変更操作を再試行する前に状態を確認します。通信のステートレス化によって、複数プロセス間でGhidraの状態や結果キャッシュが共有されるわけではありません。

ローカルHTTPでは[アクセス先を制限した起動例](usage.ja.md#local-setup)を使ってください。MCPエンドポイントにクライアント認証機能は組み込まれていません。Ghidra ServerとBSimのパスワードは各バックエンドの認証用であり、MCPクライアントの認証には使われません。

`0.0.0.0` や `::` で待ち受けてもDNSリバインディング対策は有効で、既定ではループバックのHost/Originだけを受け付けます。リモート接続を構成する場合は、クライアントが使うHostに一致する固定IP・ホスト名で待ち受け、TLS、認証、アクセス制御を配備側で用意してください。Dockerの既定設定はホストのループバックにだけポートを公開します。

stdioでは、Ghidraの出力がJSON-RPCへ混入しないように、起動後のJVM `System.out` を標準エラーへ向けます。

<a id="targets"></a>

## ターゲットと同時呼び出し

`--project-location`、必要に応じた `--project-name`、`--target-name`（既定値 `default`）で初期ターゲットを指定します。`--domain-path /folder/program` を付けると起動時にプログラムを開き、省略するとプロジェクト情報だけを登録します。起動にはプロジェクト指定または `--session` が1つ以上必要です。

起動時に複数のターゲットを登録するには、`--session` を繰り返します。以下は既存プロジェクトを使う例です。

```bash
uv run mecha_ghidra \
  --session 'name=sample,project_location=/work/sample.gpr,domain_path=/sample.bin' \
  --session 'name=reference,project_location=/work/reference.gpr,domain_path=/reference.bin' \
  --transport stdio
```

セッション定義はJSONではなく、カンマ区切りの `key=value` です。値にはカンマを使えません。キーは `name`、`project_location`、任意の `project_name` と `domain_path` です。パスの違いは[プロジェクトの基本](usage.ja.md#project-concepts)を参照してください。

`--lock-timeout-seconds` の既定値は `30` です。使用中のターゲットに対する呼び出しはロックを待ち、待機時間を超えると再試行可能な `LOCK_TIMEOUT` を返します。これは待ち行列での制限であり、解析処理の実行時間制限ではありません。MCPクライアントのタイムアウトは別途設定します。`run_script` の実行中も同じ待機時間が適用されます。スクリプトはプロセス全体のバリアを保持するため、待機時間内に入れなかった他の呼び出しはスクリプトの完了を待たずに再試行可能な `LOCK_TIMEOUT`（`details` に `script_state` と `waited_seconds` を含む）を返し、終了処理もこの時間を超えるとスクリプトを待たずに進みます。スクリプトが実行中の操作の後ろで待機しているだけの間は、他の呼び出しが止められるのは一度に約1秒までです（どのターゲットかを問わず長い読み取りがあれば新しい読み取りは通過します）。待機中のスクリプトがサーバー全体を止めることはありません。

`--script-queue-timeout-seconds` の既定値は `300` です。`run_script` が実行中の操作の完了を待つ時間で、時間内に開始できなかった実行は、スクリプトを実行せずに再試行可能な `LOCK_TIMEOUT` を返します。要求されたスクリプト実行は30秒で失敗するより実行中の解析を待つべきなので、`--lock-timeout-seconds` とは別に設定します。

<a id="file-access"></a>

## ファイルアクセス

パスはサーバーのファイルシステムを指します。Dockerではコンテナ内のパスを使います。

| オプション（複数指定可） | 制御する対象 |
| --- | --- |
| `--allowed-import-root DIR` | `import_program` が読み込むファイル |
| `--allowed-project-root DIR` | プロジェクト／セッション操作による作成・読み込み先。BSimのリモートキャッシュも含む |
| `--allowed-export-root DIR` | `export_program` の書き出し先 |

シンボリックリンクを含めてパスを解決してから検証します。エクスポートでは正規化・検証したパスをそのまま書き込み処理へ渡します。設定範囲外は `PATH_NOT_ALLOWED` になります。指定を省略した種類の操作は、このパスポリシーでは制限されません。OSのファイル権限は引き続き適用されます。

HTTPでは3種類とも指定してください。起動時の警告は**3種類とも未設定の場合だけ**に出るため、警告がないことは全操作の制限を意味しません。これらはパスの制御であり、完全なサンドボックスではありません。

<a id="tool-exposure"></a>

## ツールの公開範囲

| プロファイル | 公開するツール |
| --- | --- |
| `default` | `core`、`function_analysis`、`memory_data`、`symbol_comment_edit`、`datatype_ops` |
| `readonly` | defaultのカテゴリから、安全性タグが `read_only` のツールだけ |
| `full` | `shared_sync` と `bsim` を含む全カテゴリ |

指定がなければ `default` です。任意カテゴリは `--add-category shared_sync`、`--add-category bsim` で追加します。

`readonly` は公開するツールを絞る設定です。プロジェクトの読み取り専用マウントや、読み込み時の解析・保存の禁止は行いません。不変の過去バージョンを調べる場合は、[共有プロジェクトの履歴確認](shared-projects.ja.md#history)を使ってください。

各ツールは3種類のタグを持ちます。

| タグ | 値 |
| --- | --- |
| `category` | 上記 7 カテゴリと `scripts`（[スクリプト実行](#scripts)参照） |
| `safety` | `read_only`、`write`、`destructive_write` |
| `operation_level` | `basic`、`standard`、`advanced` |

適用順序は以下のとおりです。

1. プロファイルを選びます。`--allow-category` はカテゴリを置き換え、`--add-category` は追加します。
2. `--allow-safety` と `--allow-operation-level` で絞ります。同じ種類のallow指定はOR、異なるタグの指定はANDです。
3. `--enable-tool` でツールを個別追加します。
4. 最後に `--disable-tool` で除外します。無効化が常に優先されます。

通常の起動コマンドに、目的に応じて以下を追加します。

| 目的 | 追加する引数 |
| --- | --- |
| 既定ツールに共有操作を追加 | `--add-category shared_sync` |
| 全カテゴリの読み取りツールだけを公開 | `--tool-profile full --allow-safety read_only` |
| readonlyに名前・型・コメント編集を追加 | `--tool-profile readonly --enable-tool apply_edits` |
| バイト書き換えを除外 | `--disable-tool set_bytes` |

正確な引数とエラーコードは `tools/list`、MCPリソースの `ghidra://docs/tools` と `ghidra://docs/tools/{tool_name}` で確認できます。概要は[ツール一覧](tools.ja.md)、削除済みの `--enable-shared-project-sync` については[移行手順](troubleshooting.ja.md#upgrading)を参照してください。

`tools/list` は公開する全ツールの `inputSchema` と `outputSchema` を返します。通常の結果と `read_result`／`search_result`／`batch_read` のデータは `structuredContent.result` に入り、`content` にも従来のテキストを返します。通常結果が配列・文字列・nullでも、この形は共通です。通常ツールの圧縮結果の `result_id` などの参照情報と `error` は、引き続き `structuredContent` の直下に置きます。`batch_read` の参照情報はバッチデータ内の `structuredContent.result` に含みます。出力スキーマはこれらの応答形式を含み、送信前に検証します。ツールドキュメントの `output_schema` は論理値、`structured_output_schema` は送信する構造化出力のスキーマです。

取得ツールの応答上限 `max(threshold, 1024)` は、`content` と `structuredContent` の両方を含むツール応答を対象とします。SDKが付けるサーバー情報やJSON-RPCの外側の情報は含みません。構造化出力も収めるため、1回で取得できる文字数・件数は従来より少なくなる場合があります。一方 `batch_read` の `max_output_chars` は[ツール一覧](tools.ja.md#batch-read)のとおり、応答JSONテキスト（`structuredContent` が複製する `content` のテキスト）のみを対象とします。`has_more`／`next_offset_chars`／`next_cursor` で続きを取得してください。

<a id="scripts"></a>

## スクリプト実行

Ghidra スクリプト（Java、Jython、PyGhidra）はサーバープロセスの OS 権限で動く任意コードです。`scripts` ツールの公開は他のカテゴリと同じ仕組みで決まります（`--tool-profile full`、または他のプロファイルに `--add-category scripts` を足す。既定と readonly のプロファイルには含まれません）。

`run_script` はスクリプト本文（`source`）を直接受け取るので、AI アシスタントなどのクライアントがスクリプトを書いて実行し、診断を読んで書き直す使い方ができます。スクリプトは Ghidra の Script Manager と同じようにサーバー JVM 内で読み込み中のプログラムに対して実行され、トランザクションで包まれます。成功すれば変更はコミットされ、例外やタイムアウトならロールバックされます。結果にはトランザクション終了後に読み取った `transaction_outcome`（`committed` / `unchanged` / `rolled_back` / `unknown`）、捕捉した `stdout` / `stderr`、Java ならコンパイル診断が付きます。トランザクションを開いたまま返す、処理を走らせたまま返すスクリプトはプログラム状態を検証不能にするため、ターゲットを隔離し（`TARGET_EXECUTION_INVALID`、変更系ツールを拒否）、`close_session(discard_changes=true)` と再読み込みまで解除されません。Jython のキャンセルは協調的なもののみです。

| オプション | 効果 |
| --- | --- |
| `--script-root [LABEL=]DIR` | 事前に用意したスクリプト集（任意、複数指定可）。`list_scripts` / `get_script_info` から `script_id` = `LABEL:ファイル名` で参照する（Script Manager と同じく、ルート直下のファイルだけがスクリプト。サブディレクトリはコピーされるが一覧には出ない）。ラベル `inline` と `probe` はサーバー自身の作業ディレクトリ用に予約されており、指定すると拒否される。起動時にプロセス私有のスナップショットへコピーし、そのコピーから実行するため、元ディレクトリを後から編集しても反映されない。ファイルへのシンボリックリンクは通常ファイルとしてコピーし、ディレクトリへのシンボリックリンクは辿らない。`bundled` と書くと Ghidra 同梱の `ghidra_scripts` ディレクトリを加える（`origin=bundled`） |

`META-INF/MANIFEST.MF` があるルートも利用できます。マニフェストと依存関係の処理はGhidraに委ね、ロード・コンパイルに失敗した場合は診断を返します。

スクリプトの内容のハッシュ計算や整合性検査は行いません。`catalog_revision` はカタログを構築するたびに生成する識別子です。`expected_revision` は読み込み中のプログラムが前回の確認から変わっていないかを検査します。他の操作の完了待ちが `--script-queue-timeout-seconds` を超えた `run_script` は、実行を開始せず `LOCK_TIMEOUT` を返します。

固定の上限: `.py` スクリプトには `@runtime Jython` か `@runtime PyGhidra` のヘッダが必要（無ければ `run_script` の `runtime` で指定）、`source` は 256 KiB まで、1 ルートのファイル数は 2000 まで、`timeout_seconds` は既定 300 秒、最大 3600 秒です。タイムアウトはスクリプトのモニタ経由の協調的なキャンセルなので、`monitor.checkCancelled()` 相当を一度も呼ばないループは中断できず、終わるまでランタイム全体のロックを握り続けます（止めるにはサーバー再起動が必要です）。

ランタイム: JavaとPyGhidraのproviderはGhidraに同梱されています。Python側にはこのプロジェクトで固定した依存を導入してください（[固定したPyGhidraスナップショット](development.ja.md#pyghidraの依存バージョンとスクリプト失敗)参照）。JythonはGhidra Extensionで、`Extensions/Ghidra/ghidra_<version>_Jython.zip` を `Ghidra/Extensions/` に展開して再起動します（Dockerイメージでは済んでいます）。無いランタイムは `list_scripts` で `available=false` になります。起動時の例外伝播チェックが失敗した場合は全言語が使用不可となり、実行を `SCRIPT_RUNTIME_UNAVAILABLE` で拒否します。他の解析ツールは利用できます。

コンソール出力はストリームごとに64 KiBまで捕捉します（超過分は `dropped_bytes`）。子スクリプトを含め、Javaは `println`／`printerr`、PyGhidraは `print`／`printerr`、Jythonは `print`／`sys.stderr.write` を使ってください。Javaの `System.out`／`System.err` とCPythonの `sys.stdout.write`／`sys.stderr.write` はスクリプト別の出力捕捉を経由しません。Ghidra 12.1.4ではJython親から呼ぶJython子にscript writerが渡らないため、その子では `println`／`printerr` の代わりに共有interpreterのPython出力関数を使います。

<a id="large-results"></a>

## 大きな結果の取得

既定では、成功した大きな結果を、**応答全体が短くなる場合だけ**プレビューと `result_id` に置き換えます。全文は容量に収まる場合にプロセス内のLRUキャッシュへ保存します。同一の内容には、内容から決まる同じIDを再利用します。

| オプション | 既定値 | 意味 |
| --- | --- | --- |
| `--large-result-mode` | `resource` | 条件を満たす結果を短縮。`inline` は常に全文を返す |
| `--large-result-threshold-chars` | `12000` | この文字数を超える成功結果・ドメインエラーを短縮候補にする |
| `--large-result-preview-chars` | `4000` | プレビューの上限。必要に応じて縮小する |
| `--result-cache-max-entries` | `512` | キャッシュの最大エントリ数 |
| `--result-cache-max-bytes` | `134217728`（128 MiB） | UTF-8本文・メタデータ・JSON索引の合計上限 |
| `--result-cache-max-memory-bytes` | `134217728`（128 MiB） | 保持文字列・メタデータ・索引のメモリ計上上限（プロセスRSSではない） |
| `--tool-description-mode` | `full` | `tools/list` の説明量。`full`、`short`、`none` |

全文は `read_result(result_id, offset_chars, limit_chars)` で `has_more=false` になるまで取得するか、`ghidra://results/{result_id}` に対する `resources/read` で読みます。`limit_chars` の既定候補は短縮閾値と同じ文字数です。JSONエスケープとメタデータを含む応答テキストが上限に収まるよう、実際の取得量を調整します。`read_result` と `search_result` はresourceモードで使えます。ツールの完全な説明リソースは、説明量の設定にかかわらず利用できます。

`search_result(result_id, pattern, context_chars, max_matches)` は正規表現で検索します。スニペットは最大100件、前後の文脈は片側最大2,000文字です。一致位置はそのまま `read_result` に渡せます。`max_matches=0` ではスニペットを返さず最大10,000件まで数えます。全件数として扱う前に `scan_truncated` を確認してください。

テキストのプレビューは可能な場合に行境界で終えます。JSONは収まる項目を完全な形で返しますが、先頭部分へのフォールバックでは有効なJSONにならない場合があります。リスト・マップにはプレビュー上限の4分の1まで、`CallToolResult` 全体には2分の1までを使い、応答の付加情報に応じてさらに縮めます。空リストと閾値以下の結果はそのまま返します。ページ付き結果では、先頭数件の `items` と元の `has_more` / `next_cursor` を表示します。`preview_kind=summary` は合成表示で、全文の接頭辞ではありません。生テキストを読む場合は `continue_offset_chars`（この場合0）から取得してください。

結果がキャッシュに収まらなくても、ツール自体の処理は成功しています。短くなる場合は `RESULT_TOO_LARGE` を返し、全文を後から取得できません。それより短い場合は全文を含む応答を維持します。キャッシュからの追い出しやサーバー再起動でもIDは使えなくなります。**出力を取り直すために変更系ツールを自動で再実行しないでください。** 安全だと分かっている読み取り操作は、検索範囲やキャッシュ容量を調整してから明示的に再実行します。

大きなドメインエラーも、短くなる場合には診断全文を保存します。`isError=true`、エラーコード、実行・トランザクション状態は維持し、`result_id` から元のエラー全体を取得できます。キャッシュに収まらない場合は `result_unavailable=true` を返します。小さいエラーと `inline` モードの応答形式は従来どおりです。

JSONの配列は `read_result(result_id, mode="json", path="/items", offset_items=0, limit_items=20, fields=["from", "to"])` のように、必要な項目・フィールドだけ取得できます。`path=""` はルート配列、`path="/items"` はトップレベルのitems配列です。文字オフセットとは併用できません。省略した `fields` は全フィールド、空配列は空のオブジェクトを返します。索引は初回アクセス時に作成し、元JSONの二重保持を避け、キャッシュ予算へ計上します。1項目が大きすぎる場合はその項目を飛ばし、`item_too_large=true` と生テキスト用の `offset_chars` / `item_chars` を返し、`next_offset_items` は次の項目を指します。フィールドを絞るか `mode="text"` で取得してください。

バッチ項目の文字列は`read_result(result_id, mode="text", path="/items/0/data", offset_chars=0, limit_chars=3000)`で取得し、`search_result(result_id, path="/items/0/data", pattern="decode")`で検索できます。位置は復号した文字列上の文字位置です。両ツールは選択したpathを返し、継続時も同じpathを指定します。文字列の選択は`/items/<index>/data`のみ対応し、選択する項目はJSONの状態で最大8×1,024×1,024文字です。項目がない場合やdataが文字列でない場合はエラーになります。復号した内容は要求中だけ保持し、配列索引は既存のキャッシュ予算へ計上します。空のpathは元のJSONテキスト全体を取得・検索します。

`search_result(..., merge_context=true)` は重複する周辺文脈を `contexts` に統合し、各一致の `context_index` から参照します。既定の `false` は従来の一致ごとの文脈を返します。`count_mode="none"` は要求したスニペット件数で走査を止め、未確定の件数を `count_complete=false` で示します。既定の `"bounded"` は最大10,000件まで集計します。件数はその検索開始位置以降の値です。`next_cursor` を同じ `result_id` / `pattern` / `path` へ渡すと、返却済みの最後の一致から続きます。サイズ調整で省かれた一致も次の取得に含まれます。ゼロ長一致でも継続でき、検索時間制限は維持します。逆方向正規表現は先頭からの `bounded` 検索のみ対応し、継続カーソルは提供しません。

`disassemble` の新しいカーソルは次の命令アドレスから再開します。関数の非連続な範囲を維持し、先行ページの命令を再変換しません。従来のオフセット形式のカーソルも受け付けます。プログラムのrevisionやクエリが異なるカーソルは引き続き拒否します。

`short` モードはツールごとの明示的な短い説明を使います。選択条件や変更操作の意味を残し、完全な説明はドキュメントリソースから取得できます。既定の `full` は変更していません。
