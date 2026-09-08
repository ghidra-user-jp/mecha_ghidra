[English](configuration.md) | [日本語](configuration.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# 設定

サーバーの設定は `uv run ghidra-mcp` の引数で指定します。全オプションは `uv run ghidra-mcp --help` で確認できます。このページでは[接続方式](#transports)、[ターゲット](#targets)、[ファイルアクセス](#file-access)、[ツール公開範囲](#tool-exposure)、[大きな結果](#large-results)を説明します。

<a id="transports"></a>

## 接続方式と認証

| オプション | 既定値 | 用途 |
| --- | --- | --- |
| `--transport` | `stdio` | `stdio`、`http`（別名 `streamable-http`）、旧方式の `sse` |
| `--mcp-host` | `127.0.0.1` | HTTP/SSEの待ち受けアドレス |
| `--mcp-port` | `8081` | HTTP/SSEのポート |
| `--mcp-path` | `/mcp` | Streamable HTTPのエンドポイントパス |
| `--ghidra-path` | `GHIDRA_INSTALL_DIR` | Ghidraのインストール先 |
| `--log-level` | `INFO` | サーバーのログレベル |

ローカルHTTPでは[アクセス先を制限した起動例](usage.ja.md#local-setup)を使ってください。MCPエンドポイントにクライアント認証機能は組み込まれていません。Ghidra ServerとBSimのパスワードは各バックエンドの認証用であり、MCPクライアントの認証には使われません。

`0.0.0.0` や `::` で待ち受けてもDNSリバインディング対策は有効で、既定ではループバックのHost/Originだけを受け付けます。リモート接続を構成する場合は、クライアントが使うHostに一致する固定IP・ホスト名で待ち受け、TLS、認証、アクセス制御を配備側で用意してください。Dockerの既定設定はホストのループバックにだけポートを公開します。

stdioでは、Ghidraの出力がJSON-RPCへ混入しないように、起動後のJVM `System.out` を標準エラーへ向けます。

<a id="targets"></a>

## ターゲットと同時呼び出し

`--project-location`、必要に応じた `--project-name`、`--target-name`（既定値 `default`）で初期ターゲットを指定します。`--domain-path /folder/program` を付けると起動時にプログラムを開き、省略するとプロジェクト情報だけを登録します。起動にはプロジェクト指定または `--session` が1つ以上必要です。

起動時に複数のターゲットを登録するには、`--session` を繰り返します。以下は既存プロジェクトを使う例です。

```bash
uv run ghidra-mcp \
  --session 'name=sample,project_location=/work/sample.gpr,domain_path=/sample.bin' \
  --session 'name=reference,project_location=/work/reference.gpr,domain_path=/reference.bin' \
  --transport stdio
```

セッション定義はJSONではなく、カンマ区切りの `key=value` です。値にはカンマを使えません。キーは `name`、`project_location`、任意の `project_name` と `domain_path` です。パスの違いは[プロジェクトの基本](usage.ja.md#project-concepts)を参照してください。

`--lock-timeout-seconds` の既定値は `30` です。使用中のターゲットに対する呼び出しはロックを待ち、待機時間を超えると再試行可能な `LOCK_TIMEOUT` を返します。これは待ち行列での制限であり、解析処理の実行時間制限ではありません。MCPクライアントのタイムアウトは別途設定します。

<a id="file-access"></a>

## ファイルアクセス

パスはサーバーのファイルシステムを指します。Dockerではコンテナ内のパスを使います。

| オプション（複数指定可） | 制御する対象 |
| --- | --- |
| `--allowed-import-root DIR` | `import_program` が読み込むファイル |
| `--allowed-project-root DIR` | プロジェクト／セッション操作による作成・読み込み先。BSimのリモートキャッシュも含む |
| `--allowed-export-root DIR` | `export_program` の書き出し先 |

シンボリックリンクを含めてパスを解決してから検証します。エクスポートでは正規化・検証したパスをそのまま書き込み処理へ渡します。設定範囲外は `PATH_NOT_ALLOWED` になります。指定を省略した種類の操作は、このパスポリシーでは制限されません。OSのファイル権限は引き続き適用されます。

HTTP/SSEでは3種類とも指定してください。起動時の警告は**3種類とも未設定の場合だけ**に出るため、警告がないことは全操作の制限を意味しません。これらはパスの制御であり、完全なサンドボックスではありません。

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
| `category` | 上記の7カテゴリ |
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

<a id="large-results"></a>

## 大きな結果の取得

既定では、成功した大きな結果を、**応答全体が短くなる場合だけ**プレビューと `result_id` に置き換えます。全文は容量に収まる場合にプロセス内のLRUキャッシュへ保存します。同一の内容には、内容から決まる同じIDを再利用します。

| オプション | 既定値 | 意味 |
| --- | --- | --- |
| `--large-result-mode` | `resource` | 条件を満たす結果を短縮。`inline` は常に全文を返す |
| `--large-result-threshold-chars` | `12000` | この文字数を超える成功結果を短縮候補にする |
| `--large-result-preview-chars` | `4000` | プレビューの上限。必要に応じて縮小する |
| `--result-cache-max-entries` | `512` | キャッシュの最大エントリ数 |
| `--result-cache-max-bytes` | `134217728`（128 MiB） | UTF-8本文と保持メタデータの合計上限 |
| `--tool-description-mode` | `full` | `tools/list` の説明量。`full`、`short`、`none` |

全文は `read_result(result_id, offset_chars, limit_chars)` で `has_more=false` になるまで取得するか、`ghidra://results/{result_id}` に対する `resources/read` で読みます。`limit_chars` の既定値は短縮閾値の3分の1です。`read_result` と `search_result` はresourceモードで使えます。ツールの完全な説明リソースは、説明量の設定にかかわらず利用できます。

`search_result(result_id, pattern, context_chars, max_matches)` は正規表現で検索します。スニペットは最大100件、前後の文脈は片側最大2,000文字です。一致位置はそのまま `read_result` に渡せます。`max_matches=0` ではスニペットを返さず最大10,000件まで数えます。全件数として扱う前に `scan_truncated` を確認してください。

テキストのプレビューは可能な場合に行境界で終えます。JSONは収まる項目を完全な形で返しますが、先頭部分へのフォールバックでは有効なJSONにならない場合があります。リスト・マップにはプレビュー上限の4分の1まで、`CallToolResult` 全体には2分の1までを使い、応答の付加情報に応じてさらに縮めます。エラー、空リスト、閾値以下の結果はそのまま返します。

結果がキャッシュに収まらなくても、ツール自体の処理は成功しています。短くなる場合は `RESULT_TOO_LARGE` を返し、全文を後から取得できません。それより短い場合は全文を含む応答を維持します。キャッシュからの追い出しやサーバー再起動でもIDは使えなくなります。**出力を取り直すために変更系ツールを自動で再実行しないでください。** 安全だと分かっている読み取り操作は、検索範囲やキャッシュ容量を調整してから明示的に再実行します。
