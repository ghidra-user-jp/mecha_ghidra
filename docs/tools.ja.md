[English](tools.md) | [日本語](tools.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# ツール一覧

用途からツールを探すための一覧です。呼び出し前にクライアントのツールスキーマを確認してください。全引数・制約・エラーコードはMCPリソース `ghidra://docs/tools` と `ghidra://docs/tools/{tool_name}` にあります。`tools/list` の出力スキーマは、ツール固有の結果の形は完全に示しますが、全ツールに共通する応答（保存した大きな結果の通知、先送りの応答、エラー）は短い形だけです。それらの完全な形は `ghidra://docs/tools/{tool_name}` にあります。

多くのツールは `target`（既定値 `default`）で対象を選びます。`shared_sync` と `bsim` は既定では公開されません。[設定](configuration.ja.md#tool-exposure)で追加してください。`gui` は `--backend gui` のときだけ公開され、GUIのバックエンドは一部のツールを公開しません（[GhidraのGUI](#gui)）。

応答とエラーは、どのツールでも次の決まりに従います。

- プログラムを扱うツールの応答は、結果の出典を `source` に示します。`target`、`program`（domain path）、`revision` の3つで、ツールの実行直後の値です。この `revision` を `expected_revision` に渡すと、古い読み取りに基づく編集を拒否できます。モデルに文字列しか見せないクライアントのため、`source` は最後の文字列ブロックにも入ります。`batch_read` は1つのJSONブロックの中に `program` と `revision` を示し、[先送りした呼び出し](usage.ja.md#long-calls)の記録は `result` の横に `source` を持ちます。
- 文字列ブロックには結果そのものが入ります。文字列はそのまま、それ以外は詰めたJSONを1つのブロックにします。リストは1行に1項目です。
- 書き込みが失敗すると、何が残ったかを `error.details.output_state` で示します。`absent`（何も変わっていない。一時的なエラーなら再試行できる）、`created`（変更が未保存で残っている）、`uncertain`（続ける前にプログラムを確かめる）のいずれかです。`retryable` がtrueになるのは `absent` のときだけです。保存、commit、書き出しなど、プロジェクトやリポジトリへの書き込みでは、変更の前に断るエラーなら `absent`、それ以外は `uncertain` です。BSimのデータベースへの書き込みも同じです。読み込んだプログラムに対して動くBSimのツール（`bsim_register_target`、`bsim_update_target_signatures`、`bsim_apply_matches`）は、プログラムのトランザクションがどう終わったかを示し、データベースへの書き込みを始めた後の失敗は `uncertain` です。
- プログラムへの書き込みは、どれもクライアントが作ったUUIDを `request_id` に受け付けます。同じ `request_id` と引数で送り直すと、書き込みを再び適用せず、`replayed: true` を付けた最初の呼び出しの応答を返します（最初の呼び出しが何も変えずに失敗した場合を除く）。詳しくは[シンボルとコメント](#symbol-comment-edit)の `apply_edits` を参照してください。結果なら最後の文字列ブロック、エラーならそのJSONの文字列ブロックにも `replayed` が入ります。保存した結果の通知は2つのブロックのままで、`structuredContent` だけに示します。
- エラーの `code` は失敗の種類を、`hint` は次に呼ぶツールを（あれば）示します。関数、データ型、変数、ブックマーク、名前空間、リポジトリが見つからなければ `NOT_FOUND`、引数の誤り（入力の形の誤り、解析できないCの宣言、既にある書き出し先、存在しない書き出し先のディレクトリ）は `VALIDATION_ERROR` で、どちらも理由を `message` に示します。Ghidra内部の失敗は無害化した `cause_message` 付きの `OPERATION_FAILED` で、`VALIDATION_ERROR` にはなりません。プログラムを読み込んでいないtargetは `PROGRAM_NOT_OPEN`、存在しないtargetは `TARGET_NOT_REGISTERED` です。
- すべてのツールが `readOnlyHint`、`destructiveHint`（削除、バイトの上書き、commitやpullなどのリポジトリ操作、スクリプトはtrue）、`openWorldHint`（BSimのデータベース、Ghidra Server、スクリプトはtrue）を宣言します。

- [プロジェクトとセッション](#core)
- [読み取りのバッチ実行](#batch-read)
- [関数解析](#function-analysis)
- [メモリとデータ](#memory-data)
- [シンボルとコメント](#symbol-comment-edit)
- [データ型](#datatype-ops)
- [共有プロジェクト](#shared-sync)
- [BSim](#bsim)
- [Ghidra スクリプト](#scripts)
- [GhidraのGUI](#gui)
- [大きな結果の取得](#result-retrieval)

<a id="core"></a>

## プロジェクトとセッション

操作の順序と保存の動作は[最初の解析](usage.ja.md#first-analysis)を参照してください。

| ツール | 用途 |
| --- | --- |
| `list_targets` | 登録済みターゲットと紐づくプロジェクト情報を一覧表示 |
| `create_project` | 空のローカルGhidraプロジェクトを作成 |
| `open_program` | 既存プロジェクトのプログラムを開いてターゲットを追加。解析はせず、解析済みかどうかを`is_analyzed`で返す |
| `register_target` | プログラムを開かずにターゲットへプロジェクト情報のみ登録 |
| `close_session` | ターゲットのセッションを閉じる。`discard_changes=true` で保存せずに閉じる（`TARGET_EXECUTION_INVALID` 後の復旧経路でもある） |
| `close_session_and_remove_program` | セッションを閉じたうえでプログラムをプロジェクトから削除 |
| `list_project_programs` | ターゲットが開いているプロジェクト内プログラム一覧を取得 |
| `import_program` | バイナリまたは `.gzf` をバックグラウンドのジョブとしてインポートし、既定で解析まで行う（`analyze_imported=false`で解析を省略）。応答は最大`wait_seconds`秒待ってジョブの記録を返す |
| `get_operation` | `operation_id`（または`request_id`）で、ジョブの状態・結果を取得。取り込み・解析・スクリプトのジョブと、40秒で終わらず`deferred: true`を返した呼び出し（[長い呼び出し](usage.ja.md#long-calls)）が対象。完了まで待つこともできる。`result`にはそのツールが返す値が入る。Ghidraのロックは取らない |
| `cancel_operation` | 待機中・実行中の取り込み・解析・スクリプトのジョブを取り消す。まだプログラムを変更し始めていないジョブはその場で`OPERATION_CANCELLED`で終わり、実行中のジョブは次の取り消しの確認で巻き戻す |
| `load_project_program` | 既存プログラムを指定 `domain_path` で読み込み。ターゲットが既に保持しているプログラムを指定すると再読み込み、`version=N` で共有プロジェクトの過去バージョンを読み取り専用で開く。読み込みでは解析しない（`is_analyzed`を参照） |
| `save_project_program` | 編集後の読み込み中のプログラムをGhidraプロジェクトに保存 |
| `get_program_info` | 言語、コンパイラ、イメージベース、md5/sha256、エントリポイント、解析済みフラグ、未保存変更、取り消し可否、変更を検出する `revision` |
| `undo_program_change` / `redo_program_change` | 読み込み中のプログラムの直近トランザクションを取り消し・やり直し |
| `export_program` | プログラムを `.gzf` または生バイト列で書き出し（`--allowed-export-root` で制限可） |

<a id="batch-read"></a>

## 読み取りのバッチ実行

`batch_read` は同じ `target` への独立した読み取り1〜20件を、1回のツール呼び出し・1回のターゲット／プロジェクトロック取得で順番に実行します。既定・readonly・fullプロファイルで公開されます。対応ツールは `get_function`、`get_comments`、`get_data_type`、`get_xrefs`、`get_call_edges`、`decompile_function`、`disassemble` です。それぞれが単独でも公開されている必要があり、無効化したツールをバッチ経由で呼ぶことはできません。

```json
{
  "target": "default",
  "requests": [
    {"id": "function", "tool": "get_function", "arguments": {"address": "0x401000"}, "fields": ["entry", "name"]},
    {"id": "references", "tool": "get_xrefs", "arguments": {"address": "0x401000", "direction": "to", "limit": 20}},
    {"id": "c", "tool": "decompile_function", "arguments": {"address": "0x401000"}, "item_timeout_seconds": 15},
    {"id": "asm", "tool": "disassemble", "arguments": {"address": "0x401000", "limit": 40}, "fields": ["address", "mnemonic", "operands"]}
  ],
  "timeout_seconds": 30,
  "max_output_chars": 12000
}
```

`id` は英数字・`_`・`-`からなる1〜32文字の一意な値です。`arguments` は各ツールと同じ引数で、`target` は含めません。構造・型・セレクター・公開設定を全件検証してから実行します。`get_xrefs` / `get_call_edges` / `disassemble` の `limit` の合計は、既定値も含めて最大2,000です。逆コンパイルは1バッチ最大5件です。前の項目の結果を後の引数に使う依存関係や、再帰バッチ、書き込み、スクリプト、自動的な追加解析は扱いません。

任意の `fields`（1〜32個）は返すキーを選びます。通常は結果オブジェクトの直下、ページ付きツールでは各行のキーを選び、`program`・`revision`・`has_more`・`next_cursor` は保持します。存在しないキーは省略し、ネストしたパスは解釈しません。項目ごとのページ継続は従来と同じクエリとcursorを使います。

逆アセンブルは単独呼び出しと同じ関数・アドレス範囲指定とcursorを使い、`fields`は命令行に適用します。逆コンパイルはC文字列を返し、`fields`は指定できません。バッチ専用の`item_timeout_seconds`（既定15、1〜60）は`arguments`の外側に指定します。単独の逆コンパイルは従来の120秒設定を維持します。

応答は1つのJSONテキストです。全体の `status` は全件成功なら `ok`、一部成功なら `partial`、成功がなければ `error`。`succeeded_count`・`failed_count`・`not_run_count` と、要求順の `items`（`id`・`tool`・`status`・`data` または `error`）を確認してください。項目の未検出・曖昧な名前などでは残りを続行します。Ghidra内部で起きた`NullPointerException`は、単独の呼び出しと同じく`OPERATION_FAILED`の項目エラーとし、Javaのクラス名だけを示します。成功が0件の場合はMCPの `isError=true`、部分成功は `isError=false` でも失敗項目を含みます。

`expected_revision` は任意です。開始前の不一致、または読取中の編集・再読み込みを検出した場合は、混在した結果を返さず全体を `SESSION_CHANGED` で失敗させます。`timeout_seconds`（既定10、1〜60）はロック取得後から計測します。重い読み取りでは実行中も期限を確認し、逆コンパイルは項目上限とバッチ残時間の短い方を使って、その呼び出し専用monitorで停止を要求します。残時間が1秒未満なら逆コンパイルを開始しません。逆アセンブルは列挙・変換中に確認します。協調停止のため厳密な実時間上限ではなく、処理が戻るまでロックを保持します。予算超過後の項目は `not_run` / `time_budget_exhausted` です。停止を確認したtimeout（`DECOMPILE_TIMEOUT` / `READ_TIMEOUT`）や逆コンパイル失敗（`DECOMPILE_FAILED`）は項目エラーとし、残時間があれば後続を実行します。中断した逆アセンブルのページを成功として返しません。

保持する項目の本文には別途8 MiBの上限があり、compactなUTF-8 JSONとして計測し、状態・エラー用の余地を確保します。1項目が大きすぎる場合は`ITEM_RESULT_TOO_LARGE`とし、途中までのCを成功として返しません。残りの合計容量を超えた項目は`RESULT_BUDGET_EXHAUSTED`、以降は`not_run / result_budget_exhausted`になります。大きすぎるエラー詳細は省略を明示します。Ghidraやnativeデコンパイラ内部での生成時の最大メモリ使用量を保証するものではありません。

`max_output_chars`（既定12,000、2,048〜12,000）はバッチ全体のJSONテキスト上限です。MCPの外側の包み・トークン数は含まず、このツール固有の上限を使います。大きい結果は選択済みの全項目を1つの結果キャッシュに保存し、応答には件数・項目の状態・収まる小さい結果・共通の `result_id` を返します。省略項目の `offset_items` を使い、例えば次の呼び出しで2番目の結果を取得します。

```json
{"result_id": "返されたID", "mode": "json", "path": "/items", "offset_items": 1, "limit_items": 1}
```

取得ツールは `read_result` です。`limit_items` を増やせば複数項目をまとめて取得できます。1項目が取得上限を超える場合、`read_result` はその項目を飛ばし（`item_too_large=true`、`next_offset_items` は次の項目を指す）、生テキスト位置を返すので、`mode="text"` で読むか `search_result` で必要な箇所を探します。状態一覧だけでも予算を超える場合は `item_summaries_omitted=true` と件数を返し、一覧もキャッシュから取得します。キャッシュ上限で保存できなければ `result_unavailable=true` と明示します。通常のLRU追い出しにより、後からIDが利用できなくなる場合もあります。`large_result_mode=inline` では上限超過をエラーにするため、`fields`・`limit`・要求件数を絞ってください。

C本文は`read_result(result_id, mode="text", path="/items/2/data", offset_chars=0, limit_chars=3000)`で取得し、`search_result(result_id, path="/items/2/data", pattern="decode")`で検索できます。項目番号は0始まりで、省略された文字列項目には`text_path`を返します。位置はJSONエスケープ後ではなく、復号したC文字列上の文字位置です。ページ継続・検索cursorでは同じpathを指定してください。空のpathは従来どおり生テキストの取得・検索です。

<a id="function-analysis"></a>

## 関数解析

| ツール | 用途 |
| --- | --- |
| `list_functions` | 関数一覧（サイズと thunkフラグ付き）。`filter` で名前を絞り、`only_default_names=true` で未命名の `FUN_` 関数だけを取得 |
| `list_namespaces` | 名前空間一覧を `{name, is_class}` で取得（ページング対応）。`classes_only=true` でクラスのみ |
| `decompile_function` | 関数名またはアドレス指定で C風の疑似コードを取得（両方指定時は `address` 優先）。先頭行は、関数の完全名とエントリーアドレスを書いたコメント（例：`/* entry @ 00401e46 */`） |
| `disassemble` | 関数またはアドレス範囲の既存命令をページ単位で取得 |
| `get_function` | 関数名またはアドレス指定でシグネチャ、引数、ローカル変数、本体範囲、thunk先、名前空間を取得（両方指定時は `address` 優先） |
| `create_function` | アドレスに関数を作成 |
| `delete_function` | アドレス指定で関数を削除 |
| `analyze_program` | Ghidraの自動解析をバックグラウンドのジョブとして実行（`force=true`で解析済みでも再実行）。応答は最大`wait_seconds`秒待ってジョブの記録を返す。解析の結果は未保存のまま |
| `get_call_edges` | 関数の呼び出し元・先を呼び出し位置付きで取得。tail call、thunk転送、未解決の呼び出しを区別 |

### 解析結果と続きの取得

`get_xrefs`、`get_call_edges`、`disassemble` は `program`、`revision`、`items`、`has_more`、`next_cursor` を返します。`limit` は1ページの件数で、既定100件、最大10,000件です。続きは同じ検索条件に返されたcursorを追加して取得し、`has_more=false` で終了します。ページ間で変更できるのは `limit` だけです。

`revision` は読み込み中のプログラムの状態を識別します。編集、undo/redo、再読み込みなどでcursorが無効になった場合は `SESSION_CHANGED` を返すため、最新状態で最初から取得し直してください。[大きな結果の取得](configuration.ja.md#large-results)とは別の仕組みで、1ページが大きい場合は結果リソースとして保存されることもあります。

呼び出し関係には呼び出し元・先の識別情報と `call_site` の命令アドレスを含み、データ参照は含めません。未解決の呼び出し先は `resolved=false`、命令上の参照がないthunk転送は `call_site=null` です。tail callは別関数へのジャンプ参照を表し、高水準の制御フローを証明するものではありません。

<a id="memory-data"></a>

## メモリとデータ

| ツール | 用途 |
| --- | --- |
| `list_segments` | メモリセグメント/レイアウト情報を取得 |
| `list_imports` | インポートシンボル一覧（ライブラリ名とアドレス付き） |
| `list_exports` | エクスポートシンボル一覧（アドレス付き） |
| `list_data_items` | データアイテム一覧（ラベル、長さ、値付き） |
| `list_strings` | 文字列一覧（大文字小文字を区別しない `filter`） |
| `get_xrefs` | 参照元・先アドレスと両側の関数を取得。`direction="to"` / `"from"` で方向を選択 |
| `get_data_by_label` | ラベル名からデータを取得 |
| `get_bytes` | 指定アドレスのバイト列を取得 |
| `search_bytes` | バイトパターン検索（`??` はワイルドカード） |

<a id="symbol-comment-edit"></a>

## シンボルとコメント

| ツール | 用途 |
| --- | --- |
| `apply_edits` | 関数・変数・データの命名、型、コメントを一括編集。全件確定・ロールバック、dry run、変更前後の状態に対応 |
| `set_function_prototype` | 関数プロトタイプを設定（関数は `function_address` または `function_name` で指定） |
| `set_local_variable_type` | ローカル変数/引数の型を設定（関数は `function_address` または `function_name` で指定） |
| `rename_variable` | ローカル変数/引数の名前を `old_name` から `new_name` に変更（関数は `function_address` または `function_name` で指定）。`--backend gui` のときだけ公開。headlessでは `apply_edits` の `rename_variable` を使う |
| `set_global_data_type` | グローバルデータの型を設定（`clear_mode` 指定可） |
| `set_bytes` | メモリ内容をバイト列で書き換え |
| `get_comments` | アドレスの全コメント種別を読み出し |
| `search_symbols` | 全シンボルを名前で検索（glob 可、種別で絞り込み可） |
| `create_label` | シンボルのないアドレスにラベルを作成 |
| `add_bookmark` | ブックマークを追加 |
| `list_bookmarks` | ブックマーク一覧を取得 |
| `delete_bookmark` | IDまたはアドレス・種別・カテゴリ指定でブックマークを削除 |

### 名前・型・コメントの一括編集

`apply_edits` は1つのターゲットに1〜100件の操作を順番に適用します。対応する `kind` は `rename_function`、`rename_data`、`rename_variable`、`set_function_prototype`、`set_local_variable_type`、`set_global_data_type`、`set_comment` です。種類ごとに引数を検証します。対象アドレスは解析ツールから取得し、型名が曖昧な場合は完全パスで指定してください。

引数の例です。アドレスは対象プログラムに置き換えてください。

```json
{
  "target": "default",
  "atomic": true,
  "dry_run": true,
  "edits": [
    {"kind": "rename_function", "address": "0x401000", "new_name": "decode_config"},
    {"kind": "set_comment", "address": "0x401000", "comment_type": "pre", "comment": "設定バッファを復号する。"}
  ]
}
```

`rename_function` は `new_name`、`namespace_path` の少なくとも一方を指定します。省略・`null` の項目は現状を維持し、`new_name` は関数の単純名を指定します。Namespace パスは Global 基点（例: `AI::config`）で、空文字列は Global への移動です。`create_namespace=true` の場合は不足する親も含めて作成し、既定では既存のパスを要求します。移動先として通常の Namespace を解決・作成し、Class・Library・関数スコープは使用しません。Namespace だけの変更では、関数名と名前の出所情報を維持します。

```json
{
  "target": "default",
  "edits": [
    {"kind": "rename_function", "address": "0x401000", "namespace_path": "AI::config", "create_namespace": true}
  ]
}
```

この編集に `"new_name": "decode_config"` を加えると、名前と Namespace を同時に変更できます。Namespace の作成と関数の変更は一つのトランザクションで扱います。関数編集の結果には `changed`、`created_namespaces`、変更前後の完全修飾名・Namespace・名前の出所情報が含まれます。同じ状態への編集は `changed=false` になり、Ghidra が許容する同名関数はアドレスで区別します。試行・ロールバック時の `created_namespaces` は作成を試みたパスであり、確定して残った Namespace を示すものではありません。

既定名の thunk は転送先関数の Namespace を継承します。Ghidra が Namespace だけの変更を保持できない場合は失敗としてロールバックします。独立した名前・Namespace を設定する場合は `new_name` も明示してください。

既定の `atomic=true` では全件をまとめて確定し、1件でも失敗すると全件をロールバックします。`atomic=false` は成功した項目を保持し、失敗を個別に報告します。`dry_run=true` は実際に編集して変更前後の状態を取得した後、ロールバックします。このためdry runでも書き込み可能なプログラムと、共有管理済みファイルのチェックアウトが必要です。編集内容は残りませんが、revisionは進む場合があります。

読み取り後に別の編集が入っていないことを確認するには、編集の根拠にした応答の `source.revision`、または `get_program_info` の `revision` を `expected_revision` に渡します。プレビュー後に `dry_run=false` で適用するときは、プレビューが返したrevisionを使えます。

再送を安全にするには、クライアントが作ったUUIDを `request_id` に渡します。応答が失われて同じ `request_id` と引数で送り直すと、サーバーは編集を再び適用せず、最初の呼び出しの応答を返します。その応答には、`structuredContent`と最後の文字列ブロックに`replayed: true`が付きます。最初の呼び出しがまだ実行中なら、再送はその終了を待ち、`deferred: true` で同じ記録を返すことがあります。同じ `request_id` で引数が違うと `REQUEST_ID_CONFLICT` になります。何も変えずに失敗した呼び出し（`output_state: absent`）は、実行枠を待つ間に取り消したものを除き、その `request_id` を保ちません。次にそのIDで送った呼び出しが実行されます。`get_operation(request_id=...)` でもこの呼び出し（そのIDで最後に送ったもの）を探せます。記録はジョブと同じく、サーバーのメモリにだけあります。ほかのプログラムへの書き込みと `bsim_apply_matches` も、同じように `request_id` を受け付けます。

応答の `status`、`applied_count`、各 `results` を確認してください。全体のstatusは `applied`、`partial`、`rolled_back`、`dry_run`、`dry_run_failed` です。項目別の失敗も通常のツール応答に含まれるため、通信が成功しただけでは編集成功とは限りません。成功した項目には `before` / `after` が付き、取り消した項目と試行だけの項目は区別されます。残した変更は `save_project_program` で保存します。

個別の型編集ツールも引き続き利用できます。一括のグローバル型設定では空き領域を確認します。明示的な `clear_mode` が必要な場合は単独の `set_global_data_type` を使ってください。

<a id="datatype-ops"></a>

## データ型

| ツール | 用途 |
| --- | --- |
| `create_struct` | 構造体を作成 |
| `add_struct_members` | 構造体メンバーを追加 |
| `remove_struct_members` | 構造体メンバーを選択削除。`clear_all=true` で明示的に全削除 |
| `delete_data_type` | データ型（struct、union、enum、typedef など）を削除 |
| `get_data_type` | 完全パスまたは一意な名前から型を取得。struct・unionのメンバー、enumの値、typedefの参照先を含む |
| `list_data_types` | プログラム内のデータ型一覧を取得 |
| `rename_data_type` | データ型名を変更 |
| `create_enum` / `set_enum_values` | 列挙体の作成と値の追加・置換・削除 |
| `parse_c_declarations` | C の struct、union、enum、typedef、プロトタイプをプログラムのデータ型として取り込み |

<a id="shared-sync"></a>

## 共有プロジェクト

`--add-category shared_sync` で公開します。[共有の手順・競合・削除条件](shared-projects.ja.md)を確認してください。

| ツール | 用途 |
| --- | --- |
| `get_project_sync_status` | 共有プロジェクト上の同期状態を取得 |
| `get_version_history` | バージョン履歴（version/user/comment/time）を取得 |
| `get_version_diff` | 2バージョン間の差分要約（件数/タイプ別/アドレスレンジ）を取得。`include_details=true` でレンジごとの Ghidra Diff 説明文も返す |
| `checkout_project_program` | プログラムをチェックアウト。`exclusive` 省略時は `--shared-sync-exclusive-checkout` の設定に従う |
| `add_project_program_to_version_control` | 未共有プログラムを共有管理へ追加 |
| `commit_project_program` | チェックアウト中の変更をチェックイン。古いチェックアウトと競合した場合、`on_conflict="keep"` でローカル編集を `.keep` コピーに退避して最新へ追従、`on_conflict="discard"` で破棄 |
| `pull_project_program` | 最新状態を取得（必要に応じて破棄/追従） |
| `undo_checkout_project_program` | チェックアウトを取り消し（ローカル変更破棄可） |
| `terminate_project_program_checkout` | 既存チェックアウトをチェックアウトIDで強制終了 |
| `delete_shared_project_file` | `confirm` が `domain_path` と一致した未読み込みファイルを削除（バージョン管理済みファイルは `expected_latest_version` と明示的な `allow_non_atomic_versioned_delete=true` も必須） |

<a id="bsim"></a>

## BSim

`--add-category bsim` と接続先が必要です。[BSimガイド](bsim.ja.md)を参照してください。

| ツール | 用途 |
| --- | --- |
| `get_bsim_database_status` | DBメタデータ、実行ファイル数、設定済みカテゴリと関数タグ |
| `bsim_add_executable_category` | 実行ファイルのメタデータカテゴリを追加 |
| `list_bsim_executables` / `get_bsim_executable` | 実行ファイルレコードの一覧・取得 |
| `bsim_update_executable_metadata` | 既存レコードのカテゴリを変更 |
| `bsim_register_target` | 読み込み中のプログラムのシグネチャを生成して登録（`categories` 指定可） |
| `bsim_update_target_signatures` | 読み込み中のプログラムの現在の関数名を既存レコードに書き戻す |
| `bsim_delete_executable` | 実行ファイルとその関数レコードを削除（`confirm` に md5 または名前を再入力） |
| `bsim_query` | `scope="program"` で全体、`scope="functions"` と `addresses` / `function_names` で選択した関数を検索。自己一致は既定で除外 |
| `bsim_apply_matches` | 既定名のままの関数を最良一致の名前で一括リネーム（`dry_run`・`request_id` 可） |
| `bsim_load_matched_executable` | 一致した実行ファイルを新しいターゲットとして開く。`ghidra://` の一致には `--bsim-remote-cache-dir` が必要 |

<a id="scripts"></a>

## Ghidra スクリプト

公開は他のカテゴリと同じくツールプロファイル／カテゴリフラグで決まります（`--tool-profile full` または `--add-category scripts`）。`run_script` はスクリプト本文を直接受け取り、`--script-root` は事前に用意したスクリプト集を足すだけです。スクリプトはサーバープロセスの OS 権限で動きます。実行がどうトランザクションで包まれ、失敗時に何が起きるかは[スクリプト実行](configuration.ja.md#scripts)を参照してください。

| ツール | 用途 |
| --- | --- |
| `list_scripts` | 実行可能なスクリプトの一覧（`script_id` = `<ルート>:<ファイル名>`。Script Manager と同じくルート直下のファイルだけを列挙し、サブディレクトリは対象外）。ランタイム（`Java` / `Jython` / `PyGhidra`）、カテゴリ、説明、実行可否を返す。`include_bundled=true` で運用者が許可した Ghidra 同梱スクリプトも含める |
| `get_script_info` | 1 本のヘッダ情報。`include_source=true` でソース本文を返し、実行前に期待する `args` を確認できる |
| `run_script` | 読み込み中のプログラムに対して、Script Manager と同じようにスクリプトをバックグラウンドのジョブとして実行する。応答は最大`wait_seconds`秒待ってジョブの記録を返す。`source`（スクリプト本文。Java は `public class X extends GhidraScript`、Python は `# @runtime PyGhidra` / `# @runtime Jython` ヘッダで判定、無ければ `runtime` を指定）か `script_id`（カタログのスクリプト）を渡す。`args` は位置引数の文字列。実行はトランザクションで包まれ、成功時はコミット、例外やタイムアウト時はロールバック。ジョブの`result`には `transaction_outcome`、stdout／stderr、Java のコンパイル診断が付くので、失敗したスクリプトを直して再実行できる |

失敗はロールバックされます。`SCRIPT_FAILED` / `SCRIPT_TIMEOUT` のジョブの`operation_error`は、`details.transaction_outcome`（`rolled_back` / `unchanged` / `unknown`）、上限付きで捕捉した `stdout` / `stderr`（`dropped_bytes` 付き）、Java の `SCRIPT_COMPILE_FAILED` ではコンパイラ診断を含みます。`details.output_state`はトランザクションの結果に従います。`rolled_back`と`unchanged`は`absent`、`committed`は`created`（未保存）、`unknown`と、`execution_state`が`invalid`の場合は`uncertain`です（スクリプトが残した処理が、後でプログラムを変えるおそれがあり、ターゲットは隔離されます）。対象はプログラムの変更だけで、ファイルや通信への影響は含みません。大きな診断は、他の大きな結果と同じく結果の保存先へ移り、`operation_error.result_id`で全文を読めます。

<a id="gui"></a>

## GhidraのGUI

`--backend gui` のときだけ公開されます。使い方は[GUIでのライブ共有](gui-live.ja.md)を参照してください。`--backend gui` では、[シンボルとコメント](#symbol-comment-edit)の `rename_variable` も公開されます。

| ツール | 用途 |
| --- | --- |
| `get_gui_context` | 人間が見ているもの（CodeBrowserの一覧、アクティブなツールのProgram、位置、関数、選択範囲）、そのProgramに結び付いたtargetとrevision、表示中のモーダルの画面の題名を返す。Ghidraが背面にあるときは、最後に使ったCodeBrowserが対象。表示もtargetも変えない |
| `show_in_gui` | targetのProgramをCodeBrowserに表示し、`address` か関数の `name` へ移動する。無効な指定は表示を変える前にエラーになる。表示だけを変え、編集、保存、解析はしない |

GUIのバックエンドは、`import_program`、`analyze_program`、`create_project`、`close_session_and_remove_program` と、`bsim`、`shared_sync`、`scripts` のカテゴリを公開しません。公開するツールでも、`apply_edits` の `dry_run` と、decompileする種類（`rename_variable`、`set_local_variable_type`）の一括の編集（同じ名前の単独のツールを使う）、`load_project_program` の `version`、`close_session` の `discard_changes`、別のProjectの指定は `GUI_UNSUPPORTED` です（[使えない機能](gui-live.ja.md#limits)）。

<a id="result-retrieval"></a>

## 大きな結果の取得

`--large-result-mode resource` のときに公開されます。[結果の取得とキャッシュ](configuration.ja.md#large-results)を参照してください。

| ツール | 用途 |
| --- | --- |
| `read_result` | 保存済み大型結果のスライスを読む（`offset_chars` / `limit_chars` で `has_more` が false になるまでページング。`limit_chars` のデフォルトは圧縮閾値の 1/3） |
| `search_result` | 保存済み大型結果を正規表現で検索。最大100件のスニペット、片側最大2,000文字の前後コンテキスト、`read_result` の offset にそのまま使えるマッチ位置を返す。`max_matches=0` では最大10,000件までスニペットなしで数えるため、`match_count` を全件数として扱う前に `scan_truncated` を確認 |

編集後は `save_project_program` で保存します。共有ファイルの編集にはチェックアウトが必要です。`remove_struct_members.members` はメンバー名の文字列と `{"name": ...}` オブジェクトのどちらも受け付けます。

`add_struct_members` でメンバーの `offset` を明示すると、`parse_c_declarations` で作成した型など、自動配置が有効な構造体は手動配置へ切り替わります。置換対象外のメンバーの位置を維持し、指定位置に収まるよう必要に応じて構造体を拡張します。`offset` を省略したメンバーは、その時点の配置方式で末尾へ追加します。メンバーは入力順に処理されます。
