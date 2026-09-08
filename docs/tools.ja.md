[English](tools.md) | [日本語](tools.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# ツール一覧

用途からツールを探すための一覧です。呼び出し前にクライアントのツールスキーマを確認してください。全引数・制約・エラーコードはMCPリソース `ghidra://docs/tools` と `ghidra://docs/tools/{tool_name}` にあります。

多くのツールは `target`（既定値 `default`）で対象を選びます。`shared_sync` と `bsim` は既定では公開されません。[設定](configuration.ja.md#tool-exposure)で追加してください。

- [プロジェクトとセッション](#core)
- [関数解析](#function-analysis)
- [メモリとデータ](#memory-data)
- [シンボルとコメント](#symbol-comment-edit)
- [データ型](#datatype-ops)
- [共有プロジェクト](#shared-sync)
- [BSim](#bsim)
- [大きな結果の取得](#result-retrieval)

<a id="core"></a>

## プロジェクトとセッション

操作の順序と保存の動作は[最初の解析](usage.ja.md#first-analysis)を参照してください。

| ツール | 用途 |
| --- | --- |
| `list_targets` | 登録済みターゲットと紐づくプロジェクト情報を一覧表示 |
| `create_project` | 空のローカルGhidraプロジェクトを作成 |
| `open_program` | 既存プロジェクトのプログラムを開いてターゲットを追加 |
| `register_target` | プログラムを開かずにターゲットへプロジェクト情報のみ登録 |
| `close_session` | ターゲットのセッションを閉じる |
| `close_session_and_remove_program` | セッションを閉じたうえでプログラムをプロジェクトから削除 |
| `list_project_programs` | ターゲットが開いているプロジェクト内プログラム一覧を取得 |
| `import_program` | バイナリまたは `.gzf` をプロジェクトへインポート |
| `load_project_program` | 既存プログラムを指定 `domain_path` で読み込み。ターゲットが既に保持しているプログラムを指定すると再読み込み、`version=N` で共有プロジェクトの過去バージョンを読み取り専用で開く |
| `save_project_program` | 編集後の読み込み中のプログラムをGhidraプロジェクトに保存 |
| `get_program_info` | 言語、コンパイラ、イメージベース、md5/sha256、エントリポイント、解析済みフラグ、未保存変更、取り消し可否、変更を検出する `revision` |
| `undo_program_change` / `redo_program_change` | 読み込み中のプログラムの直近トランザクションを取り消し・やり直し |
| `export_program` | プログラムを `.gzf` または生バイト列で書き出し（`--allowed-export-root` で制限可） |

<a id="function-analysis"></a>

## 関数解析

| ツール | 用途 |
| --- | --- |
| `list_functions` | 関数一覧（サイズと thunkフラグ付き）。`filter` で名前を絞り、`only_default_names=true` で未命名の `FUN_` 関数だけを取得 |
| `list_namespaces` | 名前空間一覧を `{name, is_class}` で取得（ページング対応）。`classes_only=true` でクラスのみ |
| `decompile_function` | 関数名またはアドレス指定で C風の疑似コードを取得（両方指定時は `address` 優先） |
| `disassemble` | 関数またはアドレス範囲の既存命令をページ単位で取得 |
| `get_function` | 関数名またはアドレス指定でシグネチャ、引数、ローカル変数、本体範囲、thunk先、名前空間を取得（両方指定時は `address` 優先） |
| `create_function` | アドレスに関数を作成 |
| `delete_function` | アドレス指定で関数を削除 |
| `analyze_program` | 未解析のプログラムに解析を実行。`force=true` で再実行 |
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

既定の `atomic=true` では全件をまとめて確定し、1件でも失敗すると全件をロールバックします。`atomic=false` は成功した項目を保持し、失敗を個別に報告します。`dry_run=true` は実際に編集して変更前後の状態を取得した後、ロールバックします。このためdry runでも書き込み可能なプログラムと、共有管理済みファイルのチェックアウトが必要です。編集内容は残りませんが、revisionは進む場合があります。

読み取り後に別の編集が入っていないことを確認するには、最新の `get_program_info` または解析結果の `revision` を `expected_revision` に渡します。プレビュー後に `dry_run=false` で適用するときは、プレビューが返したrevisionを使えます。

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
| `bsim_apply_matches` | 既定名のままの関数を最良一致の名前で一括リネーム（`dry_run` 可） |
| `bsim_load_matched_executable` | 一致した実行ファイルを新しいターゲットとして開く。`ghidra://` の一致には `--bsim-remote-cache-dir` が必要 |

<a id="result-retrieval"></a>

## 大きな結果の取得

`--large-result-mode resource` のときに公開されます。[結果の取得とキャッシュ](configuration.ja.md#large-results)を参照してください。

| ツール | 用途 |
| --- | --- |
| `read_result` | 保存済み大型結果のスライスを読む（`offset_chars` / `limit_chars` で `has_more` が false になるまでページング。`limit_chars` のデフォルトは圧縮閾値の 1/3） |
| `search_result` | 保存済み大型結果を正規表現で検索。最大100件のスニペット、片側最大2,000文字の前後コンテキスト、`read_result` の offset にそのまま使えるマッチ位置を返す。`max_matches=0` では最大10,000件までスニペットなしで数えるため、`match_count` を全件数として扱う前に `scan_truncated` を確認 |

編集後は `save_project_program` で保存します。共有ファイルの編集にはチェックアウトが必要です。`remove_struct_members.members` はメンバー名の文字列と `{"name": ...}` オブジェクトのどちらも受け付けます。
