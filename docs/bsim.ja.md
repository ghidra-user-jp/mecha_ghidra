[English](bsim.md) | [日本語](bsim.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# BSimで類似関数を探す

BSimは、関数のシグネチャを解析済みプログラムのデータベースと比較します。データベースに保存するのはシグネチャとメタデータです。デコンパイルや比較に必要なプログラムは元のGhidraプロジェクトにあるため、両方を保持してください。

このガイドは、接続可能なデータベースと読み込み済みプログラムがある状態から始めます。macOSでPostgreSQLバックエンドを作る場合は、管理者向けの[セットアップ](bsim-postgresql-macos.md) → [一括登録](bsim-ingestion.md) → [運用保守](bsim-operations.md)を参照してください。これらの手順には過去の検証環境を明記しています。

## データベースを接続する

`GHIDRA_INSTALL_DIR` を設定し、データベースのパスワードを環境変数 `BSIM_PASSWORD` に渡します。既存プロジェクトとプログラムを指定してください。

```bash
uv run ghidra-mcp \
  --project-location /work/analysis.gpr \
  --domain-path /sample.bin \
  --transport stdio \
  --add-category bsim \
  --bsim-url postgresql://bsim_user@localhost/malware_curated \
  --bsim-password-env BSIM_PASSWORD
```

`--bsim-url` は既定の接続先で、呼び出しごとの `bsim_url` でも指定できます。対応するschemeは `postgresql://`、`elastic://`、`https://`、`file:` です。ネットワーク認証には `--bsim-password-env` または `--bsim-password` の片方だけを使います。パスワードを設定し、URLのユーザー名を省いた場合はOSのユーザー名を使います。応答内のURLに含まれる認証情報はマスクされます。

最初に `get_bsim_database_status` を呼んでください。データベースのメタデータ、実行ファイル数、設定済みカテゴリ・関数タグ、実行環境の情報を確認できます。各バックエンドの引数は[ツールスキーマ](tools.ja.md#bsim)を参照してください。

## 検索して一致した関数を調べる

1. `list_functions` で関数のアドレスを取得します。
2. そのアドレスを `bsim_query_function` に渡します。複数関数は `addresses` または `function_names`、プログラム全体は `bsim_query_target` を使います。
3. スコアと、検索条件を記録した `query` を確認します。自己一致は既定で除外され、`exclude_self=false` で含められます。
4. 結果の `matched_ref` を、そのまま `bsim_load_matched_executable` に渡します。参照はバージョン付きで検証されるため、手作業で組み立て直さないでください。
5. 返されたターゲットを `get_function` や `decompile_function` に指定して、コードを比較します。

`bsim_query_function` の引数例です。アドレスを置き換えてください。

```json
{
  "target": "default",
  "address": "<function-address>",
  "similarity_threshold": 0.8,
  "matches_per_function": 5
}
```

Ghidra Serverにある `ghidra://` の一致を開くには、MCPサーバーへ `--bsim-remote-cache-dir /work/bsim-cache` とリポジトリ認証情報を設定します。プロジェクトの許可ルートを設定している場合は、その配下にキャッシュを置いてください。元プロジェクトを失っても検索結果は残る場合がありますが、プログラムを開いてデコンパイルすることはできません。

## 既知プログラムを登録・更新する

| やりたいこと | ツール・動作 |
| --- | --- |
| メタデータのカテゴリを追加 | `bsim_add_executable_category` |
| 読み込み中のプログラムを登録 | `bsim_register_target`。任意の `categories` はカテゴリごとに1値を持つオブジェクト |
| 登録済みレコードを確認 | `list_bsim_executables`、`get_bsim_executable` |
| 登録済みレコードのカテゴリを更新 | `bsim_update_executable_metadata`。md5または完全一致の名前で指定 |
| 関数名変更後に名前とメタデータを更新 | `bsim_update_target_signatures`。特徴ベクトルは再生成しない |
| 再解析後にベクトルを生成し直す | 旧レコードを明示的に削除し、再登録する |

登録前にデータベースへカテゴリ名を追加してください。未設定の名前や大小文字違いは `BSIM_EXECUTABLE_CATEGORY_NOT_CONFIGURED` で拒否します。登録時のカテゴリ値はProgram Informationにも保存するため、共有プログラムで指定する場合はチェックアウトが必要です。

`bsim_update_executable_metadata` は、省略したカテゴリを保持し、指定したカテゴリの値だけを置換します。`null` または空配列を渡すとクリアし、複数値も設定できます。引数例です。

```json
{
  "md5": "0123456789abcdef0123456789abcdef",
  "categories": {
    "FAMILY": "ExampleFamily",
    "SOURCE": "internal_analysis",
    "TRUST_LEVEL": "confirmed"
  }
}
```

登録済み実行ファイルの再登録は `BSIM_ALREADY_REGISTERED` になります。`bsim_delete_executable` は実行ファイルとその関数レコードを削除します。`confirm` にmd5、またはmd5省略時は完全一致の名前をもう一度指定する必要があります。

## 一致した関数名を適用する

`bsim_apply_matches(dry_run=true)` で名前とスコアをプレビューします。一致内容を確認したうえで、`dry_run=false` を明示して適用してください。既定ではGhidraの自動命名が残る関数だけを対象とし、全体を1つのトランザクションで変更します。適用後は `save_project_program` で保存し、必要に応じて `bsim_update_target_signatures` でデータベース内の名前も更新します。

認証、到達性、参照の形式に関するエラーは[トラブルシューティング](troubleshooting.ja.md)、データベースのバックアップや大量登録の問題は[BSim運用保守](bsim-operations.md)を参照してください。
