[ドキュメント一覧](usage.ja.md) · [BSimの使い方](bsim.ja.md) · [セットアップ](bsim-postgresql-macos.md) → [一括登録](bsim-ingestion.md) → [運用保守](bsim-operations.md)

# 既知プログラムをBSimへ一括登録する

[セットアップ](bsim-postgresql-macos.md)を終え、PostgreSQLが起動している状態から始めます。`GHIDRA_HOME` は使用するGhidraの展開先に設定してください。以下のコマンド形式はGhidra 12.0.4で確認したものです。

```text
入力ファイル → analyzeHeadless → 解析済みGhidraプロジェクト
                                      ↓ generatesigs
                                シグネチャファイル
                                      ↓ commitsigs
                                BSimデータベース
```

MCPから1プログラムずつ登録する方法は[BSimの使い方](bsim.ja.md)を参照してください。このページはGhidra付属CLIによる一括処理を扱います。

## 1. メタデータのカテゴリを追加する

```bash
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated FAMILY
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated SOURCE
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated TRUST_LEVEL
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated ORIGIN
```

| カテゴリ例 | 値の例 |
| --- | --- |
| `FAMILY` | ファミリ名 |
| `SOURCE` | `public_report`、`internal_analysis` |
| `TRUST_LEVEL` | `confirmed`、`likely`、`unverified` |
| `ORIGIN` | `malware`、`benign`、`oss_library` |

カテゴリの追加だけではプログラムに値は付きません。Program Informationへ値を設定してから生成するか、登録後にMCPの `bsim_update_executable_metadata` で更新します。

## 2. Ghidraプロジェクトへ取り込んで解析する

`$HOME/samples/known` に対象ファイルを置きます。`malware_known` は新規の取り込み用プロジェクト名です。

```bash
mkdir -p "$HOME/ghidra_projects"

"$GHIDRA_HOME/support/analyzeHeadless" \
  "$HOME/ghidra_projects" malware_known \
  -import "$HOME/samples/known" \
  -recursive \
  -analysisTimeoutPerFile 120
```

`malware_known.gpr` と `malware_known.rep` が作成されます。解析・保存・インポートの成功ログを確認してください。解析時間の上限は1ファイルあたり120秒の例です。対象の規模に合わせて調整します。

`analyzeHeadless` はBSimの前処理です。この後のシグネチャ生成では、ここに保存した解析済みプログラムを使います。同じローカルプロジェクトは、GUIやMCPで開いたままにしないでください。

## 3. シグネチャを生成する

```bash
mkdir -p "$HOME/bsim_sigs"

"$GHIDRA_HOME/support/bsim" generatesigs \
  "ghidra:${HOME}/ghidra_projects/malware_known" \
  "$HOME/bsim_sigs" \
  --bsim postgresql://localhost/malware_curated \
  --overwrite
```

データベース設定とカテゴリを読み、`sigs_<md5>` ファイルを出力します。`--overwrite` は既存のシグネチャ出力を上書きする指定です。12.0.4では `bsim=<url>` ではなく `--bsim <url>` を使います。

| Ghidra URL | 意味 |
| --- | --- |
| `ghidra:/Users/yourname/ghidra_projects/malware_known` | ローカルプロジェクト |
| `ghidra://ghidra-server.example.local/malware_repo/known` | サーバーのリポジトリ・フォルダ |

シェルでホームディレクトリを使う場合は `"ghidra:${HOME}/..."` とします。`ghidra:/$HOME/...` は余分な `/` によりリモートURLに見える形になるため使わないでください。ローカルURLはその端末のパスを記録するため、ほかの端末から元プログラムを開く運用には共有リポジトリを検討します。

## 4. データベースへ投入する

```bash
"$GHIDRA_HOME/support/bsim" commitsigs \
  postgresql://localhost/malware_curated \
  "$HOME/bsim_sigs"
```

`Writing signatures for ...` を確認します。生成と投入をまとめる場合は、前段の `generatesigs` に `--commit` を追加できます。

`commitsigs` はシグネチャ内のGhidra URLも保存します。後からプロジェクトを移動すると、検索結果から元プログラムを開けなくなる場合があります。投入前に配置を決めてください。URLを書き換える必要がある場合は、使用中の `commitsigs` のusageで `--override <ghidraURL>` の対応を確認します。

## 5. 投入結果を確認する

```bash
"$GHIDRA_HOME/support/bsim" getexecount postgresql://localhost/malware_curated
"$GHIDRA_HOME/support/bsim" listexes postgresql://localhost/malware_curated --limit 20
```

検証時は、1つの `bsim_hello` プログラムで `Matching executable count: 1` と一覧表示を確認しました。全件確認では名前フィルタを付けません。12.0.4の検証では `name=*` や `--name '*'` は全件指定として扱われず、0件になりました。特定名なら `--name bsim_hello` のように指定します。

次はMCPの [bsim_query_function](bsim.ja.md) で検索します。大量登録時のインデックス管理、バックアップ、失敗時の確認は[運用保守](bsim-operations.md)にまとめています。

## 公式ドキュメント

- [Ghidraのコマンドライン解析](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Ghidra_Command_Line.md)
- [BSimのコマンドライン操作](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_BSim_Command_Line.md)
