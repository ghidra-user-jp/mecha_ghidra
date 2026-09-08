[ドキュメント一覧](usage.ja.md) · [BSimの使い方](bsim.ja.md) · [セットアップ](bsim-postgresql-macos.md) → [一括登録](bsim-ingestion.md) → [運用保守](bsim-operations.md)

# macOSでBSim PostgreSQLを構築する

Ghidra同梱のPostgreSQLバックエンドをビルドし、空のBSimデータベースを作る管理者向け手順です。データの投入は[一括登録](bsim-ingestion.md)、MCPからの検索・登録は[BSimの使い方](bsim.ja.md)へ進んでください。

**検証範囲：** この手順のビルドとサーバー起動はGhidra 12.0.4で確認した記録です。Ghidra 12.1では同じデータベースへのMCP検索・読み込みを確認しています。現在の配布物での再検証を意味しません。詳細は[検証環境](#validated-environment)に残しています。

| 手順 | 完了の目安 |
| --- | --- |
| [1. 前提環境](#prerequisites) | Ghidraの管理コマンドとJavaが使える |
| [2. バックエンドのビルド](#build) | `postgres` とBSim拡張が生成される |
| [3. サーバー起動](#start) | `bsim_ctl status` と待ち受け先を確認できる |
| [4. データベース作成](#database) | `getexecount` が成功する |

BSimは関数シグネチャとメタデータを保存します。逆アセンブルやデコンパイルに必要な元プログラムはGhidraプロジェクトに残るため、データベースとプロジェクトを一体で管理してください。複数端末から使う場合は、各端末で到達できるGhidra ServerリポジトリのURLを使います。

| コマンド | 役割 |
| --- | --- |
| `support/bsim_ctl` | PostgreSQLバックエンドの初期化・起動・停止・ユーザー管理 |
| `support/bsim` | データベース作成、シグネチャ生成・投入、メタデータ・インデックス管理 |
| `support/analyzeHeadless` | 入力ファイルをGhidraプロジェクトへ取り込み、自動解析する前処理 |

<a id="prerequisites"></a>

## 1. 前提環境

macOS、Ghidra 12系と対応するJava、Xcode Command Line Tools、Homebrewが必要です。この管理ガイドではGhidraの場所を `GHIDRA_HOME` と表します。Mecha Ghidraを起動する場合は、別途 `GHIDRA_INSTALL_DIR` を設定してください。

以下のパスは検証時の例です。使用する配布物に合わせて変更します。

```bash
export GHIDRA_HOME="$HOME/ghidra/ghidra_12.0.4_PUBLIC"
test -x "$GHIDRA_HOME/support/bsim"
test -x "$GHIDRA_HOME/support/bsim_ctl"
test -x "$GHIDRA_HOME/support/analyzeHeadless"
java -version
```

Xcode Command Line Toolsが未導入の場合に `xcode-select --install` を実行し、ビルド依存を用意します。

```bash
brew install openssl@3 readline zlib icu4c bison flex
```

<a id="build"></a>

## 2. バックエンドをビルドする

Ghidra同梱のBSim拡張付きPostgreSQLをビルドします。Homebrewの通常のPostgreSQLだけでは代わりになりません。まずスクリプトの場所を確認します。

```bash
find "$GHIDRA_HOME/Ghidra/Features/BSim" -name make-postgres.sh -print
```

検証した12.0.4では `Ghidra/Features/BSim/support/make-postgres.sh` でした。以下はApple Siliconで使った設定です。Intel Macは `/opt/homebrew` を `brew --prefix` で確認したprefix（通常 `/usr/local`）へ置き換えてください。

```bash
export PATH="/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:$PATH"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/readline/include -I/opt/homebrew/opt/icu4c/include -I/opt/homebrew/opt/zlib/include -I/opt/homebrew/opt/flex/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/readline/lib -L/opt/homebrew/opt/icu4c/lib -L/opt/homebrew/opt/zlib/lib -L/opt/homebrew/opt/flex/lib -L/opt/homebrew/opt/bison/lib"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/readline/lib/pkgconfig:/opt/homebrew/opt/icu4c/lib/pkgconfig:/opt/homebrew/opt/zlib/lib/pkgconfig:/opt/homebrew/opt/flex/lib/pkgconfig"

cd "$GHIDRA_HOME/Ghidra/Features/BSim"
./support/make-postgres.sh
```

`zlib`、`bison`、`flex` はkeg-onlyのため、ビルドに使うパスを明示しています。検証時の `icu4c` は `icu4c@78` でした。パッケージの配置が違う場合は `brew --prefix <formula>` で確認してください。

Apple Siliconで生成物を確認する例です。Intelではプラットフォーム部分を `mac_x86_64` に変更します。

```bash
"$GHIDRA_HOME/Ghidra/Features/BSim/build/os/mac_arm_64/postgresql/bin/postgres" --version
find "$GHIDRA_HOME/Ghidra/Features/BSim/build/os" \
  \( -name lshvector.so -o -name pg_prewarm.so \) -print
```

検証時はPostgreSQL 15.13、`lshvector.so`、`pg_prewarm.so` を確認しました。警告が出た場合は[ビルドのトラブルシューティング](bsim-operations.md#build-errors)を参照してください。

<a id="start"></a>

## 3. サーバーを起動する

以下はTTYのあるターミナルから実行します。初期化だけでなく、再起動時にもパスワード入力が必要な場合があります。

```bash
mkdir -p "$HOME/bsim_pg_data"
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --auth password --port 5432
```

初回起動したOSユーザーが管理者になり、管理者パスワードの設定を求められます。Ghidra Serverの初期パスワード設定とは異なり、ここで自分で指定します。12.0.4では `auth=password port=5432` ではなく `--auth password --port 5432` 形式を使います。

検証時は `listen_addresses = '*'`、`ssl = on`、`hostssl ... scram-sha-256` が生成されました。ローカルだけで使う場合は外部接続を閉じた環境で初期化し、停止して `postgresql.conf` の待ち受けを絞ります。

```bash
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --port 5432
```

`$HOME/bsim_pg_data/postgresql.conf` の値を変更します。

```text
listen_addresses = 'localhost'
```

再起動して状態と待ち受け先を確認します。

```bash
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --port 5432
"$GHIDRA_HOME/support/bsim_ctl" status "$HOME/bsim_pg_data" --port 5432
lsof -nP -iTCP:5432 -sTCP:LISTEN
```

ローカル構成では `127.0.0.1` と `::1` だけで待ち受けることを確認します。リモート利用時は接続元、認証、証明書を用途に合わせて設定してください。

<a id="database"></a>

## 4. データベースを作成する

ここでは `medium_nosize` テンプレートを使います。利用可能なテンプレートは、手元の `support/bsim` のusageを優先してください。

```bash
"$GHIDRA_HOME/support/bsim" createdatabase \
  postgresql://localhost/malware_curated \
  medium_nosize \
  --name "Malware Curated BSim DB" \
  --owner "BSim" \
  --description "Curated known malware function similarity database"

"$GHIDRA_HOME/support/bsim" getexecount postgresql://localhost/malware_curated
```

要求された管理者パスワードを入力します。空のデータベースなので、この時点では実行ファイル数が0でも正常です。12.0.4で確認したテンプレートは `large_32`、`medium_32`、`medium_64`、`medium_cpool`、`medium_nosize` で、`large_nosize` はありませんでした。

次は[既知プログラムの一括登録](bsim-ingestion.md)へ進みます。MCPを使って少数ずつ登録する場合は[BSimの使い方](bsim.ja.md)を参照してください。

<a id="validated-environment"></a>

## 検証環境の記録

<details>
<summary>過去の検証バージョンと確認した操作</summary>

この手順は、次の環境で実際にbuildと投入確認まで実行しました。

- macOS 26.4.1
- Apple Silicon Mac: `arm64`
- Ghidra 12.0.4 PUBLIC（PostgreSQL backend build/server、BSim CLI投入確認）
- Ghidra 12.1 PUBLIC（BSim CLI usage確認、PyGhidra/MCP BSim clientでquery、matched executable load、decompileを実測）
- Java: Temurin OpenJDK 21.0.8
- Homebrew prefix: `/opt/homebrew`
- Ghidra同梱PostgreSQL source: PostgreSQL 15.13
- build先: `$GHIDRA_HOME/Ghidra/Features/BSim/build/os/mac_arm_64/postgresql`
- BSim PostgreSQL data directory: `$HOME/bsim_pg_data`
- 検証DB: `postgresql://localhost/malware_curated`
- 稼働状態: 初回起動後に`listen_addresses = 'localhost'`へ変更し、`127.0.0.1:5432`と`[::1]:5432`だけでlisten

実測では、Ghidra 12.0.4でBSim拡張`lshvector`と`pg_prewarm`がbuildされ、BSim DB作成、カテゴリ追加、Ghidra Projectからのsignature生成、`commitsigs`、`getexecount`、`listexes`、`dropindex`、`rebuildindex`、`prewarm`まで成功しました。`listen_addresses`を`localhost`へ絞った後も、`getexecount`で投入済み実行ファイルを確認できています。

Ghidra 12.1では、12.0.4で起動した同じPostgreSQL BSim DBに対して、MCP/PyGhidra経由の`get_bsim_database_status`、`bsim_query_function`、`bsim_load_matched_executable`、`decompile_function`が成功することを確認しています。12.1自身でPostgreSQL serverを起動する場合は、12.1側の`Ghidra/Features/BSim/support/make-postgres.sh`でbackendをbuildしてください。

Ghidraのバージョンにより、コマンドのオプション表記、config template、同梱PostgreSQLのバージョン、`make-postgres.sh`の場所が変わる可能性があります。迷ったら、必ず手元のコマンドのusageを確認してください。

```bash
"$GHIDRA_HOME/support/bsim"
"$GHIDRA_HOME/support/bsim_ctl"
"$GHIDRA_HOME/support/analyzeHeadless"
```

</details>

## 公式ドキュメント

- [BSimの概要](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md)
- [BSimのコマンドライン操作](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_BSim_Command_Line.md)
- 使用中のGhidraに同梱されるBSimヘルプのDatabase ConfigurationとCommand-Line Utility Reference
