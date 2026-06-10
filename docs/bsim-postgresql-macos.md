# macOSでGhidra公式BSim PostgreSQL backendをセットアップする

このドキュメントは、macOS上でGhidra公式配布物に含まれるBSim PostgreSQL backendを導入し、BSim databaseの作成、Ghidra Projectの解析、signature生成、commit、投入確認までを行うための手順です。

外部プロジェクトには依存せず、Ghidra公式に含まれるBSim、`support/bsim`、`support/bsim_ctl`、`support/analyzeHeadless`だけを使います。

## 実測環境

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

## 1. 概要

- BSimは、Ghidraの関数類似検索機能です。関数ごとのsignatureを生成し、既知検体や既知ライブラリの関数と似た関数を検索できます。
- PostgreSQL backendは、数千検体以上の既知検体DBを継続運用する用途に向いています。
- H2 backendは導入が簡単ですが、小規模・単一ユーザー・ローカル検証向けです。この手順ではPostgreSQL backendを使います。
- BSim DBは関数signatureとメタデータを保存します。逆アセンブル結果やデコンパイル結果そのものは保存しません。
- 検索結果から比較表示や後続解析を行うには、BSim DBに記録されたGhidra URLが指すGhidra Project側のProgramが必要です。BSim DBとGhidra ProjectまたはGhidra Server repositoryはセットで管理してください。

役割の違い:

- `support/bsim_ctl`: BSim PostgreSQL serverの初期化、起動、停止、認証変更、ユーザー管理に使うPostgreSQL backend専用ツールです。
- `support/bsim`: BSim DB作成、metadata設定、signature生成、commit、件数確認、index管理に使うBSim管理ツールです。
- `support/analyzeHeadless`: BSimそのものではありません。大量の実行ファイルをGhidra Projectへimportし、Ghidraの自動解析を走らせるために使います。

## 2. 推奨構成

```text
Ghidra / analyzeHeadless
  ↓
Analyzed Ghidra Project
  ↓
support/bsim generatesigs
  ↓
support/bsim commitsigs
  ↓
BSim PostgreSQL Database
```

補足:

- ローカル検証はローカルGhidra Projectで始められます。
- 複数端末や複数ユーザーで使う場合は、Ghidra Server上のshared projectを検討してください。ローカルProject URLは端末固有のパスとしてBSim DBに記録されるため、他の端末から同じProgramを開けないことがあります。

## 3. 前提環境

- macOS
- Ghidra 12系
- Ghidra 12系が要求するJava
- Xcode Command Line Tools
- Homebrew
- Apple Silicon MacまたはIntel Mac

この手順では、Ghidraのインストール先を`GHIDRA_HOME`で表します。実測では次を使いました。

```bash
export GHIDRA_HOME="$HOME/ghidra/ghidra_12.0.4_PUBLIC"
```

確認例:

```bash
test -x "$GHIDRA_HOME/support/bsim"
test -x "$GHIDRA_HOME/support/bsim_ctl"
test -x "$GHIDRA_HOME/support/analyzeHeadless"
java -version
```

## 4. 依存パッケージの導入

Xcode Command Line Toolsと、PostgreSQL buildで使うHomebrewパッケージを導入します。

```bash
xcode-select --install
brew install openssl@3 readline zlib icu4c bison flex
```

注意点:

- Apple Silicon MacのHomebrew prefixは通常`/opt/homebrew`です。
- Intel MacのHomebrew prefixは通常`/usr/local`です。
- `zlib`、`bison`、`flex`はkeg-onlyとして入るため、build時に環境変数で明示すると安定します。
- 実測環境では`icu4c`は`icu4c@78`として入り、`/opt/homebrew/opt/icu4c`から参照できました。

## 5. BSim用PostgreSQLのbuild

Ghidra公式のBSim PostgreSQL backendは、通常のHomebrew版PostgreSQLをそのまま使う構成ではありません。Ghidraに含まれるBSim拡張付きPostgreSQLをbuildします。

まず`make-postgres.sh`の場所を確認します。

```bash
cd "$GHIDRA_HOME/Ghidra/Features/BSim"
find . -name "make-postgres.sh" -print
```

Ghidra 12.0.4では次にありました。

```text
Ghidra/Features/BSim/support/make-postgres.sh
```

Apple Silicon Macの実測で使った環境変数:

```bash
export PATH="/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:$PATH"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/readline/include -I/opt/homebrew/opt/icu4c/include -I/opt/homebrew/opt/zlib/include -I/opt/homebrew/opt/flex/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/readline/lib -L/opt/homebrew/opt/icu4c/lib -L/opt/homebrew/opt/zlib/lib -L/opt/homebrew/opt/flex/lib -L/opt/homebrew/opt/bison/lib"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/readline/lib/pkgconfig:/opt/homebrew/opt/icu4c/lib/pkgconfig:/opt/homebrew/opt/zlib/lib/pkgconfig:/opt/homebrew/opt/flex/lib/pkgconfig"

cd "$GHIDRA_HOME/Ghidra/Features/BSim"
./support/make-postgres.sh
```

Intel Macではprefixを`/usr/local`に置き換えます。

```bash
export PATH="/usr/local/opt/bison/bin:/usr/local/opt/flex/bin:$PATH"
export CPPFLAGS="-I/usr/local/opt/openssl@3/include -I/usr/local/opt/readline/include -I/usr/local/opt/icu4c/include -I/usr/local/opt/zlib/include -I/usr/local/opt/flex/include"
export LDFLAGS="-L/usr/local/opt/openssl@3/lib -L/usr/local/opt/readline/lib -L/usr/local/opt/icu4c/lib -L/usr/local/opt/zlib/lib -L/usr/local/opt/flex/lib -L/usr/local/opt/bison/lib"
export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig:/usr/local/opt/readline/lib/pkgconfig:/usr/local/opt/icu4c/lib/pkgconfig:/usr/local/opt/zlib/lib/pkgconfig:/usr/local/opt/flex/lib/pkgconfig"

cd "$GHIDRA_HOME/Ghidra/Features/BSim"
./support/make-postgres.sh
```

成功確認:

```bash
"$GHIDRA_HOME/Ghidra/Features/BSim/build/os/mac_arm_64/postgresql/bin/postgres" --version
find "$GHIDRA_HOME/Ghidra/Features/BSim/build/os" \
  \( -name "lshvector.so" -o -name "pg_prewarm.so" \) -print
```

実測では次を確認しました。

```text
postgres (PostgreSQL) 15.13
.../postgresql/lib/lshvector.so
.../postgresql/lib/pg_prewarm.so
```

補足:

- 初回build時に`make distclean`が`You need to run the 'configure' program first`と出すことがあります。実測ではその後configureとbuildが続き、最終的に成功しました。
- macOS 26系では、Homebrewのdylibがより新しいmacOS向けにbuildされているというlinker warningが出ましたが、今回の検証では実行に支障はありませんでした。
- Homebrew版PostgreSQLを`brew install postgresql`しても、BSim拡張付きserverの代わりにはなりません。

## 6. BSim PostgreSQL serverの起動

データディレクトリを作成します。

```bash
mkdir -p "$HOME/bsim_pg_data"
```

Ghidra 12.0.4の実測では、`bsim_ctl`は`auth=password port=5432`ではなく、`--auth password --port 5432`形式でした。

```bash
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --auth password --port 5432
```

初回起動時は、管理者パスワードを対話入力します。

```text
Set admin(<your-user>) password:
Please re-enter password:
```

実測では検証用に`changeme`を設定しました。Ghidra 12.0.4では、`changeme`が自動で設定されるのではなく、初回起動時に自分で設定する挙動でした。本番運用では強いパスワードを設定してください。

ローカル端末だけで検証する場合は、初回起動後に`listen_addresses`を`localhost`へ絞ることを推奨します。実測ではこの変更後もBSim CLIから接続できました。

```bash
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --port 5432
perl -0pi -e "s/^listen_addresses = '\\*'/listen_addresses = 'localhost'/m" "$HOME/bsim_pg_data/postgresql.conf"
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --port 5432
```

状態確認:

```bash
"$GHIDRA_HOME/support/bsim_ctl" status "$HOME/bsim_pg_data" --port 5432
```

停止:

```bash
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --port 5432
```

強制停止:

```bash
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --force --port 5432
```

重要な注意点:

- `bsim_ctl`はPostgreSQL backend専用です。H2 backendの管理には使いません。
- 初回起動したOSユーザーが、BSim PostgreSQL server上の管理者ユーザーになります。
- `--auth password`では、remote client authenticationはpasswordになります。
- 実測では、生成された`pg_hba.conf`は`hostssl ... scram-sha-256`を使い、`postgresql.conf`は`ssl = on`でした。
- 実測では、`listen_addresses = '*'`になり、PostgreSQLが`0.0.0.0:5432`と`[::]:5432`でlistenしました。ローカル検証でもネットワークから見える可能性があるため、firewall、listen address、接続元制限を必ず確認してください。
- 非対話実行でパスワード入力を通そうとすると、実測ではGhidra 12.0.4が`NullPointerException`で失敗しました。初回初期化だけでなく、既存data directoryの`start`でも拡張有効化確認のためパスワードを求めることがありました。`--auth password`運用では、`bsim_ctl start`をTTY上で実行してください。

## 7. BSim DBの作成

数千検体規模から始める場合、32bit/64bit間の類似検索を考慮しやすい`medium_nosize`を基本にします。

```bash
"$GHIDRA_HOME/support/bsim" createdatabase \
  postgresql://localhost/malware_curated \
  medium_nosize \
  --name "Malware Curated BSim DB" \
  --owner "BSim" \
  --description "Curated known malware function similarity database"
```

実行時にDB管理者ユーザーのパスワードを入力します。

```text
Password for <your-user>:
```

Ghidra MCPからBSim toolを使う場合は、サーバ起動時にBSim URLとパスワードを渡します。継続利用では、shell履歴に残りにくい`--bsim-password-env`を推奨します。

```bash
export BSIM_PASSWORD="<password>"

uv run ghidra-mcp \
  --project-location "$HOME/ghidra_projects/bsim_pg_demo.gpr" \
  --domain-path /bsim_hello \
  --tool-profile full \
  --bsim-url "postgresql://${USER}@localhost/malware_curated" \
  --bsim-password-env BSIM_PASSWORD
```

一時的なローカル検証では、文字列を直接渡すこともできます。

```bash
uv run ghidra-mcp \
  --project-location "$HOME/ghidra_projects/bsim_pg_demo.gpr" \
  --domain-path /bsim_hello \
  --tool-profile full \
  --bsim-url "postgresql://${USER}@localhost/malware_curated" \
  --bsim-password "<password>"
```

`--bsim-password`または`--bsim-password-env`を使う場合、BSim URLにユーザー名がなければOSユーザー名を使います。別ユーザーで接続する場合は`postgresql://user@host/database`の形で明示してください。MCP側では`postgresql://`、`elastic://`、`https://`、`file:`のBSim URL schemeを受け付けます。返却値やエラー内のBSim URLは`postgresql://***:***@...`のようにマスクされます。

MCPのBSim toolは、小さいprimitiveを組み合わせて使う前提です。`get_bsim_database_status`はDB metadata、executable count、PostgreSQL server version、Ghidra version、client側のGhidra install pathを返します。`bsim_add_executable_category`は実行ファイルカテゴリをDBに追加し、`bsim_update_executable_metadata`は既存executable recordのカテゴリ値を`md5`または実行ファイル名で後追い更新します。`bsim_query_target`と`bsim_query_function`の結果には、検索条件を示す`query` provenanceと、`bsim_load_matched_executable`へそのまま渡せる`matched_ref`が含まれます。`matched_ref`には`matched_ref_version: 1`が入り、load時には必須キーが検証されます。

実測結果:

```text
Created database: Malware Curated BSim DB
   owner       = BSim
   description = Curated known malware function similarity database
   template    = medium_nosize
```

config templateについて:

- Ghidra 12.0.4の実測usageでは、`large_32`、`medium_32`、`medium_64`、`medium_cpool`、`medium_nosize`が列挙されました。
- この環境のGhidra 12.0.4では`large_nosize`は列挙されませんでした。将来のGhidraで`large_nosize`がusageに出る場合は、大規模かつ32bit/64bit間のmatchを重視するDBで検討してください。
- `medium`はおおむね1000万関数規模の目安として扱えます。
- `large`系はさらに大規模なDB向けですが、利用可能なtemplateは手元の`support/bsim` usageを優先してください。

## 8. 実行ファイルカテゴリの追加

検索やDB管理でfilterしやすいように、実行ファイルカテゴリを追加します。

MCPで追加する場合:

```json
{"category": "FAMILY"}
{"category": "SOURCE"}
{"category": "TRUST_LEVEL"}
{"category": "ORIGIN"}
```

上記を`bsim_add_executable_category`へ渡します。`--bsim-url`をMCP起動時に指定していない場合は、各呼び出しで`bsim_url`も渡してください。

Ghidra付属CLIで追加する場合:

```bash
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated FAMILY
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated SOURCE
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated TRUST_LEVEL
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated ORIGIN
```

カテゴリ例:

- `FAMILY`: マルウェアファミリ名
- `SOURCE`: `public_report`、`internal_analysis`など
- `TRUST_LEVEL`: `confirmed`、`likely`、`unverified`など
- `ORIGIN`: `malware`、`benign`、`oss_library`など

注意点:

- カテゴリを追加するだけでは、各Programに値は入りません。
- 新規登録前に値を入れる場合は、targetを開いて`bsim_set_target_metadata`を呼んでから`bsim_register_target`を呼びます。
- 登録済みrecordを後から更新する場合は、`bsim_update_executable_metadata`に`md5`または`name`と`categories`を渡します。未指定カテゴリは既存値を保持し、渡したカテゴリだけ置換します。値に`null`または空配列を渡すと、そのカテゴリをクリアします。

登録済みrecordを更新する例:

```json
{
  "md5": "0123456789abcdef0123456789abcdef",
  "categories": {
    "FAMILY": "Emotet",
    "SOURCE": "internal_analysis",
    "TRUST_LEVEL": "confirmed"
  }
}
```

## 9. Ghidra Projectへのimportと解析

ローカルProjectで始める例です。

```bash
mkdir -p "$HOME/ghidra_projects"

"$GHIDRA_HOME/support/analyzeHeadless" \
  "$HOME/ghidra_projects" malware_known \
  -import "$HOME/samples/known" \
  -recursive \
  -analysisTimeoutPerFile 120
```

実測では、検証用に小さなMach-O arm64実行ファイルを作り、次のコマンドでProjectへimportしました。

```bash
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$HOME/ghidra_projects" bsim_pg_demo \
  -import "$HOME/bsim_samples/bsim_hello" \
  -overwrite \
  -analysisTimeoutPerFile 120
```

実測結果:

```text
Using Loader: Mac OS X Mach-O
Using Language/Compiler: AARCH64:LE:64:AppleSilicon:default
REPORT: Analysis succeeded
REPORT: Save succeeded for: /bsim_hello
REPORT: Import succeeded
```

補足:

- `analyzeHeadless`はBSimそのものではありません。BSim signatureを生成する前段として、解析済みProgramをGhidra Projectに入れるために使います。
- 上の例では、`$HOME/ghidra_projects/malware_known.gpr`と`$HOME/ghidra_projects/malware_known.rep`が作成されます。
- BSim DBは逆アセンブル結果やデコンパイル結果を保存しません。Ghidra Projectを消すと、検索結果から元Programを開く操作や比較表示に支障が出ます。
- 本格運用ではGhidra Serverのshared projectも検討してください。

## 10. BSim signature生成

解析済みGhidra Projectからsignatureを生成します。Ghidra 12.0.4の実測では、`bsim=<url>`ではなく`--bsim <url>`形式を使いました。

```bash
mkdir -p "$HOME/bsim_sigs"

"$GHIDRA_HOME/support/bsim" generatesigs \
  "ghidra:${HOME}/ghidra_projects/malware_known" \
  "$HOME/bsim_sigs" \
  --bsim postgresql://localhost/malware_curated \
  --overwrite
```

実測で使ったローカルProject例:

```bash
"$GHIDRA_HOME/support/bsim" generatesigs \
  "ghidra:${HOME}/ghidra_projects/bsim_pg_demo" \
  "$HOME/bsim_sigs" \
  --bsim postgresql://localhost/malware_curated \
  --overwrite
```

実測では、DB設定とカテゴリを読み込んだうえでsignatureが生成されました。

```text
Using configuration for:
 Database: Malware Curated BSim DB
 Owner:    BSim
 Categories:
   FAMILY
   SOURCE
   TRUST_LEVEL
   ORIGIN

Generating signatures for: bsim_hello
```

出力例:

```text
$HOME/bsim_sigs/sigs_db8ce40fd869106fef816f69e4ce2c77
```

Ghidra URLの例:

```text
ghidra:/Users/yourname/ghidra_projects/malware_known
ghidra:${HOME}/ghidra_projects/malware_known
ghidra://localhost/malware_repo/known
ghidra://ghidra-server.example.local/malware_repo/known
```

注意点:

- ローカルProject URLは`ghidra:`の直後に絶対パスを書きます。
- Bashで`$HOME`を使う場合は、`ghidra:${HOME}/...`のように書くと実際には`ghidra:/Users/...`になり、ローカルProject URLとして扱いやすいです。
- `ghidra:/$HOME/...`はshell展開後に`ghidra://Users/...`のように見え、remote URLと紛らわしくなるため避けます。
- `generatesigs`はBSim DBの設定を参照するため、BSim PostgreSQL serverが起動している必要があります。

## 11. BSim DBへのcommit

生成したsignatureをBSim DBへ投入します。

```bash
"$GHIDRA_HOME/support/bsim" commitsigs \
  postgresql://localhost/malware_curated \
  "$HOME/bsim_sigs"
```

実測結果:

```text
Writing signatures for sigs_db8ce40fd869106fef816f69e4ce2c77
```

signature生成とcommitを一度に行うこともできます。Ghidra 12.0.4のusageでは次の形式です。

```bash
"$GHIDRA_HOME/support/bsim" generatesigs \
  "ghidra:${HOME}/ghidra_projects/malware_known" \
  "$HOME/bsim_sigs" \
  --bsim postgresql://localhost/malware_curated \
  --commit \
  --overwrite
```

補足:

- `commitsigs`はsignatureに記録されたGhidra URLをBSim DBへ保存します。
- Projectの場所を投入後に変えると、検索結果からProgramを開けなくなることがあります。
- `commitsigs`の`--override <ghidraURL>`でURLを上書きできる場合がありますが、運用を複雑にするため、投入前にProject配置を固めることを推奨します。

## 12. 投入確認

全件数を確認します。

```bash
"$GHIDRA_HOME/support/bsim" getexecount \
  postgresql://localhost/malware_curated
```

実測結果:

```text
Matching executable count: 1
```

一覧を確認します。

```bash
"$GHIDRA_HOME/support/bsim" listexes \
  postgresql://localhost/malware_curated \
  --limit 20
```

実測結果:

```text
db8ce40fd869106fef816f69e4ce2c77 bsim_hello AARCH64:LE:64:AppleSilicon default
1 executables found
```

名前で絞る例:

```bash
"$GHIDRA_HOME/support/bsim" getexecount \
  postgresql://localhost/malware_curated \
  --name bsim_hello
```

実測では、旧来の例で見かける`name=*`や`--name '*'`は全件matchとしては扱われず、0件になりました。全件を確認する場合はfilterを付けずに実行してください。

## 13. 大量投入時の運用

大量のsignatureを一括投入する場合、投入前にindexをdropし、投入後にrebuildすると速くなる場合があります。

```bash
"$GHIDRA_HOME/support/bsim" dropindex postgresql://localhost/malware_curated
"$GHIDRA_HOME/support/bsim" rebuildindex postgresql://localhost/malware_curated
"$GHIDRA_HOME/support/bsim" prewarm postgresql://localhost/malware_curated
```

実測結果:

```text
Successfully dropped index for database Malware Curated BSim DB
Starting rebuild ...
Successfully rebuilt index for database Malware Curated BSim DB
Successfully prewarmed 2 blocks of main index for database Malware Curated BSim DB
```

注意点:

- indexがない間はqueryが遅くなります。
- 本番DBでは、drop/rebuildをメンテナンス時間帯に行ってください。
- `rebuildindex`は投入完了後に実行します。
- `prewarm`は再起動直後の初回queryを軽くしたい場合に使えます。効果はDBサイズ、メモリ、OS cache、運用状況に依存します。

## 14. バックアップ方針

次の2点を一体でバックアップしてください。

- BSim PostgreSQL DB
- Ghidra ProjectまたはGhidra Server repository

理由:

- BSim DBはsignatureとメタデータを保存します。
- Ghidra Projectは解析済みProgram、逆アセンブル情報、デコンパイル表示に必要なProgram状態を保存します。
- BSim DBだけを復元しても、記録されたGhidra URLの先にProgramがなければ、検索結果から比較表示や後続解析ができません。

推奨:

- 検体そのもの、hash、入手元、family、campaign、解析者、信頼度などは、CSV、SQLite、別DBなどでも管理しておくと再構築しやすくなります。
- BSim DBとGhidra Projectのbackup時刻をそろえ、どのProject snapshotからどのBSim DBを作ったかを記録してください。

## 15. トラブルシュート

### `make-postgres.sh`が見つからない

- `GHIDRA_HOME`がGhidra配布物のrootを指しているか確認します。
- `find "$GHIDRA_HOME" -name "make-postgres.sh" -print`で探します。
- Ghidraのバージョン差で配置が変わることがあります。

```bash
find "$GHIDRA_HOME" -name "make-postgres.sh" -print
```

### OpenSSL / readline / zlib / bison / flexが見つからずbuildに失敗する

- `brew install openssl@3 readline zlib icu4c bison flex`を実行します。
- Apple Siliconなら`/opt/homebrew`、Intelなら`/usr/local`を前提に、`PATH`、`CPPFLAGS`、`LDFLAGS`、`PKG_CONFIG_PATH`を設定します。
- `brew --prefix <formula>`で実際のprefixを確認します。

```bash
brew --prefix openssl@3
brew --prefix readline
brew --prefix zlib
brew --prefix bison
brew --prefix flex
```

### 初回`make distclean`で警告が出る

初回展開直後に次の警告が出ることがあります。

```text
You need to run the 'configure' program first.
make: *** [distclean] Error 1
```

実測では、この警告のあとconfigureとbuildが続き、最終的に成功しました。そこで停止していなければ、続く出力を確認してください。

### `bsim_ctl start`がパスワード入力で落ちる

実測では、`bsim_ctl start`を非対話で走らせるとパスワード入力に失敗し、`NullPointerException`になりました。初回起動だけでなく、既存data directoryの再起動でも発生しました。

- `bsim_ctl start`はTTY上で実行してください。
- `Set admin(<user>) password:`と`Please re-enter password:`に入力します。
- 途中失敗した空のdata directoryは、内容を確認してから作り直してください。

### `bsim_ctl start`でポート衝突する

- 既に5432でPostgreSQLなどが起動している可能性があります。
- 別portで初期化する場合は、初回`start`時に`--port <port>`を指定します。
- DB URLにもportを含めます。

```bash
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --auth password --port 15432
"$GHIDRA_HOME/support/bsim" createdatabase postgresql://localhost:15432/malware_curated medium_nosize
```

### ネットワークに広くlistenしてしまう

実測では、`postgresql.conf`に`listen_addresses = '*'`が設定され、`0.0.0.0:5432`と`[::]:5432`でlistenしました。

- ローカル検証だけならfirewallで外部接続を閉じてください。
- 必要に応じて`$HOME/bsim_pg_data/postgresql.conf`の`listen_addresses`を`localhost`へ変更し、serverを再起動してください。
- 本番運用では接続元、ユーザー権限、証明書、監査、backupを設計してください。

```bash
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --port 5432
perl -0pi -e "s/^listen_addresses = '\\*'/listen_addresses = 'localhost'/m" "$HOME/bsim_pg_data/postgresql.conf"
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --port 5432
lsof -nP -iTCP:5432 -sTCP:LISTEN
```

### `auth=password`でログインできない

- Ghidra 12.0.4では、初回起動時に管理者パスワードを自分で設定します。
- 初回起動したOSユーザーが管理者ユーザーになります。
- パスワード変更は手元の`bsim_ctl` usageを確認してください。Ghidra 12.0.4のusageでは`resetpassword <username>`形式でした。

```bash
"$GHIDRA_HOME/support/bsim_ctl" resetpassword "$USER" --port 5432
```

### `createdatabase`で接続エラーになる

- `bsim_ctl status "$HOME/bsim_pg_data" --port 5432`でserver状態を確認します。
- portが5432以外なら、BSim DB URLにもportを含めます。
- `--auth password`の場合、実行時に要求されるパスワードを入力します。
- SSLや証明書まわりのエラーは、`pg_hba.conf`、`postgresql.conf`、BSim client側の接続設定を確認してください。
- MCP toolのエラーは、認証失敗なら`BSIM_AUTHENTICATION_FAILED`、接続不能なら`BSIM_DATABASE_UNREACHABLE`、URL未指定なら`BSIM_URL_REQUIRED`、不正なURLなら`BSIM_URL_INVALID`、不正なthreshold/limitなら`BSIM_PARAMETER_INVALID`、不正な`matched_ref`なら`BSIM_INVALID_MATCHED_REF`のように分類されます。

### `large_nosize`が使えない

Ghidra 12.0.4の実測usageでは`large_nosize`は列挙されませんでした。

```text
large_32 | medium_32 | medium_64 | medium_cpool | medium_nosize
```

32bit/64bit間のmatchを重視する場合は`medium_nosize`を使います。将来のGhidraで`large_nosize`がusageに出る場合は、大規模DB向けに検討してください。

### `generatesigs`で`ghidra:` URLが間違っている

- ローカルProjectは`ghidra:/Users/yourname/ghidra_projects/project_name`のように指定します。
- Bashの`$HOME`を使う場合は`ghidra:${HOME}/ghidra_projects/project_name`が安全です。
- Ghidra Server repositoryの場合は`ghidra://host/repository/folder`です。
- ローカルProjectをGhidra GUIで開いたままだとlockにより失敗する場合があります。

### `commitsigs`後に`getexecount`が0のまま

- `generatesigs`の出力先に`sigs_<md5>`ファイルが生成されているか確認します。
- `commitsigs`のBSim DB URLが、作成したDBと同じか確認します。
- `name=*`や`--name '*'`で確認すると0件になる場合があります。まずfilterなしで確認してください。

```bash
"$GHIDRA_HOME/support/bsim" getexecount postgresql://localhost/malware_curated
```

### 大量投入が遅い

- 先に`dropindex`し、投入後に`rebuildindex`すると速くなる場合があります。
- `generatesigs`はGhidra ProjectのI/O性能、Program数、解析品質の影響を受けます。
- `commitsigs`はDBのI/O、index更新、network latencyの影響を受けます。
- 投入単位を分け、失敗時に再実行しやすいsignature directory構成にしてください。

### Ghidra Projectを消してしまった

- BSim DBにはsignatureとメタデータは残りますが、逆アセンブル結果やデコンパイル結果は残りません。
- 検索件数だけは見えても、検索結果から元Programを開いた比較表示ができない場合があります。
- 元検体が残っている場合は、同じProject名、folder構成、Ghidra URLで再import・再解析できるか検討します。ただし、完全に同じ状態になるとは限りません。
- BSim DBとGhidra Projectは必ずセットでbackupしてください。

## 16. 最小コマンドまとめ

Apple Silicon Macで、Ghidra 12.0.4を使って最初に試すための一連の例です。Intel Macの場合は`/opt/homebrew`を`/usr/local`に読み替えてください。

```bash
export GHIDRA_HOME="$HOME/ghidra/ghidra_12.0.4_PUBLIC"

xcode-select --install
brew install openssl@3 readline zlib icu4c bison flex

export PATH="/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:$PATH"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/readline/include -I/opt/homebrew/opt/icu4c/include -I/opt/homebrew/opt/zlib/include -I/opt/homebrew/opt/flex/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/readline/lib -L/opt/homebrew/opt/icu4c/lib -L/opt/homebrew/opt/zlib/lib -L/opt/homebrew/opt/flex/lib -L/opt/homebrew/opt/bison/lib"
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/readline/lib/pkgconfig:/opt/homebrew/opt/icu4c/lib/pkgconfig:/opt/homebrew/opt/zlib/lib/pkgconfig:/opt/homebrew/opt/flex/lib/pkgconfig"

cd "$GHIDRA_HOME/Ghidra/Features/BSim"
find . -name "make-postgres.sh" -print
./support/make-postgres.sh

mkdir -p "$HOME/bsim_pg_data"
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --auth password --port 5432

# ローカル検証だけならlocalhostに絞る。再起動時にもパスワードを求められる場合があります。
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --port 5432
perl -0pi -e "s/^listen_addresses = '\\*'/listen_addresses = 'localhost'/m" "$HOME/bsim_pg_data/postgresql.conf"
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --port 5432

"$GHIDRA_HOME/support/bsim" createdatabase \
  postgresql://localhost/malware_curated \
  medium_nosize \
  --name "Malware Curated BSim DB" \
  --owner "BSim" \
  --description "Curated known malware function similarity database"

"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated FAMILY
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated SOURCE
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated TRUST_LEVEL
"$GHIDRA_HOME/support/bsim" addexecategory postgresql://localhost/malware_curated ORIGIN

mkdir -p "$HOME/ghidra_projects"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$HOME/ghidra_projects" malware_known \
  -import "$HOME/samples/known" \
  -recursive \
  -analysisTimeoutPerFile 120

mkdir -p "$HOME/bsim_sigs"
"$GHIDRA_HOME/support/bsim" generatesigs \
  "ghidra:${HOME}/ghidra_projects/malware_known" \
  "$HOME/bsim_sigs" \
  --bsim postgresql://localhost/malware_curated \
  --overwrite

"$GHIDRA_HOME/support/bsim" commitsigs \
  postgresql://localhost/malware_curated \
  "$HOME/bsim_sigs"

"$GHIDRA_HOME/support/bsim" getexecount \
  postgresql://localhost/malware_curated

"$GHIDRA_HOME/support/bsim" listexes \
  postgresql://localhost/malware_curated \
  --limit 20
```

停止する場合:

```bash
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --port 5432
```

## 公式ドキュメント

- [Introduction to BSim](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md)
- [BSim Databases from the Command Line](https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial_BSim_Command_Line.html)
- [Database Configuration](https://www.ghidradocs.com/11.0_PUBLIC/help/BSim/help/topics/BSim/DatabaseConfiguration.html)
- [Command-Line Utility Reference](https://www.ghidradocs.com/11.0_PUBLIC/help/BSim/help/topics/BSim/CommandLineReference.html)
- [Ingesting Executables](https://www.ghidradocs.com/11.0_PUBLIC/help/BSim/help/topics/BSim/IngestProcess.html)
- [Ghidra Analysis from the Command Line](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Ghidra_Command_Line.md)
