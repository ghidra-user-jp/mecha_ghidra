[ドキュメント一覧](usage.ja.md) · [BSimの使い方](bsim.ja.md) · [セットアップ](bsim-postgresql-macos.md) → [一括登録](bsim-ingestion.md) → [運用保守](bsim-operations.md)

# BSim PostgreSQLの運用保守

[セットアップ](bsim-postgresql-macos.md)と[一括登録](bsim-ingestion.md)に続く管理者向けガイドです。コマンドと固有のエラーはGhidra 12.0.4での検証記録に基づきます。別バージョンでは同梱のusageを確認してください。MCPツールのエラーは[トラブルシューティング](troubleshooting.ja.md)にもまとめています。

- [起動・停止](#service)
- [大量投入とインデックス](#indexes)
- [バックアップ](#backup)
- [トラブルシューティング](#troubleshooting)

<a id="service"></a>

## 起動・停止

`GHIDRA_HOME` を管理に使うGhidraの展開先に設定します。`bsim_ctl` はPostgreSQLバックエンド専用で、H2の管理には使いません。

```bash
"$GHIDRA_HOME/support/bsim_ctl" status "$HOME/bsim_pg_data" --port 5432
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --port 5432
"$GHIDRA_HOME/support/bsim_ctl" stop "$HOME/bsim_pg_data" --port 5432
```

上記はそれぞれ別の操作です。`start` はパスワードを入力できるTTYで実行してください。通常停止できず強制停止が必要な場合は、`stop` に `--force` を追加します。

<a id="indexes"></a>

## 大量投入とインデックス

大きな投入では、インデックスを外してから登録し、終了後に再構築すると速くなる場合があります。検索性能が低下するため、利用者への影響を避けられるメンテナンス時間帯で行ってください。

1. 投入前に `dropindex` を実行します。
2. [一括登録](bsim-ingestion.md)の `commitsigs` を完了させます。
3. 成否と投入件数を確認し、`rebuildindex` を実行します。途中で投入に失敗した場合も、インデックスを外した状態を放置しないでください。
4. 必要に応じて `prewarm` を実行します。効果はDBサイズ、メモリ、OSキャッシュに依存します。

```bash
"$GHIDRA_HOME/support/bsim" dropindex postgresql://localhost/malware_curated
# この間にシグネチャを投入する
"$GHIDRA_HOME/support/bsim" rebuildindex postgresql://localhost/malware_curated
"$GHIDRA_HOME/support/bsim" prewarm postgresql://localhost/malware_curated
```

検証時はdrop、rebuild、prewarmの成功を確認しました。少量の検証DBでの結果であり、大規模DBでの速度向上を測定したものではありません。

<a id="backup"></a>

## バックアップ

**BSimデータベースとGhidraプロジェクト／共有リポジトリを組にして保全します。** BSimだけを復元しても、記録されたGhidra URLの先にプログラムがなければ比較や後続解析はできません。

両者のスナップショット時刻と対応関係を記録し、入力ファイルのハッシュ、入手元、ファミリ、解析者、信頼度なども別途管理すると再構築しやすくなります。PostgreSQLとGhidra Serverそれぞれのバックアップ手順に従い、復元後に件数だけでなく、検索結果から元プログラムを開けることも確認してください。

<a id="troubleshooting"></a>

## トラブルシューティング

<a id="build-errors"></a>

### `make-postgres.sh` が見つからない

- `GHIDRA_HOME`がGhidra配布物のrootを指しているか確認します。
- `find "$GHIDRA_HOME" -name "make-postgres.sh" -print`で探します。
- Ghidraのバージョン差で配置が変わることがあります。

```bash
find "$GHIDRA_HOME" -name "make-postgres.sh" -print
```

### ビルド依存が見つからない

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

### 初回の `make distclean` で警告が出る

初回展開直後に次の警告が出ることがあります。

```text
You need to run the 'configure' program first.
make: *** [distclean] Error 1
```

実測では、この警告のあとconfigureとbuildが続き、最終的に成功しました。そこで停止していなければ、続く出力を確認してください。

### `bsim_ctl start` がパスワード入力で落ちる

実測では、`bsim_ctl start`を非対話で走らせるとパスワード入力に失敗し、`NullPointerException`になりました。初回起動だけでなく、既存data directoryの再起動でも発生しました。

- `bsim_ctl start`はTTY上で実行してください。
- `Set admin(<user>) password:`と`Please re-enter password:`に入力します。
- 途中失敗した空のdata directoryは、内容を確認してから作り直してください。

### 起動時にポートが衝突する

- 既に5432でPostgreSQLなどが起動している可能性があります。
- 別portで初期化する場合は、初回`start`時に`--port <port>`を指定します。
- DB URLにもportを含めます。

```bash
"$GHIDRA_HOME/support/bsim_ctl" start "$HOME/bsim_pg_data" --auth password --port 15432
"$GHIDRA_HOME/support/bsim" createdatabase postgresql://localhost:15432/malware_curated medium_nosize
```

### 意図しないアドレスで待ち受けている

12.0.4の検証では `listen_addresses = '*'` が生成されました。ローカル専用なら[セットアップの待ち受け設定](bsim-postgresql-macos.md#start)に従って `localhost` へ変更し、再起動後に `lsof` で確認します。

### パスワード認証でログインできない

- Ghidra 12.0.4では、初回起動時に管理者パスワードを自分で設定します。
- 初回起動したOSユーザーが管理者ユーザーになります。
- パスワード変更は手元の`bsim_ctl` usageを確認してください。Ghidra 12.0.4のusageでは`resetpassword <username>`形式でした。

```bash
"$GHIDRA_HOME/support/bsim_ctl" resetpassword "$USER" --port 5432
```

### `createdatabase` で接続エラーになる

- `bsim_ctl status "$HOME/bsim_pg_data" --port 5432`でserver状態を確認します。
- portが5432以外なら、BSim DB URLにもportを含めます。
- `--auth password`の場合、実行時に要求されるパスワードを入力します。
- SSLや証明書まわりのエラーは、`pg_hba.conf`、`postgresql.conf`、BSim client側の接続設定を確認してください。
- MCP toolのエラーは、認証失敗なら`BSIM_AUTHENTICATION_FAILED`、接続不能なら`BSIM_DATABASE_UNREACHABLE`、URL未指定なら`BSIM_URL_REQUIRED`、不正なURLなら`BSIM_URL_INVALID`、不正なthreshold/limitなら`BSIM_PARAMETER_INVALID`、不正な`matched_ref`なら`BSIM_INVALID_MATCHED_REF`のように分類されます。

### `large_nosize` が使えない

Ghidra 12.0.4の実測usageでは`large_nosize`は列挙されませんでした。

```text
large_32 | medium_32 | medium_64 | medium_cpool | medium_nosize
```

32bit/64bit間のmatchを重視する場合は`medium_nosize`を使います。将来のGhidraで`large_nosize`がusageに出る場合は、大規模DB向けに検討してください。

### `generatesigs` のGhidra URLが不正

- ローカルProjectは`ghidra:/Users/yourname/ghidra_projects/project_name`のように指定します。
- Bashの`$HOME`を使う場合は`ghidra:${HOME}/ghidra_projects/project_name`が安全です。
- Ghidra Server repositoryの場合は`ghidra://host/repository/folder`です。
- ローカルProjectをGhidra GUIで開いたままだとlockにより失敗する場合があります。

### 投入後も実行ファイル数が0のまま

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

### 元のGhidraプロジェクトを失った

- BSim DBにはsignatureとメタデータは残りますが、逆アセンブル結果やデコンパイル結果は残りません。
- 検索件数だけは見えても、検索結果から元Programを開いた比較表示ができない場合があります。
- 元検体が残っている場合は、同じProject名、folder構成、Ghidra URLで再import・再解析できるか検討します。ただし、完全に同じ状態になるとは限りません。
- BSim DBとGhidra Projectは必ずセットでbackupしてください。
