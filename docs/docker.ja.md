[English](docker.md) | [日本語](docker.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# Docker

GhidraとJavaを同梱したイメージでMecha Ghidraを起動します。Compose対応のDockerを用意し、このリポジトリをcloneして、ルートディレクトリで以下を実行してください。

## ビルドと起動

旧サービス名 `ghidra-mcp` を使う既存環境では、設定を更新する前に[移行手順](troubleshooting.ja.md#古い設定からの移行)を確認してください。

```bash
mkdir -p samples exports
./build_docker_image.sh
docker compose up -d
docker compose ps
docker compose logs --tail=100 mecha_ghidra
```

[MCPクライアント](clients.ja.md)の接続先は `http://127.0.0.1:8081/mcp` です。起動時は `default` ターゲットのプロジェクト情報だけを登録します。新しいボリュームでは、解析ツールを使う前に次の手順を実行してください。

`docker compose build` でもビルドできます。既定のプラットフォームは `linux/amd64` です。イメージはUID/GID `10001:10001` で動き、ポートはホストのループバックに公開します。ヘルスチェックはTCP接続を確認するもので、プログラムの読み込みやデコンパイルの成功までは確認しません。

## 最初のインポート

ホストの `./samples/sample.bin` に解析対象を置きます。以下はMCPツール名とJSON引数です。

1. `create_project` — 新しいボリュームで最初の1回だけ実行します。

   ```json
   {"project_location":"/data/projects","project_name":"default"}
   ```

2. `import_program`：

   ```json
   {"target":"default","binary_path":"/samples/sample.bin"}
   ```

3. `load_project_program` — インポート応答の `program` を `domain_path` に渡します。

   ```json
   {"target":"default","domain_path":"/sample.bin"}
   ```

これで `list_functions` や `decompile_function` を使えます。次回以降は作成や再インポートを省き、既存プログラムを読み込んでください。

## 保存先とパス

| ホスト側 | コンテナ内 | 用途 |
| --- | --- | --- |
| `./samples` | `/samples` | 読み取り専用の入力ファイル |
| Composeボリューム `ghidra-projects` | `/data/projects` | 永続化するGhidraプロジェクト |
| `./exports` | `/data/exports` | `.gzf` や生バイト列の書き出し先 |

既定プロジェクトは `/data/projects/default.gpr` と隣接する `default.rep` です。実際のボリューム名にはComposeのプロジェクト名が付く場合があります。インポート時に入力ファイルをプロジェクトへコピーするため、元ファイルには読み取り権限だけで足ります。

コンテナは、この3つのパスに[allowed-root設定](configuration.ja.md#file-access)を適用します。`import_program` にはホスト側のパスではなく `/samples/sample.bin` を渡してください。書き出し先は `/data/exports` 以下です。Linuxではエクスポート用のbind mountにUID 10001が書き込めるようにします。Docker Desktopでは権限の扱いが異なる場合があります。

プロジェクトボリュームを残して停止するには、以下を使います。

```bash
docker compose down
```

`-v` を付けると名前付きボリュームとプロジェクトデータも削除します。保存先を入れ替える前に `.gpr` と `.rep` の両方をバックアップしてください。

## ARM64とGhidra配布物の変更

Linux ARM64やApple Siliconでは、ビルドと起動に同じプラットフォームを指定します。

```bash
DOCKER_PLATFORM=linux/arm64 ./build_docker_image.sh
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

既定のARM64ビルドは、固定した公式Ghidra ZIPへ、このリポジトリのネイティブデコンパイラを追加します。必要な実行ファイルがなければビルド時に失敗します。

| 変更対象 | 必ず組み合わせて指定する変数 |
| --- | --- |
| Ghidra配布物 | `GHIDRA_DIST_URL` と `GHIDRA_DIST_SHA256` |
| ネイティブデコンパイラ | `GHIDRA_DECOMPILER_NATIVES_URL` と `GHIDRA_DECOMPILER_NATIVES_SHA256` |

ビルドコマンドへ環境変数として渡します。ARM64でGhidra配布物を変更する場合は、そのバージョンに合う追加ファイル、または必要なネイティブファイルを含む配布物を指定してください。異なるGhidraバージョンの追加ファイルは使わないでください。[配布物の選択](usage.ja.md#native-decompiler-artifacts)と[ネイティブビルド](development.ja.md#native-builds)も参照できます。

## 共有リポジトリとBSim

既定のイメージ起動コマンドでは、これらのカテゴリを公開しません。使う場合は、Composeサービスの `command` に[共有プロジェクト](shared-projects.ja.md)や[BSim](bsim.ja.md)の引数を追加します。[Dockerfile](../Dockerfile)にあるプロジェクト、接続方式、allowed-rootの引数を維持してください。バックエンドのパスワードはサービスの環境変数で渡します。ホスト側で動くバックエンドはコンテナの `localhost` にはないため、コンテナから到達できるホスト名を指定してください。
