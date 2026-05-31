[English](usage.md) | [日本語](usage.ja.md)

# 利用ガイド

このドキュメントは、`ghidra-mcp` の導入と運用手順をまとめたものです。提供ツールの一覧は [README](../README.ja.md) を参照してください。

## 動作要件

- Python 3.10 以上
- [uv](https://github.com/astral-sh/uv)（Python パッケージと仮想環境の管理ツール）
- Ghidra 本体（PyGhidra が参照できるよう `GHIDRA_INSTALL_DIR` を設定してください）
- PyGhidra が要求する Java/Ghidra のバージョン（Ghidra 11.3 以降を推奨）

## セットアップ手順

1. **uv のインストール**
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   または各プラットフォーム向けパッケージを利用してください。

2. **リポジトリの取得**
   ```bash
   git clone <このリポジトリのURL>
   cd GhidraMCP_headless
   ```

3. **依存関係の同期**
   ```bash
   uv sync
   ```
   `uv` が自動的に仮想環境を作成し、`pyproject.toml` に定義された依存パッケージ（`requests`, `mcp`, `pyghidra` など）をインストールします。

4. **環境変数の設定**
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```
   or
   ```bash
   $env:GHIDRA_INSTALL_DIR="C:\path\to\ghidra"
   ```
   
   PyGhidra が Ghidra 本体を見つけられるようにしてください。

   Ghidra Serverを利用する場合は、ユーザ作成時に変更したパスワードを環境変数に設定する。
   ```bash
   export GHIDRA_SERVER_PASSWORD='your-password'
   ```

5. **MCP サーバーの起動**
   ```bash
   uv run ghidra-mcp --project-location /Users/samsepi0l/ghidra_project.gpr  --transport http --mcp-host 127.0.0.1 --mcp-port 8081 
   ```

## Docker でのセットアップ

Ghidra をホストへ個別インストールせずに試したい場合は、このリポジトリ同梱の `Dockerfile` と `docker-compose.yml` を使えます。

1. **解析対象の置き場を作成**
   ```bash
   mkdir -p samples
   ```
2. **Docker イメージをビルド（推奨）**
   ```bash
   ./build_docker_image.sh
   ```
3. **MCP サーバーを起動**
   ```bash
   docker compose up -d
   ```
4. **MCP クライアントを接続**
   `http://127.0.0.1:8081/mcp`

この compose 構成では、`--project-location /data/projects --project-name default` を使い、project 実体は `/data/projects/default.gpr` / `/data/projects/default.rep` に置く前提です。新規 volume では MCP から `create_project(project_location="/data/projects/default.gpr")` を先に実行して空 project を作成し、そのあと binary を import して load してください。起動直後は program 未ロードなので、通常の初回導線は `create_project`（新規 volume のみ）、`import_program`、`load_project_program` です。

- `docker compose build` も利用できます。同梱 compose は既定で `DOCKER_PLATFORM=linux/amd64` を使い、同梱 Linux decompiler と一致させます。
- `DOCKER_PLATFORM` は上書きできます。`linux/arm64` を使う場合、Docker build は upstream 公式 Ghidra 配布物に同梱の mecha_ghidra decompiler natives overlay を重ねます。
- ARM64 overlay が無い状態なら、`decompile_function` 実行時に遅れて壊れる代わりに Docker build 時点で fail-fast します。
- 独自の Ghidra 配布物を使う場合は、`GHIDRA_DIST_URL` と `GHIDRA_DIST_SHA256` を両方指定してください。独自の ARM64 overlay を使う場合は、`GHIDRA_DECOMPILER_NATIVES_URL` と `GHIDRA_DECOMPILER_NATIVES_SHA256` も両方指定してください。

### ARM64 Docker build

Linux ARM64 や Apple Silicon で Docker を native 実行したい場合は、`DOCKER_PLATFORM=linux/arm64` だけで upstream 公式 Ghidra 配布物に既定の decompiler natives overlay を重ねて使えます。

```bash
DOCKER_PLATFORM=linux/arm64 docker compose build
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

別の ARM64 decompiler natives overlay を使いたい場合:

```bash
DOCKER_PLATFORM=linux/arm64 \
GHIDRA_DECOMPILER_NATIVES_URL=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/<release-tag>/ghidra_decompiler_natives_all.zip \
GHIDRA_DECOMPILER_NATIVES_SHA256=<release-asset-sha256> \
docker compose build
```

配布物を自前で生成したい場合は次を実行します。

```bash
./scripts/build_linux_arm64_decompiler.sh
./scripts/build_decompiler_natives.sh --platform mac_arm_64
./scripts/build_decompiler_natives.sh --platform mac_x86_64
```

生成物:

- `dist/ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
- `dist/ghidra_*_linux_arm_64_decompiler.zip`
- `dist/ghidra_*_mac_arm_64_decompiler_overlay.tar.gz`
- `dist/ghidra_*_mac_arm_64_decompiler.zip`
- `dist/ghidra_*_mac_x86_64_decompiler_overlay.tar.gz`
- `dist/ghidra_*_mac_x86_64_decompiler.zip`

GitHub release では、そのまま使える Ghidra bundle の `ghidra_12.1_decompiler_natives_all.zip` と、追加された `linux_arm_64` / `mac_arm_64` / `mac_x86_64` の `decompile` / `sleigh` パスだけをまとめた小さい overlay `ghidra_decompiler_natives_all.zip` の両方を公開します。

### Docker での共有パス

- 解析対象: `./samples` を `/samples` に bind mount（read-only）
- Ghidra project: named volume `ghidra-projects` を `/data/projects` に mount（read-write）

推奨構成をこの形にしている理由は次のとおりです。

- `import_program` は入力ファイルを Ghidra project にコピーするため、入力側は read-only で問題ありません。
- Ghidra project の `.rep` 配下は細かい I/O が多く、Docker Desktop 環境では bind mount より named volume の方が安定しやすく、体感性能も落ちにくいです。

### Docker 起動後の import 例

`./samples/hello.bin` を置いた場合、MCP クライアントからは次のように扱います。

- `import_program(target="default", binary_path="/samples/hello.bin")`
- `load_project_program(target="default", domain_path="/hello.bin")`

`import_program` は project ルートへ import するので、返却される `domain_path` は通常 `/<filename>` です。以後はその `domain_path` を `load_project_program` や shared project 同期系ツールに渡します。

## Notes

- http接続時の推奨は `--transport http` です。FastMCP の Streamable HTTP モードで起動し、`http://127.0.0.1:8081/mcp` で接続できます。
- 互換性のため `--transport sse` も引き続き利用できます（`/sse`）。
- `--mcp-host 0.0.0.0`（または `::`）で起動する場合、ローカル限定時とは保護設定が異なります。外部公開時は必ずリバースプロキシ/TLS/アクセス制御を併用してください。
- ツール公開は `--tool-profile`, `--allow-category`, `--add-category`, `--allow-safety`, `--allow-operation-level`, `--enable-tool`, `--disable-tool` で制御します。
- `shared_sync` は通常の tool category です。shared project の `commit/pull/checkout/delete` operations を行う同期ツールを公開したい場合は、`--add-category shared_sync` を追加するか、`--tool-profile full` を使ってください。
- ツール制御引数を何も付けない場合は `--tool-profile default` と同じで、default のツール集合を使い、`shared_sync` は含みません。
- `--allow-category` は現在の category 集合を置き換え、`--add-category` は追加します。同じ種類の allow は OR、異なる種類は AND で評価されます。
- shared project の認証が必要な場合は `--ghidra-server-user` と、`--ghidra-server-password` または `--ghidra-server-password-env` のどちらか片方をセットで指定してください。片方だけ指定した場合や、両方のパスワード指定を同時に行った場合は起動エラーになります。
- `--ghidra-server-password` が空文字の場合、または `--ghidra-server-password-env` で指定した環境変数が未設定/空文字の場合も起動エラーになります。ログにはパスワード値を出力しません。プロセス引数へ秘密情報を出したくない場合は `--ghidra-server-password-env` を推奨します。
- Linux ARM64 では `Ghidra/Features/Decompiler/os/linux_arm_64` が不足していると、起動時または decompiler 初期化時に専用メッセージ付きで失敗します。
- `--domain-path` を省略した場合はプロジェクトのみをターゲット登録して起動します（空プロジェクトでも起動可能）。この場合は `import_program` 後に `load_project_program` で program を開いてください。
- project がまだ存在しない場合は、`create_project` で空のローカル `.gpr/.rep` を作成してから `register_target` / `import_program` / `load_project_program` を実行できます。既存 project は `overwrite=true` を明示しない限り上書きしません。
- 既存ターゲットへ program をロード/切り替える操作は `load_project_program` を使い、新規ターゲット作成は `create_session` を使います。program 未指定で先にターゲットだけ作る場合は `register_target` を使ってください。
- `load_project_program`（および同等内部経路の `create_session`）では `target + domain_path` ごとに初回ロード時のみ解析を試行します。同一ターゲットライフサイクルで同じ program を再ロードした場合は再解析しません。明示的な解析パスが必要な場合は `analyze_program` または `reanalyze_program` を使ってください。
- `rename_function` などの更新系 tool を使った後、変更を `.gpr/.rep` に残すには `save_project_program(target="default")` を呼んでください。Ghidra GUI 側で同じ program を開いている場合、保存後の状態を見るには GUI 側で再オープンまたはリロードが必要になることがあります。
- private プロジェクトを shared 管理へ載せる場合は `add_project_program_to_version_control` を利用できます（同オプション有効時のみ）。
- shared project 同期ツールは `domain_path` を省略すると現在ロード中のprogramを対象にし、`domain_path` を指定するとそのprogramを直接対象にできます。
- `delete_shared_project_file` は明示的な `domain_path` と、正規化後パスに一致する `confirm` が必須です。ロード中ファイル、active checkout があるファイル、`allow_private=true` でない private file は削除しません。
- shared project で `rename_*` / `set_*` など更新系ツールを使う場合は、先に `checkout_project_program` が必要です（未checkout時は `CHECKOUT_REQUIRED` エラー）。
- shared project 同期ツールの `add_project_program_to_version_control` / `commit_project_program` / `pull_project_program` / `undo_checkout_project_program` は、現在ロード中programを対象にした場合のみ `DomainFile` の in-use 制約回避のため内部で一度閉じて再オープンします。
- Ghidra の制約として、headless mode では競合マージはサポートされません（`checkin/merge` ともに `requires merge ... not supported in headless mode` エラーになります）。
- `pull_project_program(on_local_changes="discard")` はローカル変更に対して `undoCheckout(keep=False)` を使用し、さらに checked-out 状態で `can_merge=true` の場合は `DomainFile.merge()` を呼ばず、古い checkout を破棄して最新サーバー状態へ追従します。
- `can_merge=true` でも破棄できる checkout が無い場合、`pull_project_program` は Ghidra の PropertyList merge 経路を踏まずに `UNSAFE_MERGE_REQUIRED` で停止します。
- `commit_project_program` は競合（`can_merge=true`）を検知した場合、デフォルトでは `UNSAFE_MERGE_REQUIRED` で停止します。ローカル checkout を破棄して最新サーバー状態へ追従したい場合のみ `on_conflict="discard"` を明示してください（`status=noop` / `reason=conflict_discarded`）。
- Docker 構成では `./samples:/samples:ro` と `ghidra-projects:/data/projects` を既定で使います。入力ファイルは `/samples/<filename>` として指定してください。
- Docker で初回起動する server は project のみを登録した状態で立ち上がるため、新規 volume では `create_project` で project を作成し、その後 `import_program` で取り込み、続けて `load_project_program` で program を開いてください。

### ツール公開制御の例

readonly:

```bash
uv run ghidra-mcp --project-location /path/to/project.gpr --domain-path /main --tool-profile readonly
```

default + shared_sync:

```bash
uv run ghidra-mcp --project-location /path/to/project.gpr --domain-path /main --add-category shared_sync
```

full を readonly に絞る:

```bash
uv run ghidra-mcp --project-location /path/to/project.gpr --domain-path /main --tool-profile full --allow-safety read_only
```

### shared project 認証つき起動例

```bash
export GHIDRA_SERVER_PASSWORD='your-password'
uv run ghidra-mcp \
    --project-location /Users/samsepi0l/ghidra_project.gpr \
    --transport http \
    --mcp-host 127.0.0.1 \
    --mcp-port 8081 \
    --add-category shared_sync \
    --ghidra-server-user your-user \
    --ghidra-server-password-env GHIDRA_SERVER_PASSWORD
```

パスワード文字列を直接渡すこともできます。

```bash
uv run ghidra-mcp \
    --project-location /Users/samsepi0l/ghidra_project.gpr \
    --transport http \
    --mcp-host 127.0.0.1 \
    --mcp-port 8081 \
    --add-category shared_sync \
    --ghidra-server-user your-user \
    --ghidra-server-password 'your-password'
```

## Ghidra Serverの設定

### インストール・ユーザ設定

サーバーのインストール
```bash
sudo GHIDRA_INSTALL_DIR/server/svrInstall
```

自分自身のユーザとmecha ghidra用のユーザを登録
```bash
sudo GHIDRA_INSTALL_DIR/server/svrAdmin -add your_username
sudo GHIDRA_INSTALL_DIR/server/svrAdmin -add mecha-ghidra
```

GHIDRA_INSTALL_DIR/server/server.confを編集して、ユーザ名を指定して接続できるようにする。
`${ghidra.repositories.dir}` は必ず最後に指定する
```text
wrapper.app.parameter.1=-a0
wrapper.app.parameter.2=-u
wrapper.app.parameter.3=${ghidra.repositories.dir}
```

ghidraを起動する
```bash
sudo server/ghidraSvr restart
```

New ProjectからShared Projectを作成

<img width="508" height="388" alt="Image" src="https://github.com/user-attachments/assets/1091c615-1590-4a49-aa2c-7628d6efed70" />

localhostに接続

<img width="508" height="388" alt="image" src="https://github.com/user-attachments/assets/0d1a0cef-fbee-4513-af18-3193a3529c2f" />

作成したユーザでログインする。初回パスワードは `changeme`

<img width="350" height="179" alt="image" src="https://github.com/user-attachments/assets/e03718b4-89df-4a2b-8609-521a42dd1878" />

初回ログイン時にパスワードを変更するように言われるので、作成した2つのユーザのパスワードを変更する

<img width="353" height="181" alt="image" src="https://github.com/user-attachments/assets/24da9ede-db7b-4ba2-8107-2fb7fe895968" />

プロジェクトを作成する。LLMのアカウントはRead/Writeに設定。

<img width="652" height="383" alt="image" src="https://github.com/user-attachments/assets/3da1693c-3dd7-4ba8-a6e6-95b4767cf95c" />

<img width="531" height="389" alt="image" src="https://github.com/user-attachments/assets/76ef63d5-de7a-48ca-8758-76b5157a98c3" />

<img width="531" height="389" alt="image" src="https://github.com/user-attachments/assets/80a8aa7e-659b-4d8e-bf5f-65eea292dc7f" />

## Codex での MCP 設定

Codexアプリ/CLI では `~/.codex/config.toml` の `mcp_servers` セクションに設定します。推奨の `streamable-http` 接続例:

```toml
[mcp_servers.ghidra_headless]
enabled = true
url = "http://127.0.0.1:8081/mcp"
```

`stdio` で直接起動したい場合の例:

```toml
[mcp_servers.ghidra_headless]
enabled = true
command = "/Users/samsepi0l/.local/bin/uv"
args = [
  "--directory",
  "/Users/samsepi0l/ghidra/GhidraMCP_headless",
  "run",
  "ghidra-mcp",
  "--project-location",
  "/Users/samsepi0l/ghidra_project.gpr",
  "--transport",
  "stdio"
]
```

## Claude Code での MCP 設定

Claude Code では CLI から MCP サーバーを登録できます。推奨の `streamable-http` 接続例:

```bash
claude mcp add --transport http ghidra_headless http://127.0.0.1:8081/mcp
```

サーバー側で shared project 認証が必要な場合は、`ghidra-mcp` 起動時に `--ghidra-server-user` と `--ghidra-server-password` または `--ghidra-server-password-env` を指定してください。

## Kilocode/Roocode での MCP 設定

Kilocode／Roocode の MCP 設定は JSON 形式で記述できます。`stdio` でサーバーを起動する場合の例:

```json
{
  "mcpServers": {
    "ghidra_headless": {
      "command": "/Users/samsepi0l/.local/bin/uv",
      "args": [
        "--directory",
        "/Users/samsepi0l/GhidraMCP_headless",
        "run",
        "ghidra-mcp",
        "--project-location",
        "/Users/samsepi0l/ghidra_project.gpr",
        "--transport",
        "stdio"
      ],
      "timeout": 300,
      "disabled": true
    }
  }
}
```

Streamable HTTP モードであれば、以下のようにエンドポイントを指定します。

```json
"ghidra_headless": {
  "disabled": false,
  "timeout": 60,
  "type": "streamable-http",
  "url": "http://127.0.0.1:8081/mcp",
}
```

streamable-http を使う必要があるクライアントでは `--transport http` で起動し、`http://127.0.0.1:8081/mcp` を指定してください。
