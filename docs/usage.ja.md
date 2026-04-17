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

この compose 構成では、`--project-location /data/projects --project-name default` を使い、project 実体は `/data/projects/default.gpr` / `/data/projects/default.rep` に置く前提です。初回利用前にその Ghidra project を一度作成し、そのあと binary を import して load してください。起動直後は program 未ロードなので、最初の導線は `import_program` と `load_project_program` です。

- `docker compose build` も利用できます。同梱 compose は既定で `DOCKER_PLATFORM=linux/amd64` を使い、同梱 Linux decompiler と一致させます。
- `DOCKER_PLATFORM` は上書きできます。`linux/arm64` を使う場合、Docker build は既定で mecha_ghidra release `v0.1.0-rc.1` の patched Ghidra 配布物を自動選択します。
- ARM64 で upstream 公式 ZIP を明示指定すると、`decompile_function` 実行時に遅れて壊れる代わりに Docker build 時点で fail-fast します。
- 独自成果物を使う場合は、`GHIDRA_DIST_URL` と `GHIDRA_DIST_SHA256` を両方指定してください。

### ARM64 Docker build

Linux ARM64 や Apple Silicon で Docker を native 実行したい場合は、`DOCKER_PLATFORM=linux/arm64` だけで既定の patched ARM64 配布物を使えます。

```bash
DOCKER_PLATFORM=linux/arm64 docker compose build
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

別の patched ZIP を使いたい場合:

```bash
DOCKER_PLATFORM=linux/arm64 \
GHIDRA_DIST_URL=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/v0.1.0-rc.1/ghidra_12.0.4_PUBLIC_20260303_linux_arm_64_decompiler.zip \
GHIDRA_DIST_SHA256=b8b4961048874091a7aabd08579eee485aec52f1885ae67bff665431f1606af2 \
docker compose build
```

配布物を自前で生成したい場合は次を実行します。

```bash
./scripts/build_linux_arm64_decompiler.sh
```

生成物:

- `dist/ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
- `dist/ghidra_*_linux_arm_64_decompiler.zip`

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
- `commit/pull/checkout` など shared project 同期ツールを公開したい場合のみ `--enable-shared-project-sync` を付けて起動してください。
- shared project の認証が必要な場合は `--ghidra-server-user` と、`--ghidra-server-password` または `--ghidra-server-password-env` のどちらか片方をセットで指定してください。片方だけ指定した場合や、両方のパスワード指定を同時に行った場合は起動エラーになります。
- `--ghidra-server-password` が空文字の場合、または `--ghidra-server-password-env` で指定した環境変数が未設定/空文字の場合も起動エラーになります。ログにはパスワード値を出力しません。プロセス引数へ秘密情報を出したくない場合は `--ghidra-server-password-env` を推奨します。
- Linux ARM64 では `Ghidra/Features/Decompiler/os/linux_arm_64` が不足していると、起動時または decompiler 初期化時に専用メッセージ付きで失敗します。
- `--domain-path` を省略した場合はプロジェクトのみをターゲット登録して起動します（空プロジェクトでも起動可能）。この場合は `import_program` 後に `load_project_program` で program を開いてください。
- 既存ターゲットへ program をロード/切り替える操作は `load_project_program` を使い、新規ターゲット作成は `create_session` を使います。program 未指定で先にターゲットだけ作る場合は `register_target` を使ってください。
- `load_project_program`（および同等内部経路の `create_session`）では `target + domain_path` ごとに初回ロード時のみ解析を試行します。同一ターゲットライフサイクルで同じ program を再ロードした場合は再解析しません。
- private プロジェクトを shared 管理へ載せる場合は `add_project_program_to_version_control` を利用できます（同オプション有効時のみ）。
- shared project 同期ツールは `domain_path` を省略すると現在ロード中のprogramを対象にし、`domain_path` を指定するとそのprogramを直接対象にできます。
- shared project で `rename_*` / `set_*` など更新系ツールを使う場合は、先に `checkout_project_program` が必要です（未checkout時は `CHECKOUT_REQUIRED` エラー）。
- shared project 同期ツールの `commit_project_program` / `pull_project_program` / `undo_checkout_project_program` は、現在ロード中programを対象にした場合のみ `DomainFile` の in-use 制約回避のため内部で一度閉じて再オープンします。
- Ghidra の制約として、headless mode では競合マージはサポートされません（`checkin/merge` ともに `requires merge ... not supported in headless mode` エラーになります）。
- `pull_project_program(on_local_changes="discard")` はローカル変更に対して `undoCheckout(keep=False)` を使用し、さらに checked-out 状態で `can_merge=true` の場合は `DomainFile.merge()` を呼ばず、古い checkout を破棄して最新サーバー状態へ追従します。
- `can_merge=true` でも破棄できる checkout が無い場合、`pull_project_program` は Ghidra の PropertyList merge 経路を踏まずに `UNSAFE_MERGE_REQUIRED` で停止します。
- `commit_project_program` は競合（`can_merge=true`）を検知した場合、デフォルトでローカル変更を破棄して最新状態へ追従し、`status=noop` / `reason=conflict_discarded` を返します（人間側の更新を優先）。
- Docker 構成では `./samples:/samples:ro` と `ghidra-projects:/data/projects` を既定で使います。入力ファイルは `/samples/<filename>` として指定してください。
- Docker で初回起動する server は project のみを登録した状態で立ち上がるため、まず `import_program` で取り込み、続けて `load_project_program` で program を開いてください。

### shared project 認証つき起動例

```bash
export GHIDRA_SERVER_PASSWORD='your-password'
uv run ghidra-mcp \
    --project-location /Users/samsepi0l/ghidra_project.gpr \
    --transport http \
    --mcp-host 127.0.0.1 \
    --mcp-port 8081 \
    --enable-shared-project-sync \
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
    --enable-shared-project-sync \
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
