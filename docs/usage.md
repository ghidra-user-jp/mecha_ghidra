# 利用ガイド

このドキュメントは、`ghidra-mcp` の導入と運用手順をまとめたものです。提供ツールの一覧は [README](../README.md) を参照してください。

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
   PyGhidra が Ghidra 本体を見つけられるようにしてください。

   Ghidra Serverを利用する場合は、ユーザ作成時に変更したパスワードを環境変数に設定する。
   ```bash
   export GHIDRA_SERVER_PASSWORD='your-password'
   ```

5. **MCP サーバーの起動**
   ```bash
   uv run ghidra-mcp --project-location /Users/samsepi0l/ghidra_project.gpr --domain-path /main --transport http --mcp-host 127.0.0.1 --mcp-port 8081 --mcp-path /mcp
   ```

## Notes

- http接続時の推奨は `--transport http` です。FastMCP の Streamable HTTP モードで起動し、`http://127.0.0.1:8081/mcp` で接続できます。
- 互換性のため `--transport sse` も引き続き利用できます（`/sse`）。
- `commit/pull/checkout` など shared project 同期ツールを公開したい場合のみ `--enable-shared-project-sync` を付けて起動してください。
- shared project の認証が必要な場合は `--ghidra-server-user` と `--ghidra-server-password-env` をセットで指定してください（パスワードの直接引数は未対応）。
- `--domain-path` を省略した場合はプロジェクトのみをターゲット登録して起動します（空プロジェクトでも起動可能）。この場合は `import_program` 後に `load_project_program` で program を開いてください。
- private プロジェクトを shared 管理へ載せる場合は `add_project_program_to_version_control` を利用できます（同オプション有効時のみ）。
- shared project 同期ツールは `domain_path` を省略すると現在ロード中のprogramを対象にし、`domain_path` を指定するとそのprogramを直接対象にできます。
- shared project で `rename_*` / `set_*` など更新系ツールを使う場合は、先に `checkout_project_program` が必要です（未checkout時は `CHECKOUT_REQUIRED` エラー）。
- shared project 同期ツールの `commit/pull/undo_checkout` は、現在ロード中programを対象にした場合のみ `DomainFile` の in-use 制約回避のため内部で一度閉じて再オープンします。
- Ghidra の制約として、headless mode では競合マージはサポートされません（`checkin/merge` ともに `requires merge ... not supported in headless mode` エラーになります）。
- `pull_project_program(on_local_changes="discard")` は `undoCheckout(keep=False)` のみを使用し、force 破棄は行いません。
- `commit_project_program` は競合（`can_merge=true`）を検知した場合、デフォルトでローカル変更を破棄して最新状態へ追従し、`status=noop` / `reason=conflict_discarded` を返します（人間側の更新を優先）。

### shared project 認証つき起動例

```bash
export GHIDRA_SERVER_PASSWORD='your-password'
uv run ghidra-mcp \
    --project-location /Users/samsepi0l/ghidra_project.gpr \
    --domain-path /main \
    --transport http \
    --mcp-host 127.0.0.1 \
    --mcp-port 8081 \
    --mcp-path /mcp \
    --ghidra-server-user your-user \
    --ghidra-server-password-env GHIDRA_SERVER_PASSWORD
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
