[English](clients.md) | [日本語](clients.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# MCPクライアント

クライアントごとに接続方式を1つ選びます。**HTTP**は別途起動したサーバーへ接続し、**stdio**はクライアントがサーバープロセスを起動・終了します。HTTPの場合は、先に[ローカル導入](usage.ja.md#local-setup)または[Docker導入](docker.ja.md)を済ませてください。

## Codex

起動済みのHTTPサーバーへ接続する場合は、`~/.codex/config.toml` に追加します。

```toml
[mcp_servers.ghidra_headless]
url = "http://127.0.0.1:8081/mcp"
```

CLIから同じ接続先を登録することもできます。

```bash
codex mcp add ghidra_headless --url http://127.0.0.1:8081/mcp
```

stdioの場合は、上の設定の**代わりに**以下を使います。すべての絶対パスを置き換え、既存の `analysis.gpr` を指定してください。

```toml
[mcp_servers.ghidra_headless]
command = "uv"
args = [
  "--directory", "/absolute/path/to/mecha_ghidra",
  "run", "ghidra-mcp",
  "--project-location", "/absolute/path/to/analysis.gpr",
  "--transport", "stdio"
]
env = { GHIDRA_INSTALL_DIR = "/absolute/path/to/ghidra" }
```

起動・ツール実行のタイムアウトなど、クライアント側の設定は[CodexのMCPドキュメント](https://developers.openai.com/codex/mcp)を参照してください。

## Claude Code

起動済みのHTTPサーバーへ接続します。

```bash
claude mcp add --transport http ghidra_headless http://127.0.0.1:8081/mcp
```

接続状態はClaude Code内の `/mcp` で確認します。設定のスコープやstdio接続は[Claude CodeのMCPガイド](https://code.claude.com/docs/en/mcp)を参照してください。

## Kilo CodeとJSON形式のクライアント

Kilo CodeのVS Code拡張では、MCP設定に有効なサーバーエントリを追加します。

```json
{
  "mcpServers": {
    "ghidra_headless": {
      "url": "http://127.0.0.1:8081/mcp",
      "disabled": false
    }
  }
}
```

詳細は[Kilo CodeのMCP設定](https://kilo.ai/docs/automate/mcp/using-in-kilo-code)を参照してください。ほかのクライアントでは `type` などの接続方式フィールドが必要な場合があります。各クライアントのスキーマに従ってください。

Roo Codeなど、`mcpServers` 形式のstdio設定を使うクライアントでは、次のように起動します。

```json
{
  "mcpServers": {
    "ghidra_headless": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mecha_ghidra",
        "run", "ghidra-mcp",
        "--project-location", "/absolute/path/to/analysis.gpr",
        "--transport", "stdio"
      ],
      "env": { "GHIDRA_INSTALL_DIR": "/absolute/path/to/ghidra" }
    }
  }
}
```

## 接続を確認する

1. クライアントにMecha Ghidraのツール一覧が表示されることを確認します。
2. `list_targets` を呼びます。ターゲットの登録だけでは、プログラムは読み込まれていない場合があります。
3. [最初の解析](usage.ja.md#first-analysis)に進みます。既存プロジェクトなら `list_project_programs` と `load_project_program` を使います。

GUIクライアントから `uv` が見つからない場合は、実行ファイルを絶対パスで指定してください。GUIアプリはシェルの環境変数を引き継がない場合があるため、stdioでは上記のように `GHIDRA_INSTALL_DIR` を明示します。インポートや解析に十分なクライアント側タイムアウトを設定してください。`--lock-timeout-seconds` は待ち行列での待機時間だけを制御し、クライアント側のタイムアウトは延長しません。

旧SSE方式が必要なクライアントには、サーバーを `--transport sse` で起動して `/sse` を指定します。共有リポジトリの認証情報はHTTPクライアント設定ではなく、サーバーの[Ghidra Server設定](shared-projects.ja.md)で指定します。
