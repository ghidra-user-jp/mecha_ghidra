[English](clients.md) | [日本語](clients.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# MCPクライアント

クライアントごとに接続方式を1つ選びます。**HTTP**は別途起動したサーバーへ接続し、**stdio**はクライアントがサーバープロセスを起動・終了します。HTTPの場合は、先に[ローカル導入](usage.ja.md#local-setup)または[Docker導入](docker.ja.md)を済ませてください。

HTTPはMCPのセッションIDを発行せず、ステートレスなJSON応答を返します。ステートフルに戻す互換設定はありません。解析状態とタイムアウトの扱いは[接続方式の設定](configuration.ja.md#transports)を参照してください。

## ツールの発見

Mecha Ghidraは標準の `tools/list` でツール定義を公開します。ツール検索に対応するクライアントは、必要な定義だけを後から読み込めます。サーバーの `instructions` は、プロファイルと個別フィルターで有効になったツールに基づいて、バイナリ解析の用途と検索する機能を説明します。readonly構成では編集機能を案内せず、BSim・共有リポジトリ・スクリプトも対応ツールの公開時だけ案内します。詳しい使い方はツール説明と `ghidra://docs/tools/{tool_name}` に置きます。

説明は同じ公開設定なら同じ順序・内容になり、検証対象の構成でUTF-8の1,900バイト以内に収めています。[サーバー作者向けガイド](https://code.claude.com/docs/en/mcp#for-mcp-server-authors)に沿って、扱う作業・検索すべき場面・主要機能を簡潔に示します。検索と遅延読み込みの実行はクライアント側の機能であり、`--tool-description-mode full` が全定義のモデル入力を強制するわけではありません。

## Codex

起動済みのHTTPサーバーへ接続する場合は、`~/.codex/config.toml` に追加します。

```toml
[mcp_servers.mecha_ghidra]
url = "http://127.0.0.1:8081/mcp"
```

CLIから同じ接続先を登録することもできます。

```bash
codex mcp add mecha_ghidra --url http://127.0.0.1:8081/mcp
```

stdioの場合は、上の設定の**代わりに**以下を使います。すべての絶対パスを置き換え、既存の `analysis.gpr` を指定してください。

```toml
[mcp_servers.mecha_ghidra]
command = "uv"
args = [
  "--directory", "/absolute/path/to/mecha_ghidra",
  "run", "mecha_ghidra",
  "--project-location", "/absolute/path/to/analysis.gpr",
  "--transport", "stdio"
]
env = { GHIDRA_INSTALL_DIR = "/absolute/path/to/ghidra" }
```

起動・ツール実行のタイムアウトなど、クライアント側の設定は[CodexのMCPドキュメント](https://developers.openai.com/codex/mcp)を参照してください。

## Claude Code

起動済みのHTTPサーバーへ接続します。

```bash
claude mcp add --transport http mecha_ghidra http://127.0.0.1:8081/mcp
```

接続状態はClaude Code内の `/mcp` で確認します。設定のスコープやstdio接続は[Claude CodeのMCPガイド](https://code.claude.com/docs/en/mcp)を参照してください。

## Kilo CodeとJSON形式のクライアント

Kilo CodeのVS Code拡張では、MCP設定に有効なサーバーエントリを追加します。

```json
{
  "mcpServers": {
    "mecha_ghidra": {
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
    "mecha_ghidra": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mecha_ghidra",
        "run", "mecha_ghidra",
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

共有リポジトリの認証情報はHTTPクライアント設定ではなく、サーバーの[Ghidra Server設定](shared-projects.ja.md)で指定します。
