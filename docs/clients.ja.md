[English](clients.md) | [日本語](clients.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# MCPクライアント

クライアントごとに接続方式を1つ選びます。**HTTP**は別途起動したサーバーへ接続し、**stdio**はクライアントがサーバープロセスを起動・終了します。HTTPの場合は、先に[ローカル導入](usage.ja.md#local-setup)または[Docker導入](docker.ja.md)を済ませてください。

HTTPはMCPのセッションIDを発行せず、ステートレスなJSON応答を返します。ステートフルに戻す互換設定はありません。解析状態とタイムアウトの扱いは[接続方式の設定](configuration.ja.md#transports)を参照してください。

`--backend gui`（[GUIでのライブ共有](gui-live.ja.md)）では、どちらの接続方式も使えます。stdioでは、クライアントが中継を起動します。最初の中継がGhidraのGUIを起動し、後の中継や別のクライアントはそれを共有し、クライアントが終わってもGUIは開いたまま残ります。下のstdioの引数に `--backend gui` を足します（[GUIの設定の例](#gui)）。HTTPでは、`--backend gui --transport http` で起動したサーバーに接続します。

## プロトコルの版

サーバーは、MCPの2026-07-28版（`server/discover`。要求ごとにプロトコルの版と能力を載せる）で話し、`initialize` から始まる従来のクライアントにも応じます。設定は要りません。どちらで話すかはクライアントが決めます。2026年9月時点で、Claude Code 2.1.282は、HTTPでは2026-07-28版を使い、stdioでは `MCP_PROTOCOL_NEGOTIATION=auto` がなければ従来の方式を使います。CodexとVS Codeは従来の方式を使います。

結果のどこまでがAIに渡るかは、クライアントで異なります。たとえばClaude Code 2.1.282は、`structuredContent` があると、同じ結果のテキストを渡しません。結果は、データと案内を両方に載せています。[大きな結果](configuration.ja.md#large-results)のプレビューと `read_hint` も同じです。

## ツールの発見

Mecha Ghidraは標準の `tools/list` でツール定義を公開します。ツール検索に対応するクライアントは、必要な定義だけを後から読み込めます。サーバーの `instructions` は、プロファイルと個別フィルターで有効になったツールに基づいて、バイナリ解析の用途と検索する機能を説明します。readonly構成では編集機能を案内せず、BSim・共有リポジトリ・スクリプトも対応ツールの公開時だけ案内します。GUIのツールを公開するときは、人間がGUIで同じProgramを編集していることと、`show_in_gui` は頼まれたときだけ使うことも案内します。詳しい使い方はツール説明と `ghidra://docs/tools/{tool_name}` に置きます。

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

<a id="gui"></a>

## stdioでGhidraのGUIを使う

中継は、クライアントが渡す環境変数でGhidraのGUIを起動しますが、渡される変数は限られています。`GHIDRA_INSTALL_DIR` を渡し、Linuxでは `DISPLAY`（Xのサーバーが求めるなら `XAUTHORITY` も）を渡してください。絶対パスはすべて置き換えてください。`analysis.gpr` は既存である必要があります。

Codex（`~/.codex/config.toml`）：

```toml
[mcp_servers.mecha_ghidra_gui]
command = "uv"
args = [
  "--directory", "/absolute/path/to/mecha_ghidra",
  "run", "mecha_ghidra", "--backend", "gui",
  "--project-location", "/absolute/path/to/analysis.gpr",
  "--transport", "stdio"
]
env = { GHIDRA_INSTALL_DIR = "/absolute/path/to/ghidra" }
```

Claude Code：

```bash
claude mcp add mecha_ghidra_gui -e GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra -- uv --directory /absolute/path/to/mecha_ghidra run mecha_ghidra --backend gui --project-location /absolute/path/to/analysis.gpr --transport stdio
```

一つのGUIを共有するクライアントは、runtime全体に効く設定（パスの制限、`--domain-path`、target）をそろえて起動します（[stdioのクライアントから使う](gui-live.ja.md#stdio)）。

Windowsでは：

- Codexは、stdioのサーバーを、Codexが終わるときにその中のプロセスも終えるJob Objectの中で動かし、GUIもそこから出られません。そのため中継はGUIを起動せず、ツールの呼び出しは `RUNTIME_UNAVAILABLE` と、先にruntimeを起動するよう案内を返します。同じオプションに `--transport http` を付けて（8081が使われているなら `--mcp-port` も）端末でruntimeを起動し、その端末を開いたままCodexを使ってください。Codexの中継は、動いているruntimeにつながります。端末のプロセスは、人間がGhidraを終えたときに終わります。
- Claude Codeでは、中継がGUIを起動し、Claude Codeが終わってもGUIは残ります。
- CodexのTOMLでは、Windowsのパスをリテラル文字列（`'C:\path\to\ghidra'`）で書くか、バックスラッシュを二重にします。

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
3. [最初の解析](usage.ja.md#first-analysis)に進みます。既存プロジェクトなら `list_project_programs` と `load_project_program` を使います。読み込みでは解析しないため、応答が`is_analyzed: false`なら`analyze_program`を実行します。

GUIクライアントから `uv` が見つからない場合は、実行ファイルを絶対パスで指定してください。GUIアプリはシェルの環境変数を引き継がない場合があるため、stdioでは上記のように `GHIDRA_INSTALL_DIR` を明示します。どの呼び出しも、クライアントを待たせるのは最大で約50秒です。`import_program`・`analyze_program`・`run_script`は`wait_seconds`以内に応答してバックグラウンドのジョブとして動き、それ以外の呼び出しは40秒で終わらなければ`deferred: true`を返してサーバー上で処理を続けます（[長い呼び出し](usage.ja.md#long-calls)）。そのため、クライアント側の既定の60秒のタイムアウトで足ります。`--lock-timeout-seconds` は待ち行列での待機時間だけを制御し、クライアント側のタイムアウトは延長しません。

共有リポジトリの認証情報はHTTPクライアント設定ではなく、サーバーの[Ghidra Server設定](shared-projects.ja.md)で指定します。
