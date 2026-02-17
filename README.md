# GhidraMCP headless

PyGhidra を利用して Ghidra のヘッドレス機能を MCP ツールとして公開する Python パッケージです。従来の Jython スクリプトによる HTTP サーバーを置き換え、純粋な Python 3.10 以降の環境で Ghidra プロジェクトを操作できます。

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

4. **Ghidra パスの設定**
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```
   PyGhidra が Ghidra 本体を見つけられるようにしてください。

5. **MCP サーバーの起動**
   ```bash
   uv run ghidra-mcp --project-location /Users/samsepi0l/ghidra_project.gpr --domain-path /main --transport stream-http --mcp-host 127.0.0.1 --mcp-port 8081 --mcp-path /mcp
   ```
- 推奨は `--transport stream-http` です。FastMCP の Streamable HTTP モードで起動し、`http://127.0.0.1:8081/mcp` で接続できます。
- 互換性のため `--transport sse` も引き続き利用できます（`/sse`）。

### プロジェクト内でのプログラム追加・切り替え

1. **セッション作成（プロジェクトを開く）**
   ```bash
   create_session(target="fw", project_location="/path/project", project_name="Sample", domain_path="/folder/program1")
   ```
2. **プログラム一覧確認**
   ```bash
   list_project_programs(target="fw")
   ```
   - `target` は必須です。
3. **（任意）新しいバイナリをプロジェクトに追加**
   ```bash
   import_program(target="fw", binary_path="/tmp/new_firmware.bin")
   ```
4. **別プログラムを読み込み（既存プログラムへ切替）**
   ```bash
   load_project_program(target="fw", domain_path="/folder/program2")
   ```
5. **解析ツール呼び出し**（例: `list_methods(target="fw")`）
6. **不要になったら `close_session(target="fw")` でクリーンアップ（プロジェクトからプログラムも消す場合は `close_session_and_remove_program(target="fw")`）**

#### プログラムA/Bを別セッションで解析する例

1. MCP サーバー起動（プログラムAを読み込む）
```bash
uv run ghidra-mcp \
    --project-location /path/to/projectDir \
    --project-name SampleProject \
    --domain-path /folder/programA \
    --target-name targetA \
    --transport stdio
```

2. プログラムB用のセッションを追加
```python
create_session(
    target="targetB",
    project_location="/path/to/projectDir",
    project_name="SampleProject",
    domain_path="/folder/programB"
)
```

3. セッションごとに解析ツールを実行
```python
list_methods(target="targetA")
decompile_function(name="main", target="targetB")
get_function_xrefs(name="init", target="targetA")
```

4. `targetB` 内で別プログラムに切り替えたい場合（任意）
```python
list_project_programs(target="targetB")
load_project_program(target="targetB", domain_path="/folder/programC")
import_program(target="targetB", binary_path="/tmp/programD.bin")
load_project_program(target="targetB", domain_path="/programD.bin")
```
- `import_program` は追加のみを行い、現在の解析対象は切り替えません。必要なら続けて `load_project_program` を呼び出してください。

5. 作業終了後はセッションを順に閉じる（プロジェクトから削除したい場合は `close_session_and_remove_program` を使用）
```python
close_session(target="targetB")
close_session(target="targetA")
```

### 複数ターゲットを同時にロードする例

複数のバイナリ／プロジェクトを同時に開きたい場合は、`--session` オプションを複数回指定します。各定義はカンマ区切りで `name=...`, `project_location=...`, `domain_path=...`（必要なら `project_name=...`）を渡してください。

```bash
uv run ghidra-mcp \
    --session name=firmware,project_location=/path/fw_project.gpr,domain_path=/firmware.bin \
    --session name=game,project_location=/path/game_project,project_name=GameProj,domain_path=/main \
    --transport stdio
```

MCP ツール呼び出し時は `target="firmware"` のようにターゲット名を指定することで、操作対象プログラムを切り替えられます。現在登録済みのターゲットは `list_targets` ツールで確認できます。

サーバー起動後でも、`create_session` ツールを呼び出すことで新しいターゲットを追加できます（例: `create_session(target="patch", project_location="/path/to/project.gpr", domain_path="/folder/programX")`）。
新規バイナリを解析対象にしたい場合は、`import_program(target="patch", binary_path="/tmp/patch.bin")` で追加してから `load_project_program(target="patch", domain_path="/patch.bin")` で切り替えてください。不要になったターゲットは `close_session(target="patch")` またはプロジェクトから削除する `close_session_and_remove_program(target="patch")` で解放してください。

## 主要機能

- **関数・シンボル操作**: 関数一覧、デコンパイル、リネーム、Xref 取得など。
- **データ型編集**: 構造体・列挙体・クラス相当のデータ型作成／更新／削除に対応。
- **メモリアクセス**: メモリのバイト列取得・検索・書き込み、グローバルデータ型の適用。
- **コメント付与**: 逆アセンブリ／デコンパイラコメントの設定が可能。
- **PyGhidra ベース**: Jython ではなく CPython 上で Ghidra API を直接呼び出します。
- **複数ターゲット管理**: 同一プロセスで複数セッションを保持し、ターゲット名で切り替えながら解析できます。
- **プロジェクト操作**: `list_project_programs` でプロジェクト内のプログラム一覧を取得し、`import_program` で新規バイナリを追加、`load_project_program` で既存プログラムへ切り替えできます。

FastMCP のツールは `ghidra_headless.handlers.core` にまとめてあり、MCP クライアントからは `ghidra_mcp.cli` を通じて利用できます。詳しいオプションは `uv run ghidra-mcp --help` を参照してください。

### 提供ツール一覧

- **ターゲット管理**: `list_targets`, `create_session`, `close_session`, `close_session_and_remove_program`, `list_project_programs`, `import_program`, `load_project_program`
- **解析支援**: `list_methods`, `list_functions`, `list_classes`, `list_namespaces`, `list_segments`, `list_imports`, `list_exports`, `list_data_items`, `list_strings`, `search_functions_by_name`, `search_bytes`, `get_function_by_address`, `get_function_xrefs`, `get_xrefs_to`, `get_xrefs_from`, `get_callee`, `get_data_by_label`, `get_bytes`, `decompile_function`, `decompile_function_by_address`, `disassemble_function`
- **シンボル／コメント編集**: `rename_function`, `rename_function_by_address`, `rename_variable`, `rename_data`, `set_function_prototype`, `set_local_variable_type`, `set_global_data_type`, `set_bytes`, `add_bookmark`, `set_decompiler_comment`, `set_disassembly_comment`
- **データ型操作**: `create_struct`, `add_struct_members`, `clear_struct`, `remove_struct_members`, `get_struct`, `create_enum`, `add_enum_values`, `get_enum`, `remove_enum_values`, `add_class_members`, `remove_class_members`

## Kilocode / Roocode での MCP 設定

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
      "alwaysAllow": [
        "list_methods",
        "list_classes",
        "decompile_function",
        "rename_function",
        "create_session",
        "close_session",
        "close_session_and_remove_program"
      ],
      "timeout": 300,
      "disabled": true
    },
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
      "alwaysAllow": [
        "list_targets",
        "list_project_programs",
        "import_program",
        "load_project_program",
        "decompile_function",
        "get_data_by_label",
        "get_bytes",
        "get_xrefs_to",
        "get_function_by_address",
        "disassemble_function",
        "list_strings"
      ]
    },
```

SSE を使う必要があるクライアントでは `--transport sse` で起動し、`http://127.0.0.1:8081/sse` を指定してください。

各 JSON は Kilocode/Roocode の MCP 設定画面に貼り付け、必要に応じて `--session` の内容（追加ターゲット）やポート番号を調整してください。設定後を再読み込みすると、`list_methods` や `create_session` など本パッケージの MCP ツールを利用できます。

## 開発・テスト

- 依存関係の更新: `uv add <package>` / `uv remove <package>`
- コード整形・型チェックなど必要に応じてツールを追加し、`uv run <tool>` で実行してください。
- テスト実行: まず `uv sync --extra test` でテスト依存 (`pytest`, `pytest-mock`) をインストールし、`uv run pytest` でユニットテストを実行できます。

## ライセンス

このプロジェクトのライセンスは同梱の LICENSE ファイルを参照してください。
