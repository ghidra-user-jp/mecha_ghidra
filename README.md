<img width="4096" height="700" alt="mecha_ghidra_one_line" src="https://github.com/user-attachments/assets/def48147-f8cf-4a6a-b4e6-cb3a43798d56" />

# Mecha Ghidra — Headless Ghidra MCP for Ghidra Server
PyGhidra と FastMCP で Ghidra を headless MCP サーバーとして公開する Python パッケージです。Ghidra プロジェクトの解析・編集に加え、複数ターゲット管理やプログラムの import/load 切り替え、オプションの shared project 同期機能を使った AI クライアントとの共同解析まで行えます。

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
   ```
   export GHIDRA_SERVER_PASSWORD='your-password'
   ```
6. **MCP サーバーの起動**
   ```bash
   uv run ghidra-mcp --project-location /Users/samsepi0l/ghidra_project.gpr --domain-path /main --transport http --mcp-host 127.0.0.1 --mcp-port 8081 --mcp-path /mcp
   ```
- 推奨は `--transport http` です。FastMCP の Streamable HTTP モードで起動し、`http://127.0.0.1:8081/mcp` で接続できます。
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
`domain_path` がまだない場合は、`register_target(target="patch", project_location="/path/to/project.gpr")` で project-only ターゲットを先に登録し、`import_program` と `load_project_program` を続けて呼び出してください。
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

#### Core Operations

- `list_targets` - 登録済みターゲットと紐づくプロジェクト情報を一覧表示
- `create_session` - 既存プロジェクトのプログラムを開いてターゲットを追加
- `register_target` - プログラムを開かずにターゲットへプロジェクト情報のみ登録
- `close_session` - ターゲットのセッションをクローズ
- `close_session_and_remove_program` - セッションを閉じたうえでプログラムをプロジェクトから削除
- `list_project_programs` - ターゲットが開いているプロジェクト内プログラム一覧を取得
- `import_program` - バイナリまたは `.gzf` をプロジェクトへインポート
- `load_project_program` - 既存プログラムを指定 `domain_path` でロード

#### Function Analysis

- `list_methods` - メソッド一覧を取得（ページング対応）
- `list_functions` - 関数一覧を取得
- `list_classes` - クラス一覧を取得
- `list_namespaces` - 名前空間一覧を取得（ページング対応）
- `search_functions_by_name` - 関数名の部分一致検索
- `decompile_function` - 関数名指定で C 擬似コードを取得
- `decompile_function_by_address` - アドレス指定で C 擬似コードを取得
- `disassemble_function` - 関数の逆アセンブル結果を取得
- `get_function_by_address` - アドレスに対応する関数情報を取得
- `get_function_xrefs` - 関数名を起点に参照元/参照先を取得
- `get_callee` - 指定アドレスの呼び出し先関数を取得

#### Memory & Data

- `list_segments` - メモリセグメント/レイアウト情報を取得
- `list_imports` - インポートシンボル一覧を取得
- `list_exports` - エクスポートシンボル一覧を取得
- `list_data_items` - データアイテム一覧を取得
- `list_strings` - 文字列一覧を取得（フィルタ対応）
- `get_xrefs_to` - 指定アドレスへのクロスリファレンスを取得
- `get_xrefs_from` - 指定アドレスからのクロスリファレンスを取得
- `get_data_by_label` - ラベル名からデータを取得
- `get_bytes` - 指定アドレスのバイト列を取得
- `search_bytes` - バイトパターン検索

#### Symbol & Comment Editing

- `rename_function` - 関数名を変更（名前指定）
- `rename_function_by_address` - 関数名を変更（アドレス指定）
- `rename_variable` - ローカル変数名を変更
- `rename_data` - データラベル名を変更
- `set_function_prototype` - 関数プロトタイプを設定
- `set_local_variable_type` - ローカル変数の型を設定
- `set_global_data_type` - グローバルデータの型を設定
- `set_bytes` - メモリ内容をバイト列で書き換え
- `set_decompiler_comment` - デコンパイラコメントを設定
- `set_disassembly_comment` - 逆アセンブリコメントを設定
- `add_bookmark` - ブックマークを追加

#### Data Type Operations

- `create_struct` - 構造体を作成
- `add_struct_members` - 構造体メンバーを追加
- `clear_struct` - 構造体メンバーを全削除
- `remove_struct_members` - 構造体メンバーを選択削除
- `get_struct` - 構造体定義を取得
- `create_enum` - 列挙体を作成
- `add_enum_values` - 列挙体の値を追加
- `remove_enum_values` - 列挙体の値を削除
- `get_enum` - 列挙体定義を取得
- `add_class_members` - クラス相当データ型へメンバーを追加
- `remove_class_members` - クラス相当データ型からメンバーを削除

#### Shared Project Sync (`--enable-shared-project-sync` 指定時のみ)

`get_project_sync_status` / `get_version_history` / `get_version_diff` / `checkout` / `commit` / `pull` / `undo_checkout` / `terminate_checkout` / `reload` は `domain_path` を任意指定できます（未指定時は現在ロード中のprogram）。

- `get_project_sync_status` - shared project 上の同期状態を取得
- `get_version_history` - バージョン履歴（version/user/comment/time）を取得
- `get_version_diff` - 2バージョン間の差分要約（件数/タイプ別/アドレスレンジ）を取得
- `checkout_project_program` - プログラムを checkout（排他指定可）
- `add_project_program_to_version_control` - private プログラムを shared 管理へ追加
- `commit_project_program` - checkout 中の変更を check-in
- `pull_project_program` - 最新状態を取得（必要に応じて破棄/追従）
- `undo_checkout_project_program` - checkout を取り消し（ローカル変更破棄可）
- `terminate_project_program_checkout` - 既存 checkout を checkout ID で強制終了
- `reload_project_program` - 現在プログラムを再ロード

## Ghidra Serverの設定

### インストール・ユーザ設定

サーバーのインストール
```
sudo GHIDRA_INSTALL_DIR/server/svrInstall 
```

自分自身のユーザとmecha ghidra用のユーザを登録
```
sudo GHIDRA_INSTALL_DIR/server/svrAdmin -add your_username
sudo GHIDRA_INSTALL_DIR/server/svrAdmin -add mecha-ghidra
```

GHIDRA_INSTALL_DIR/server/server.confを編集して、ユーザ名を指定して接続できるようにする。
* ${ghidra.repositories.dir}は必ず最後に指定する
```
wrapper.app.parameter.1=-a0
wrapper.app.parameter.2=-u
wrapper.app.parameter.3=${ghidra.repositories.dir}
```

ghidraを起動する
```
sudo server/ghidraSvr restart
```

New　ProjectからShared Projectを作成

<img width="508" height="388" alt="Image" src="https://github.com/user-attachments/assets/1091c615-1590-4a49-aa2c-7628d6efed70" />

localhostに接続

<img width="508" height="388" alt="image" src="https://github.com/user-attachments/assets/0d1a0cef-fbee-4513-af18-3193a3529c2f" />

作成したユーザでログインする
初回パスワードは`changeme`

<img width="350" height="179" alt="image" src="https://github.com/user-attachments/assets/e03718b4-89df-4a2b-8609-521a42dd1878" />

初回ログイン時にパスワードを変更するように言われるので、作成したユーザ2つのユーザのパスワードを変更する

<img width="353" height="181" alt="image" src="https://github.com/user-attachments/assets/24da9ede-db7b-4ba2-8107-2fb7fe895968" />


プロジェクトを作成する。LLMのアカウントはRead/Writeに設定。

<img width="652" height="383" alt="image" src="https://github.com/user-attachments/assets/3da1693c-3dd7-4ba8-a6e6-95b4767cf95c" />



<img width="531" height="389" alt="image" src="https://github.com/user-attachments/assets/76ef63d5-de7a-48ca-8758-76b5157a98c3" />


<img width="531" height="389" alt="image" src="https://github.com/user-attachments/assets/80a8aa7e-659b-4d8e-bf5f-65eea292dc7f" />


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

streamable-http を使う必要があるクライアントでは `--transport http` で起動し、`http://127.0.0.1:8081/mcp` を指定してください。

各 JSON は Kilocode/Roocode の MCP 設定画面に貼り付け、必要に応じて `--session` の内容（追加ターゲット）やポート番号を調整してください。設定後を再読み込みすると、`list_methods` や `create_session` など本パッケージの MCP ツールを利用できます。

## 開発・テスト

- 依存関係の更新: `uv add <package>` / `uv remove <package>`
- コード整形・型チェックなど必要に応じてツールを追加し、`uv run <tool>` で実行してください。
- テスト実行: まず `uv sync --extra test` でテスト依存 (`pytest`, `pytest-mock`) をインストールし、`uv run pytest` でユニットテストを実行できます。

## ライセンス

このプロジェクトのライセンスは同梱の LICENSE ファイルを参照してください。
