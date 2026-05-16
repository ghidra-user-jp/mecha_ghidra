<img src="https://github.com/user-attachments/assets/0adbf0e3-4ad9-4a7b-87a6-62a2f9921bb7" />

[English](README.md) | [日本語](README.ja.md)

# Mecha Ghidra — Headless Ghidra MCP for Ghidra Server
PyGhidra と FastMCP で Ghidra を headless MCP サーバーとして公開する Python パッケージです。Ghidra プロジェクトの解析・編集に加え、複数ターゲット管理やプログラムの import/load 切り替え、タグベースで制御できる shared project 同期機能を使った AI クライアントとの共同解析まで行えます。

## ドキュメント

- [利用ガイド](docs/usage.ja.md) | [English](docs/usage.md): セットアップ、shared project 運用、複数ターゲット運用、Kilocode/Roocode 連携
- [開発ガイド](docs/development.ja.md) | [English](docs/development.md): 開発フロー、テスト実行

## クイックスタート

1. 依存関係を同期
   ```bash
   uv sync
   ```
2. Ghidra パスを設定
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```
3. サーバーを起動（Streamable HTTP）
   ```bash
   uv run ghidra-mcp \
        --project-location /Users/samsepi0l/ghidra_project.gpr \
        --domain-path /main \
       --transport http \
       --mcp-host 127.0.0.1 \
       --mcp-port 8081 \
        --mcp-path /mcp
   ```

運用パターンや shared project 認証を含む詳細は [利用ガイド](docs/usage.ja.md) を参照してください。

## Docker クイックスタート

Ghidra 同梱イメージで起動したい場合は、同梱の `Dockerfile` と `docker-compose.yml` を使えます。

1. 解析対象を置くディレクトリを作成
   ```bash
   mkdir -p samples
   ```
2. イメージをビルド（推奨）
   ```bash
   ./build_docker_image.sh
   ```
3. MCP サーバーを起動
   ```bash
   docker compose up -d
   ```
4. MCP クライアントは `http://127.0.0.1:8081/mcp` に接続

- `docker compose build` も引き続き利用できます。同梱 compose は既定で `DOCKER_PLATFORM=linux/amd64` を使い、これは同梱 Linux decompiler を動かすために必要です。
- `linux/arm64` を使う場合は、Docker build が upstream 公式 Ghidra 配布物に mecha_ghidra の decompiler natives overlay を重ねます。ARM64 overlay が無い状態なら、`decompile_function` 実行時に遅れて落ちる代わりに build 時点で明確なエラーを返します。
- Ghidra 配布物を上書きしたい場合は `GHIDRA_DIST_URL` と `GHIDRA_DIST_SHA256` を両方指定します。ARM64 overlay も上書きする場合は、`GHIDRA_DECOMPILER_NATIVES_URL` と `GHIDRA_DECOMPILER_NATIVES_SHA256` も両方指定してください。
- `./samples` はコンテナ内に `/samples` として read-only 共有されます。`import_program` では `/samples/<filename>` を指定してください。
- Ghidra project は named volume `ghidra-projects` に永続化され、既定の project path は `/data/projects/default.gpr` です。初回利用前に一度その project を作成するか、既存の Ghidra project をそこへ mount してください。
- 起動直後は program 未ロードの状態です。`import_program(target="default", binary_path="/samples/<filename>")` 実行後、返ってきた `domain_path` を `load_project_program` に渡してください。
- 推奨共有方法は「入力 bind mount(read-only) + Ghidra project named volume(read-write)」です。`import_program` は入力ファイルを project にコピーするので入力側は read-only で十分で、`.rep` 配下の重い I/O は bind mount より volume の方が安定しやすいためです。

## native decompiler 配布物

このリポジトリには、upstream 配布物に含まれない場合がある Ghidra native decompiler を生成して配布する専用導線があります。

- `./scripts/build_linux_arm64_decompiler.sh` で `linux_arm_64` 用の native `decompile` / `sleigh` をビルドできます。
- `./scripts/build_decompiler_natives.sh --platform mac_arm_64` で Apple Silicon macOS 用の native `decompile` / `sleigh` をビルドできます。
- `./scripts/build_decompiler_natives.sh --platform mac_x86_64` で Intel macOS 用の native `decompile` / `sleigh` をビルドできます。
- build script は次の raw artifacts を生成します。
  - `ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
  - `ghidra_*_linux_arm_64_decompiler.zip`
  - `ghidra_*_mac_arm_64_decompiler_overlay.tar.gz`
  - `ghidra_*_mac_arm_64_decompiler.zip`
  - `ghidra_*_mac_x86_64_decompiler_overlay.tar.gz`
  - `ghidra_*_mac_x86_64_decompiler.zip`
- overlay tarball には `Ghidra/Features/Decompiler/os/<platform>/{decompile,sleigh}` のパスがそのまま入るので、既存の Ghidra install にそのまま展開できます。
- patched ZIP は対象 platform ごとに、ARM Linux Docker/直接配置、Apple Silicon macOS、Intel macOS で使う想定です。
- GitHub release には、追加した native decompiler ファイルをすべて含む利用者向け `mecha_ghidra_decompiler_natives_all.zip` を 1 つだけ publish します。
  - `Ghidra/Features/Decompiler/os/linux_arm_64/decompile`
  - `Ghidra/Features/Decompiler/os/linux_arm_64/sleigh`
  - `Ghidra/Features/Decompiler/os/mac_arm_64/decompile`
  - `Ghidra/Features/Decompiler/os/mac_arm_64/sleigh`
  - `Ghidra/Features/Decompiler/os/mac_x86_64/decompile`
  - `Ghidra/Features/Decompiler/os/mac_x86_64/sleigh`
- release 本文には、zip の展開位置の説明と上記の追加パスを書きます。
- 通常のリポジトリ snapshot は、GitHub 標準の `Source code (zip)` / `Source code (tar.gz)` を使ってください。

ARM64 Docker build 例:

```bash
DOCKER_PLATFORM=linux/arm64 docker compose build
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

別の成果物へ上書きしたい場合:

```bash
DOCKER_PLATFORM=linux/arm64 \
GHIDRA_DECOMPILER_NATIVES_URL=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/<release-tag>/mecha_ghidra_decompiler_natives_all.zip \
GHIDRA_DECOMPILER_NATIVES_SHA256=<release-asset-sha256> \
docker compose build
```

ARM Linux 上で patched binary が無いまま起動した場合は、`linux_arm_64` native が不足していることを明示するエラーを返します。

## 主要機能

- **関数・シンボル操作**: 関数一覧、デコンパイル、リネーム、Xref 取得など。
- **データ型編集**: 構造体・列挙体・クラス相当のデータ型作成／更新／削除に対応。
- **メモリアクセス**: メモリのバイト列取得・検索・書き込み、グローバルデータ型の適用。
- **コメント付与**: 逆アセンブリ／デコンパイラコメントの設定が可能。
- **PyGhidra ベース**: Jython ではなく CPython 上で Ghidra API を直接呼び出します。
- **複数ターゲット管理**: 同一プロセスで複数セッションを保持し、ターゲット名で切り替えながら解析できます。
- **プロジェクト操作**: `create_project` でローカル project を作成し、`list_project_programs` でプログラム一覧取得、`import_program` で新規バイナリ追加、`load_project_program` で既存プログラムへ切り替えできます。

FastMCP のツールは `ghidra_headless.handlers.core` にまとめてあり、MCP クライアントからは `ghidra_mcp.cli` を通じて利用できます。詳しいオプションは `uv run ghidra-mcp --help` を参照してください。

### 提供ツール一覧

#### Core Operations

- `list_targets` - 登録済みターゲットと紐づくプロジェクト情報を一覧表示
- `create_project` - 空のローカル Ghidra project を作成
- `create_session` - 既存プロジェクトのプログラムを開いてターゲットを追加
- `register_target` - プログラムを開かずにターゲットへプロジェクト情報のみ登録
- `close_session` - ターゲットのセッションをクローズ
- `close_session_and_remove_program` - セッションを閉じたうえでプログラムをプロジェクトから削除
- `list_project_programs` - ターゲットが開いているプロジェクト内プログラム一覧を取得
- `import_program` - バイナリまたは `.gzf` をプロジェクトへインポート
- `load_project_program` - 既存プログラムを指定 `domain_path` でロード
- `save_project_program` - 編集後の現在ロード中 program を Ghidra project に保存

#### Function Analysis

- `list_methods` - メソッド一覧を取得（ページング対応）
- `list_functions` - 関数一覧を取得
- `list_classes` - クラス一覧を取得
- `list_namespaces` - 名前空間一覧を取得（ページング対応）
- `search_functions_by_name` - 関数名の部分一致検索
- `decompile_function` - 関数名指定で C 擬似コードを取得
- `decompile_function_by_address` - アドレス指定で C 擬似コードを取得
- `disassemble_function` - 関数の逆アセンブル結果を取得
- `disassemble_range` - アドレス範囲の逆アセンブル結果を取得
- `get_function_by_address` - アドレスに対応する関数情報を取得
- `create_function` - アドレスに関数を作成
- `delete_function` - アドレス指定で関数を削除
- `analyze_program` - 未解析扱いの program に解析を実行
- `reanalyze_program` - program 解析を強制的に再実行
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
- `rename_variable` - ローカル変数名/引数名を変更
- `rename_data` - データラベル名を変更
- `set_function_prototype` - 関数プロトタイプを設定
- `set_local_variable_type` - ローカル変数/引数の型を設定
- `set_global_data_type` - グローバルデータの型を設定（`clear_mode` 指定可）
- `set_bytes` - メモリ内容をバイト列で書き換え
- `set_decompiler_comment` - デコンパイラコメントを設定
- `set_disassembly_comment` - 逆アセンブリコメントを設定
- `add_bookmark` - ブックマークを追加
- `list_bookmarks` - ブックマーク一覧を取得
- `delete_bookmark` - ID または address/type/category 指定でブックマークを削除

`rename_function_by_address` などの更新系 tool を使った後は、`save_project_program(target="default")` を呼ぶと変更が Ghidra project に保存されます。Ghidra GUI 側で同じ program を開いている場合、保存後の状態を見るには GUI 側で再オープンまたはリロードしてください。

#### Data Type Operations

- `create_struct` - 構造体を作成
- `add_struct_members` - 構造体メンバーを追加
- `clear_struct` - 構造体メンバーを全削除
- `remove_struct_members` - 構造体メンバーを選択削除
- `delete_struct` - 構造体データ型を削除
- `get_struct` - 構造体定義を取得
- `list_data_types` - program 内のデータ型一覧を取得
- `rename_data_type` - データ型名を変更
- `create_enum` - 列挙体を作成
- `add_enum_values` - 列挙体の値を追加
- `remove_enum_values` - 列挙体の値を削除
- `delete_enum` - 列挙体データ型を削除
- `get_enum` - 列挙体定義を取得
- `create_class` - GhidraClass 名前空間と対応構造体を作成
- `add_class_members` - クラス相当データ型へメンバーを追加
- `remove_class_members` - クラス相当データ型からメンバーを削除

#### Shared Project Sync（`shared_sync` category）

`get_project_sync_status` / `get_version_history` / `get_version_diff` / `checkout` / `add_to_version_control` / `commit` / `pull` / `undo_checkout` / `terminate_checkout` / `delete_shared_project_file` / `reload` は記載のある箇所で `domain_path` を指定できます（未指定時は現在ロード中のprogram。削除は明示的な `domain_path` が必須）。

- `get_project_sync_status` - shared project 上の同期状態を取得
- `get_version_history` - バージョン履歴（version/user/comment/time）を取得
- `get_version_diff` - 2バージョン間の差分要約（件数/タイプ別/アドレスレンジ）を取得
- `checkout_project_program` - プログラムを checkout（排他指定可）
- `add_project_program_to_version_control` - private プログラムを shared 管理へ追加
- `commit_project_program` - checkout 中の変更を check-in（競合 checkout を破棄する場合は `on_conflict="discard"` を明示）
- `pull_project_program` - 最新状態を取得（必要に応じて破棄/追従）
- `undo_checkout_project_program` - checkout を取り消し（ローカル変更破棄可）
- `terminate_project_program_checkout` - 既存 checkout を checkout ID で強制終了
- `delete_shared_project_file` - `confirm` が `domain_path` と一致した未ロードの shared project file を削除
- `reload_project_program` - 現在プログラムを再ロード

詳細な運用フローや制約事項は [利用ガイド](docs/usage.ja.md) を参照してください。

### ツール公開制御

各ツールには次の 3 種類のタグがあります。

- `category`: `core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`, `shared_sync`
- `safety`: `read_only`, `write`, `destructive_write`
- `operation_level`: `basic`, `standard`, `advanced`

プロファイル:

- `default`: 既存互換。`core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`
- `readonly`: `default` の category + `read_only` のみ
- `full`: 全 category を公開。`shared_sync` も含む

評価ルール:

- ツール制御引数を何も付けない場合は `--tool-profile default` と同じ
- `shared_sync` は通常の `category` として扱う
- 既定では `shared_sync` を含まない
- `--enable-shared-project-sync` は廃止
- 同じ種類の allow 指定は OR
- 異なる種類の allow 指定は AND
- `--allow-category` は現在の category 集合を置き換える
- `--add-category` は現在の category 集合に追加する
- `--enable-tool` はタグ/profile フィルタ後に追加する
- `--disable-tool` は最後に除外し、常に優先される

起動例:

既存互換:

```bash
uv run ghidra-mcp --project-location /path/to/project.gpr --domain-path /main
```

readonly:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile readonly
```

full:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile full
```

default + shared_sync 追加:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile default \
    --add-category shared_sync
```

full + readonly 絞り込み:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile full \
    --allow-safety read_only
```

個別 enable / disable:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile readonly \
    --enable-tool rename_function \
    --disable-tool set_bytes
```

## ライセンス

このプロジェクトのライセンスは同梱の LICENSE ファイルを参照してください。
