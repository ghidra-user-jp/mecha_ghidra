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
- `linux/arm64` を使う場合は、Docker build が既定で同梱の mecha_ghidra patched Ghidra 配布物を自動選択します。upstream の公式 ZIP を ARM64 へ無理に指定した場合は、`decompile_function` 実行時に遅れて落ちる代わりに build 時点で明確なエラーを返します。
- 独自の patched ZIP を使いたい場合は、`GHIDRA_DIST_URL` と `GHIDRA_DIST_SHA256` を両方指定して上書きできます。
- `./samples` はコンテナ内に `/samples` として read-only 共有されます。`import_program` では `/samples/<filename>` を指定してください。
- Ghidra project は named volume `ghidra-projects` に永続化され、既定の project path は `/data/projects/default.gpr` です。初回利用前に一度その project を作成するか、既存の Ghidra project をそこへ mount してください。
- 起動直後は program 未ロードの状態です。`import_program(target="default", binary_path="/samples/<filename>")` 実行後、返ってきた `domain_path` を `load_project_program` に渡してください。
- 推奨共有方法は「入力 bind mount(read-only) + Ghidra project named volume(read-write)」です。`import_program` は入力ファイルを project にコピーするので入力側は read-only で十分で、`.rep` 配下の重い I/O は bind mount より volume の方が安定しやすいためです。

## Linux ARM64 decompiler 配布物

このリポジトリには、Linux ARM64 向け Ghidra decompiler を生成して配布する専用導線を追加しました。

- `./scripts/build_linux_arm64_decompiler.sh` で `linux_arm_64` 用の native `decompile` / `sleigh` をビルドできます。
- release workflow では次の 2 種類を publish します。
  - `ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
  - `ghidra_*_linux_arm_64_decompiler.zip`
- overlay tarball には `Ghidra/Features/Decompiler/os/linux_arm_64/{decompile,sleigh}` のパスがそのまま入るので、既存の Ghidra install にそのまま展開できます。
- patched ZIP は ARM Linux の Docker build や、ARM Linux へそのまま配置する用途を想定しています。
- GitHub release には、Apple Silicon / Linux ARM64 の Docker 用・overlay 用だと分かるように `mecha_ghidra_docker_arm64_*.zip` / `*.tar.gz` も publish します。
- 通常のリポジトリ snapshot は、GitHub 標準の `Source code (zip)` / `Source code (tar.gz)` を使ってください。

ARM64 Docker build 例:

```bash
DOCKER_PLATFORM=linux/arm64 docker compose build
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

別の成果物へ上書きしたい場合:

```bash
DOCKER_PLATFORM=linux/arm64 \
GHIDRA_DIST_URL=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/<release-tag>/ghidra_12.0.4_PUBLIC_20260303_linux_arm_64_decompiler.zip \
GHIDRA_DIST_SHA256=<release-asset-sha256> \
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
- `rename_variable` - ローカル変数名/引数名を変更
- `rename_data` - データラベル名を変更
- `set_function_prototype` - 関数プロトタイプを設定
- `set_local_variable_type` - ローカル変数/引数の型を設定
- `set_global_data_type` - グローバルデータの型を設定（`clear_mode` 指定可）
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
- `safety`: `safe_readonly`, `safe_nonsemantic_edit`, `unsafe_semantic_edit`, `unsafe_binary_destructive`, `unsafe_nonbinary_destructive`
- `operation_level`: `basic`, `standard`, `advanced`

プロファイル:

- `default`: 既存互換。`core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`
- `readonly`: `default` の category + `safe_readonly` のみ
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
    --allow-safety safe_readonly
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
