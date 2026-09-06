<img src="https://github.com/user-attachments/assets/0adbf0e3-4ad9-4a7b-87a6-62a2f9921bb7" />

[English](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/README.md) | [日本語](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/README.ja.md)

# Mecha Ghidra — Headless Ghidra MCP for Ghidra Server
PyGhidra と公式 MCP Python SDK（`mcp` 2.x）で Ghidra を headless MCP サーバーとして公開する Python パッケージです。Ghidra プロジェクトの解析・編集に加え、複数ターゲット管理やプログラムの import/load 切り替え、タグベースで制御できる shared project 同期機能を使った AI クライアントとの共同解析まで行えます。

## ドキュメント

- [利用ガイド](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.ja.md) | [English](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.md): セットアップ、shared project 運用、複数ターゲット運用、Kilocode/Roocode 連携
- [開発ガイド](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/development.ja.md) | [English](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/development.md): 開発フロー、テスト実行

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
       --project-location /path/to/ghidra_project.gpr \
       --transport http
   ```

運用パターンや shared project 認証を含む詳細は [利用ガイド](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.ja.md) を参照してください。

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
- 同梱 Compose の port は host loopback（`127.0.0.1:8081`）だけに公開されます。外部公開する場合は port 設定を明示的に上書きし、TLS、認証、ネットワークアクセス制御を併用してください。
- `linux/arm64` を使う場合は、Docker build が upstream 公式 Ghidra 配布物に mecha_ghidra の decompiler natives overlay を重ねます。ARM64 overlay が無い状態なら、`decompile_function` 実行時に遅れて落ちる代わりに build 時点で明確なエラーを返します。
- Ghidra 配布物を上書きしたい場合は `GHIDRA_DIST_URL` と `GHIDRA_DIST_SHA256` を両方指定します。ARM64 overlay も上書きする場合は、`GHIDRA_DECOMPILER_NATIVES_URL` と `GHIDRA_DECOMPILER_NATIVES_SHA256` も両方指定してください。
- ARM64/macOS 向け native decompiler 配布物の種類、生成方法、release asset の使い分けは [利用ガイド](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.ja.md#native-decompiler-%E9%85%8D%E5%B8%83%E7%89%A9) を参照してください。
- `./samples` はコンテナ内に `/samples` として read-only 共有されます。`import_program` では `/samples/<filename>` を指定してください。
- コンテナは `--allowed-import-root /samples --allowed-project-root /data/projects --allowed-export-root /data/exports`（ホストの `./exports`）付きで起動します。MCP クライアントが import できるのは共有した samples ディレクトリ配下のファイルだけで、プロジェクトの作成・オープンもプロジェクト用ボリューム配下に限定されます。実行ユーザーは非 root（uid 10001）で、8081 番ポートに対する TCP ヘルスチェックが有効です。
- Ghidra project は named volume `ghidra-projects` に永続化され、既定の project path は `/data/projects/default.gpr` です。初回利用前に一度その project を作成するか、既存の Ghidra project をそこへ mount してください。
- 起動直後は program 未ロードの状態です。`import_program(target="default", binary_path="/samples/<filename>")` 実行後、返ってきた `domain_path` を `load_project_program` に渡してください。
- 推奨共有方法は「入力 bind mount(read-only) + Ghidra project named volume(read-write)」です。`import_program` は入力ファイルを project にコピーするので入力側は read-only で十分で、`.rep` 配下の重い I/O は bind mount より volume の方が安定しやすいためです。

## 主要機能

- **関数・シンボル操作**: 関数一覧、デコンパイル、リネーム、Xref 取得など。
- **データ型編集**: 構造体の作成／更新／削除と列挙体の参照に対応。
- **メモリアクセス**: メモリのバイト列取得・検索・書き込み、グローバルデータ型の適用。
- **コメント付与**: 逆アセンブリ／デコンパイラコメントの設定が可能。
- **PyGhidra ベース**: Jython ではなく CPython 上で Ghidra API を直接呼び出します。
- **複数ターゲット管理**: 同一プロセスで複数セッションを保持し、ターゲット名で切り替えながら解析できます。
- **プロジェクト操作**: `create_project` でローカル project を作成し、`list_project_programs` でプログラム一覧取得、`import_program` で新規バイナリ追加、`load_project_program` で既存プログラムへ切り替えできます。
- **コンテキスト効率の良い大型結果**: コンテキストを実際に削減できる場合、大型のツール結果を短いプレビューと `result_id` に置き換え、保存した全文を `read_result` / `search_result` で必要な分だけ取得できます（詳細は[大型結果の圧縮](#大型結果の圧縮)）。

ツールの実装は `ghidra_headless.handlers.core` にまとめてあり、MCP クライアントからは `ghidra_mcp.cli` を通じて利用できます。詳しいオプションは `uv run ghidra-mcp --help` を参照してください。

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
- `load_project_program` - 既存プログラムを指定 `domain_path` でロード。ターゲットが既に保持している program を指定すると再ロード、`version=N` で shared project の過去バージョンを読み取り専用で開く
- `save_project_program` - 編集後の現在ロード中 program を Ghidra project に保存
- `get_program_info` - 言語、コンパイラ、イメージベース、md5/sha256、エントリポイント、解析済みフラグ、未保存変更、undo 可否
- `undo_program_change` / `redo_program_change` - ロード中 program の直近トランザクションを取り消し・やり直し
- `export_program` - program を `.gzf` または生バイト列で書き出し（`--allowed-export-root` で制限可）

#### Function Analysis

- `list_functions` - 関数一覧（サイズと thunk フラグ付き）。`filter` で名前を絞り、`only_default_names=true` で未命名の `FUN_` 関数だけを取得
- `list_namespaces` - 名前空間一覧を `{name, is_class}` で取得（ページング対応）。`classes_only=true` でクラスのみ
- `decompile_function` - 関数名またはアドレス指定で C 擬似コードを取得（両方指定時は `address` 優先）
- `disassemble_function` - 関数の逆アセンブル結果を取得
- `disassemble_range` - アドレス範囲の逆アセンブル結果を取得
- `get_function` - 関数名またはアドレス指定でシグネチャ、引数、ローカル変数、本体範囲、thunk 先、名前空間を取得（両方指定時は `address` 優先）
- `create_function` - アドレスに関数を作成
- `delete_function` - アドレス指定で関数を削除
- `analyze_program` - 未解析扱いの program に解析を実行。`force=true` で再実行
- `get_function_xrefs` - 関数（アドレスまたは名前）の呼び出し元を、呼び出し元関数名付きで取得
- `get_callee` - 指定アドレスの関数から呼び出す関数を `{name, entry, is_external}` で取得

#### Memory & Data

- `list_segments` - メモリセグメント/レイアウト情報を取得
- `list_imports` - インポートシンボル一覧（ライブラリ名とアドレス付き）
- `list_exports` - エクスポートシンボル一覧（アドレス付き）
- `list_data_items` - データアイテム一覧（ラベル、長さ、値付き）
- `list_strings` - 文字列一覧（大文字小文字を区別しない `filter`）
- `get_xrefs_to` - 指定アドレスへのクロスリファレンスを参照元関数名付きで取得
- `get_xrefs_from` - 指定アドレスからのクロスリファレンスを参照先関数名付きで取得
- `get_data_by_label` - ラベル名からデータを取得
- `get_bytes` - 指定アドレスのバイト列を取得
- `search_bytes` - バイトパターン検索（`??` はワイルドカード）

#### Symbol & Comment Editing

- `rename_function` - 関数名またはアドレス指定で関数名を変更（両方指定時は `address` 優先）
- `rename_variable` - ローカル変数名/引数名を変更（関数は `function_address` または `function_name` で指定）
- `rename_data` - データラベル名を変更
- `set_function_prototype` - 関数プロトタイプを設定（関数は `function_address` または `function_name` で指定）
- `set_local_variable_type` - ローカル変数/引数の型を設定（関数は `function_address` または `function_name` で指定）
- `set_global_data_type` - グローバルデータの型を設定（`clear_mode` 指定可）
- `set_bytes` - メモリ内容をバイト列で書き換え
- `set_comment` - `pre`（デコンパイラ）、`eol`（リスティング）、`post`、`plate`（関数ヘッダ）、`repeatable` のコメントを設定
- `get_comments` - アドレスの全コメント種別を読み出し
- `search_symbols` - 全シンボルを名前で検索（glob 可、種別で絞り込み可）
- `create_label` - シンボルのないアドレスにラベルを作成
- `add_bookmark` - ブックマークを追加
- `list_bookmarks` - ブックマーク一覧を取得
- `delete_bookmark` - ID または address/type/category 指定でブックマークを削除

`rename_function` などの更新系 tool を使った後は、`save_project_program(target="default")` を呼ぶと変更が Ghidra project に保存されます。Ghidra GUI 側で同じ program を開いている場合、保存後の状態を見るには GUI 側で再オープンまたはリロードしてください。

#### Data Type Operations

- `create_struct` - 構造体を作成
- `add_struct_members` - 構造体メンバーを追加
- `remove_struct_members` - 構造体メンバーを選択削除。`members` 省略で全削除
- `delete_data_type` - データ型（struct、union、enum、typedef など）を削除
- `get_struct` - 構造体定義を取得
- `list_data_types` - program 内のデータ型一覧を取得
- `rename_data_type` - データ型名を変更
- `get_enum` - 列挙体定義を取得
- `create_enum` / `set_enum_values` - 列挙体の作成と値の追加・置換・削除
- `parse_c_declarations` - C の struct、union、enum、typedef、プロトタイプを program のデータ型として取り込み

#### Shared Project Sync（`shared_sync` category）

`get_project_sync_status` / `get_version_history` / `get_version_diff` / `checkout` / `add_to_version_control` / `commit` / `pull` / `undo_checkout` / `terminate_checkout` / `delete_shared_project_file` は記載のある箇所で `domain_path` を指定できます（未指定時は現在ロード中のprogram。削除は明示的な `domain_path` が必須）。

- `get_project_sync_status` - shared project 上の同期状態を取得
- `get_version_history` - バージョン履歴（version/user/comment/time）を取得
- `get_version_diff` - 2バージョン間の差分要約（件数/タイプ別/アドレスレンジ）を取得。`include_details=true` でレンジごとの Ghidra Diff 説明文も返す
- `checkout_project_program` - プログラムを checkout。`exclusive` 省略時は `--shared-sync-exclusive-checkout` の設定に従う
- `add_project_program_to_version_control` - private プログラムを shared 管理へ追加
- `commit_project_program` - checkout 中の変更を check-in。古い checkout と競合した場合、`on_conflict="keep"` でローカル編集を `.keep` コピーに退避して最新へ追従、`on_conflict="discard"` で破棄
- `pull_project_program` - 最新状態を取得（必要に応じて破棄/追従）
- `undo_checkout_project_program` - checkout を取り消し（ローカル変更破棄可）
- `terminate_project_program_checkout` - 既存 checkout を checkout ID で強制終了
- `delete_shared_project_file` - `confirm` が `domain_path` と一致した未ロードファイルを削除（versioned file は `expected_latest_version` と明示的な `allow_non_atomic_versioned_delete=true` も必須）

#### BSim（`bsim` category）

Ghidra BSim データベース（`--bsim-url` または呼び出しごとの `bsim_url`）に対する関数類似検索です。DB の構築は [docs/bsim-postgresql-macos.md](docs/bsim-postgresql-macos.md) を参照してください。

- `get_bsim_database_status` - DB メタデータ、実行ファイル数、設定済みカテゴリと関数タグ
- `bsim_add_executable_category` - 実行ファイルのメタデータカテゴリを追加
- `list_bsim_executables` / `get_bsim_executable` - 実行ファイル record の一覧・取得
- `bsim_update_executable_metadata` - 既存 record のカテゴリを変更
- `bsim_register_target` - ロード中 program のシグネチャを生成して登録（`categories` 指定可）
- `bsim_update_target_signatures` - ロード中 program の現在の関数名を既存 record に書き戻す
- `bsim_delete_executable` - 実行ファイルとその関数 record を削除（`confirm` に md5 または名前を再入力）
- `bsim_query_target` / `bsim_query_function` - program 全体、または関数リストに対する類似関数検索。自己一致は既定で除外
- `bsim_apply_matches` - 既定名のままの関数を最良一致の名前で一括リネーム（`dry_run` 可）
- `bsim_load_matched_executable` - 一致した実行ファイルを新しいターゲットとして開く。`ghidra://` の一致には `--bsim-remote-cache-dir` が必要

#### Large Result Retrieval

`--large-result-mode resource`（デフォルト）のときに登録されます。

- `read_result` - 保存済み大型結果のスライスを読む（`offset_chars` / `limit_chars` で `has_more` が false になるまでページング。`limit_chars` のデフォルトは圧縮閾値の 1/3）
- `search_result` - 保存済み大型結果を正規表現で検索。最大100件のスニペット、片側最大2,000文字の前後コンテキスト、`read_result` の offset にそのまま使えるマッチ位置を返す。`max_matches=0` では最大10,000件までスニペットなしで数えるため、`match_count` を全件数として扱う前に `scan_truncated` を確認

詳細な運用フローや制約事項は [利用ガイド](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.ja.md) を参照してください。

### ツール公開制御

各ツールには次の 3 種類のタグがあります。

- `category`: `core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`, `shared_sync`, `bsim`
- `safety`: `read_only`, `write`, `destructive_write`
- `operation_level`: `basic`, `standard`, `advanced`

プロファイル:

- `default`: 既存互換。`core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`
- `readonly`: `default` の category + `read_only` のみ
- `full`: 全 category を公開。`shared_sync` と `bsim` も含む

評価ルール:

- ツール制御引数を何も付けない場合は `--tool-profile default` と同じ
- `shared_sync` は通常の `category` として扱う
- 既定では `shared_sync` と `bsim` を含まない。`--add-category shared_sync` / `--add-category bsim` で追加する。BSim ツールは加えて `--bsim-url` か呼び出しごとの `bsim_url` が必要
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

### 大型結果の圧縮

ローカル LLM はコンテキストが伸びるほど減速し、その主因はデコンパイル結果や長大な一覧といった大型のツール出力です。エージェントのコンテキストを小さく保つため、閾値を超え、かつ圧縮後の応答の方が小さくなるツール結果を次の形に置き換えます。

- プレビューと、続きを取得する具体的な手順 — テキスト結果は冒頭部分（行境界で切断）を表示します。リスト・dict 結果は、完全なアイテム/エントリが 1 つ以上プレビュー予算に収まる場合に限り、先頭の完全なアイテム/エントリを有効な JSON として表示します。1 つも収まらない場合は payload の生の先頭部分にフォールバックするため、プレビュー自体は有効な JSON とは限りません
- `result_id` と MCP resource link（`ghidra://results/{result_id}`）
- `structuredContent` のメタデータ（`size_chars`、`mime_type`、`result_type`、`item_count` など）

設定したキャッシュに収まる場合、全文はサーバ内のインメモリ LRU ストアに保持され、次の 3 通りでアクセスできます。

- `read_result(result_id, offset_chars, limit_chars)` - ページング読み取り。tools のみ対応の MCP クライアントでも動作
- `search_result(result_id, pattern, context_chars, max_matches)` - 正規表現検索。最大100件のスニペットと片側最大2,000文字のコンテキストを返し、offset はそのまま `read_result` に渡せます
- `ghidra://results/{result_id}` への `resources/read` - MCP resource 対応クライアント向け

閾値以下の結果・エラー結果・空リスト結果は従来どおりそのまま返します。閾値を超えていても、完全なプレビュー/resource 応答の方がシリアライズ後のインライン応答より小さくならない場合は、インラインのままです。結果エントリ（UTF-8 payload と保持するメタデータ）がキャッシュ全体の byte 予算に収まらない場合も、ツールの実行自体は成功扱いですが、後から取得できるようキャッシュへ保持することはできません。通知の方がインライン応答より小さい場合、サーバは元の payload を含めず、結果を取得できないことを示すコンパクトな `RESULT_TOO_LARGE` notice を返します。通知の方が小さくなければ、全文を含むより小さいインライン結果を維持します。この notice を理由に副作用のあるツールを自動再実行しないでください。安全に再実行できる呼び出しでは、クエリを絞るか byte 予算を増やした上で明示的に再実行してください。同一内容の保存済み結果はコンテンツアドレスで同じ `result_id` を再利用するため、エージェントが同じ呼び出しを繰り返してもストアは膨張しません。

フラグ:

- `--large-result-mode {resource,inline}`（デフォルト `resource`）: `resource` は、完全な応答が小さくなる場合に限り対象の大型結果を条件付きで圧縮します。`inline` は常に全 payload を返します。
- `--large-result-threshold-chars N`（デフォルト `12000`）: この文字数の閾値を超える成功結果を圧縮候補にします。
- `--large-result-preview-chars N`（デフォルト `4000`）: プレビューの初期上限。テキスト結果は最大で全額、JSON リスト・dict 結果は最大で 1/4（数件の完全なアイテム/エントリでスキーマが伝わるため）、`CallToolResult` 全体ダンプは最大で 1/2 を使います。JSON エスケープや応答メタデータによって完全な応答予算を超える場合は、さらにプレビューを縮小します。完全なリストアイテム/dict エントリが 1 つも収まらない場合は生の先頭部分を使うため、有効な JSON とは限りません。
- `--result-cache-max-entries N`（デフォルト `512`）/ `--result-cache-max-bytes N`（デフォルト `134217728`）: LRU ストアの予算。byte 予算は UTF-8 payload と保持するメタデータの合計を計上します。破棄済み `result_id` を読むと、元のツールには副作用があった可能性があるため自動再実行せず、安全または冪等と分かる場合だけ再生成するよう案内します。結果エントリが byte 上限を超える場合は保存せず、通知の方が小さい場合だけ全文を含まない成功扱いの `RESULT_TOO_LARGE` result-unavailable notice を返します。そうでなければインライン結果を維持します。副作用のある呼び出しを自動再試行しないでください。
- `--tool-description-mode {full,short,none}`（デフォルト `full`）: `tools/list` の説明文の詳細度。`short` は spec の `short_description` を優先し、なければ先頭文にフォールバックします。各ツールの完全なドキュメントは MCP resource（`ghidra://docs/tools` と `ghidra://docs/tools/{tool_name}`）からいつでも取得できます。

## セキュリティと同時実行に関するフラグ

- `--allowed-import-root DIR`（複数指定可）: `import_program` はこのディレクトリ配下のファイルだけを受け付けます。判定前にシンボリックリンクを解決するため、ルート内のリンク経由で外へ出ることはできません。未指定の場合、サーバープロセスが読める任意のファイルを import し、`get_bytes` や `list_strings` で読み出せてしまいます。
- `--allowed-project-root DIR`（複数指定可）: `create_project`、`create_session`、`register_target` はこのディレクトリ配下のプロジェクト位置だけを受け付けます。
- どちらもローカルの stdio 利用では省略できます。`--transport http` または `sse` で両方とも未指定の場合、起動時に警告を出します。ネットワークに公開する構成では必ず両方を設定してください。
- `--lock-timeout-seconds N`（デフォルト `30`）: ツール呼び出しはワーカースレッドで実行されるため、同じターゲットに対する並列呼び出しは実行中の呼び出しの後ろで待ちます。この秒数を超えて待った呼び出しは、無期限に止まるのではなく再試行可能な `LOCK_TIMEOUT` エラーを返します。
- `--shared-sync-exclusive-checkout`: `exclusive` を明示しない `checkout_project_program`（および `commit_project_program` の自動 checkout）を排他 checkout にします。headless の Ghidra は merge できないため、`keep`/`discard` の判断を迫られる競合を未然に防げます。人と同じ program をエージェントが編集する運用では有効化を推奨します。
- `--allowed-export-root DIR`（複数指定可）: `export_program` の出力先をこの配下に制限します。未指定ならサーバープロセスが書ける場所ならどこにでも書き出せます。
- `--bsim-remote-cache-dir DIR`: Ghidra Server 上にある一致を `bsim_load_matched_executable` で開けるようにします。リポジトリごとにローカルキャッシュ project をこのディレクトリ配下に作成します。project ルートを制限している場合は `--allowed-project-root` 配下である必要があります。

## 動作上の注意

- `load_project_program` と `close_session` は、直前にロードしていたプログラムに未保存の変更があれば保存します。保存のタイミングを明示したい場合は `save_project_program` を呼んでください。
- `load_project_program(version=N)` は shared project の過去バージョンを読み取り専用でターゲットに開きます。参照系ツールは使えますが、更新系ツールは `READ_ONLY_PROGRAM` で失敗し、同期ツールはこのセッションを対象にしません。`version` を省略して再ロードすると現在のファイルに戻ります。
- `rename_variable` と `set_local_variable_type` は自動解析を勝手に開始しません。未解析のプログラムに対しては `PROGRAM_NOT_ANALYZED` で失敗するので、先に `analyze_program` を実行してください。
- ツールの失敗はすべて MCP のツールエラーとして返り、本文は `CHECKOUT_REQUIRED:` や `PATH_NOT_ALLOWED:` のような安定したコードで始まります。同じコードは `ghidra://docs/tools/{tool_name}` でも確認できます。
- `stdio` トランスポートでは、起動後に JVM の `System.out` を stderr へ振り向け、Ghidra のコンソール出力が JSON-RPC ストリームを壊さないようにしています。コンテナ内では `--transport http` の利用を推奨します。
- 共有プロジェクトでは、変更系コマンドの前に行うリポジトリ接続確認の成功結果を 2 秒間再利用します。連続した編集のたびにサーバー往復が発生することを避けるためで、バージョンやチェックアウト状態は毎回サーバーから読み直します。
- `remove_struct_members` の `members` はメンバー名の配列と `{"name": ...}` オブジェクトの配列のどちらも受け付けます（`create_struct` / `add_struct_members` と同じ形です）。

## アップグレード

- 新規ツール: `get_program_info`、`undo_program_change` / `redo_program_change`、`export_program`（`--allowed-export-root` 付き）、`get_comments`、`search_symbols`、`create_label`、`create_enum` / `set_enum_values`、`parse_c_declarations`。
- core 系の 7 ツールを近隣ツールに統合しました。`search_functions_by_name` → `list_functions(filter=...)`、`list_classes` → `list_namespaces(classes_only=true)`、`reanalyze_program` → `analyze_program(force=true)`、`set_decompiler_comment` / `set_disassembly_comment` → `set_comment(kind="pre"|"eol")`、`clear_struct` → `members` 省略の `remove_struct_members`、`delete_struct` → `delete_data_type`。`get_function` はシグネチャ、引数、ローカル変数を返すようになり、`list_imports`、`list_exports`、`list_namespaces`、`get_callee` は文字列ではなくオブジェクトを返します。`get_xrefs_to` / `get_xrefs_from` は相手側の関数名を含み、`rename_variable`、`set_function_prototype`、`set_local_variable_type` は `function_address` と `function_name` のどちらでも関数を指定でき、`search_bytes` は `??` ワイルドカードを受け付け、`list_strings.filter` は大文字小文字を区別しません。
- 3 つのツールを削除しました。`reload_project_program`（ターゲットが保持している `domain_path` を `load_project_program` に渡すと再ロードされ、応答に `reloaded=true` が付きます）、`list_bsim_categories`（`get_bsim_database_status` が `categories` と `function_tags` を返します）、`bsim_set_target_metadata`（`bsim_register_target` の `categories` に渡します）。新規ツールは `bsim_apply_matches`、`bsim_update_target_signatures`、`bsim_delete_executable` です。`checkout_project_program.exclusive` の既定は `false` からサーバー設定（`--shared-sync-exclusive-checkout`）に変わり、`commit_project_program.on_conflict` に `keep` が追加され、`get_version_diff` に `include_details` が付き、`bsim_query_target` は `exclude_self=false` を指定しない限り自身の record への一致を除外します。
- 0.1.4 では `mcp` 2.x SDK（`mcp>=2.1.1,<3`）へ移行しました。ツール呼び出しはサーバーのイベントループを止めずにワーカースレッドで実行されます。SDK の公開 API（`MCPServer`、`Tool`）だけを使うようにしたため、今後の SDK 更新は CI の `latest-mcp-sdk` ジョブと Dependabot で追従できます。
- `pull_project_program` の出力スキーマに、ランタイムが常に返していた `checked_out` を追加しました。修正前はサーバー側で pull が完了した後に出力検証で失敗していました。既に登録済みのプログラムを再登録すると `BSIM_ALREADY_REGISTERED` を返し、他ユーザーの排他チェックアウトで拒否されたチェックアウトは汎用の `SYNC_OPERATION_FAILED` ではなく `CHECKOUT_UNAVAILABLE` を返します。
- `add_bookmark` の未使用パラメータ `format` を削除しました。`on_conflict`、`on_local_changes`、`clear_mode` はスキーマ上で列挙型になり、`get_bytes.size` や BSim の閾値などの数値上限もスキーマに載るようになりました。

## ライセンス

このプロジェクトは Apache License, Version 2.0 の下で公開されています。詳細は同梱の
[LICENSE](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/LICENSE) ファイルを参照してください。
