[English](development.md) | [日本語](development.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# 開発

開発環境、実行時に守る制約、リリース手順をまとめています。サーバーを利用する場合は[はじめに](usage.ja.md)から進んでください。

## 環境構築と検証

```bash
uv sync --extra dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest
```

`dev` extraにはテスト依存、Ruff、パッケージング用ツールが含まれます。テストだけなら `uv sync --extra test` を使えます。依存の追加・削除には `uv add`／`uv remove` を使い、lockfileの変更も含めて管理してください。Ruffの設定は[pyproject.toml](../pyproject.toml)にあり、不要な抑制コメントは `RUF100` になります。

通常のテストはJVMをフェイクに置き換えます。通過しても実際のGhidraの動作を確認したことにはなりません。スレッド、接続方式、JVM起動、プロジェクト所有権、デコンパイラ、共有操作に関わる変更では、下記の実機検証を選んで実行してください。

## コードの構成

| 領域 | 役割 |
| --- | --- |
| [`ghidra_mcp/presentation`](../src/ghidra_mcp/presentation) | CLI、接続方式、MCPツール登録、結果の提示 |
| [`ghidra_mcp/application`](../src/ghidra_mcp/application) | ユースケース、パス・ロック制御、実行環境との接続インターフェース |
| [`ghidra_mcp/contracts`](../src/ghidra_mcp/contracts)、[`domain`](../src/ghidra_mcp/domain) | ツールスキーマ、値オブジェクト、エラー |
| [`ghidra_mcp/infrastructure`](../src/ghidra_mcp/infrastructure) | Ghidraアダプターと実行環境の統合 |
| [`ghidra_headless`](../src/ghidra_headless) | JVM起動、プロジェクト・セッションの所有、Ghidraコマンド |
| [`tests`](../tests) | 単体、スキーマ、構成、明示的に有効化する実機テスト |

CLI はサーバーの状態をモジュールスコープに持ちません。`main()` が `CLIApplication`（ランタイムバンドルと、そのレジストリに束縛したツール関数。`presentation/cli.py` の `build_application`/`bind_tools`）を1つ組み立てて引き渡し、テストは `tests/cli_support.py` 経由で自前のものを作ります。モジュールレベルの可変状態は ruff（`PLW0603`）が拒否します。JVMクラスの遅延取得には `functools.cache` を、リセットが必要なプロセス全体の状態には明示的なホルダーオブジェクト（`ghidra_headless/scripts/providers.py` を参照）を使ってください。各パッケージの `__init__` は再エクスポートを遅延解決します（`ghidra_mcp/_lazy.py`）。そのため `ghidra_mcp.contracts` のような葉の層をimportしても、CLI・MCP SDK・JVMブリッジは読み込まれません。`test_layering.py` はこれを別プロセスで検査します。[`test_layering.py`](../tests/test_layering.py)が依存方向を検査します。presentationはapplicationを使い、applicationはinfrastructureが実装する接続インターフェースを定義し、infrastructureは `ghidra_headless` を使います。`domain` と `contracts` は上位層をimportせず、`ghidra_headless` は `ghidra_mcp` をimportしません。唯一の例外が[`ghidra_headless/contracts`](../src/ghidra_headless/contracts)です。コアが強制するJVM非依存の規則（現在は `batch_read` のリクエスト規則）を置く場所で、`ghidra_mcp/contracts` がここをimportすることでスキーマとコアが同じコードで検証します。レイヤリングテストは、このパッケージのimportで `jpype`/`pyghidra`/`ghidra` が読み込まれないことも検査します。applicationが必要とする新しい機能は[ports.py](../src/ghidra_mcp/application/services/ports.py)へ追加します。

ツール定義は[tool_spec.py](../src/ghidra_mcp/contracts/tool_spec.py)にあります。ハンドラで新しい `params.get(...)` キーを読む場合は、スキーマと `COMMAND_DEP_KEYS` を更新してください。[test_spec_handler_parameters.py](../tests/test_spec_handler_parameters.py)が対応関係を検査します。

大きな結果の処理は `result_store.py`（LRU）、`result_compaction.py`（プレビュー・応答の判断）、`result_tools.py`（取得・検索）に分かれ、`result_resources.py` が窓口です。共有同期は `infrastructure/ghidra_adapter/runtime/sync_operations.py` と、`sync_locking`、`sync_identity`、`sync_postconditions`、`sync_active_program`、`sync_reopen` の各mixinで構成します。

## 実行時のルール

### JVMの起動

JVMは `ghidra_headless.launcher.start_headless_jvm()` だけを経由して起動し、`pyghidra.start()` を直接呼ばないでください。起動前に `-Djava.awt.headless=true` を設定し、非headlessのJVMが起動済みなら `JVM_NOT_HEADLESS` で拒否します。

macOSでは特に重要です。MCP 2.xはワーカースレッドでハンドラを実行するため、そこで初めてAWTを初期化するとAppKitのメインスレッドを待ち続ける場合があります。JVM起動後のheadless設定では間に合いません。表示に依存する操作は `HEADLESS_UNSUPPORTED` で失敗させます。

### プログラム・トランザクション・リソース

プログラムは `DomainFile.getDomainObject(project, ...)` で開き、`Program.release(project)` で解放します。`GhidraProject.openProgram` に置き換えないでください。永続するバッチトランザクションによって `isChanged()` が見えなくなり、undoが使えず、`.gzf` のエクスポートも妨げられます。

変更ごとにトランザクションが必要です。ハンドラは `core_helpers._txn`、セッション・実行環境側は `ghidra_headless.session.transactions.run_in_transaction` を使います。インポートしたプログラムは直後に閉じるため、GhidraProjectを使えます。コンテキストを交換するときは古いデコンパイラを解放し、交換に失敗したときは利用可能な既存コンテキストを保持します。

共有コマンドでは、成功したリポジトリ接続確認を2秒間再利用します。バージョンとチェックアウト状態は毎回取得します。同期処理を変更するときも、この区別を維持してください。

### MCP SDK

対応範囲は `mcp>=2.2.0,<3` です。公式の低レベル `Server` に `on_list_tools`、`on_call_tool`、リソース用ハンドラーを登録し、`mcp.types.Tool` で入出力スキーマを明示します。SDKの関数メタデータは上書きしません。入力はPydanticのstrictモデル、送信する `structuredContent` はJSON Schemaで検証します。同期処理はワーカースレッドへ渡します。HTTPは `Server.streamable_http_app(stateless_http=True, json_response=True, ...)`、stdioは `stdio_server()` と `Server.run()` を使います。CIの `latest-mcp-sdk` が範囲内の最新版を検証し、Dependabotが `mcp`／`mcp-types` の更新をまとめます。

Javaクラスは `jpype.JClass`、スレッドIDは `Thread.threadId()` を使います。raw importのオプションは読み取り専用の `FileByteProvider` と `BinaryLoader` の公開APIで取得します。`ProgramLoader` の非公開メソッドへのリフレクションや、非推奨の `RandomAccessByteProvider` は使いません。Ghidraの `HexLong` オプションは接頭辞がなくても16進数として解釈するため、整数のファイルオフセットと長さは `hex()` で渡します。

### PyGhidraの依存バージョンとスクリプト失敗

PyGhidraは上流コミット [`263160cf57db21a9e25f1e0a8bc42fde5b8824eb`](https://github.com/NationalSecurityAgency/ghidra/commit/263160cf57db21a9e25f1e0a8bc42fde5b8824eb) に固定しています。パッケージのバージョン表記は3.2.0ですが、**未リリースのスナップショット**です。2026-09-20時点でPyPIの最新版は3.1.0で、スクリプトの例外を握りつぶします（[上流Issue](https://github.com/NationalSecurityAgency/ghidra/issues/9288)）。このスナップショットでは例外が伝播するため、非公開runnerへのローカルパッチを撤去しました。この固定は `pyproject.toml` の `[tool.uv.sources]` にあり、`uv sync`/`uv run`（およびDockerイメージ）に適用され、`uv.lock` にSHA-256を記録します。公開メタデータ側は `pyghidra>=3.1.0` のみを要求するため、PyPIからのインストールと公開は可能です。修正を含まないPyPI版PyGhidraでは起動時プローブが全スクリプトランタイムを利用不可（`SCRIPT_RUNTIME_UNAVAILABLE`）にし、他のツールは動作します。初回の `uv sync` ではGhidraのソースアーカイブを取得します。修正を含むリリースが出たら、sourcesのエントリ削除と下限バージョンの引き上げを同じコミットで行ってください（スナップショットも3.2.0を名乗るため）。

PyPI公開はリリース対象外です。リポジトリとリリース添付物での配布には、この検証済みコミット固定を維持します。PyGhidraの正式版を待つことはv1.0の公開条件に含めません。依存を更新するときはlockfileを更新し、以下の実機・パッケージ検証を再実行してください。ローカルwheelとリポジトリからのインストールは、この依存で検証済みです。

起動時に標準providerで例外伝播を検証します。失敗した場合は、子スクリプト経由の実行も防ぐためJava・Jython・PyGhidraの全言語を使用不可にし、通常の解析ツールは利用可能に保ちます。各スクリプト実行入口でもトランザクション開始前に検証状態を確認します。Jythonが導入済みなら、全言語の実行に `GhidraState` 経由で共有interpreterを渡し、子Jythonの例外と出力を呼び出し元へ返します。`runScript()` はサブディレクトリのファイルや実行中に登録したソースも呼び出せるため、カタログ直下の `.py` の有無で共有を省略しません。上流runnerの差し替えや非公開loaderメソッドへのアクセスは行いません。

コメントの読み書きには `ghidra.program.model.listing.CommentType` と、それを受け取る公開APIを使用します。削除予定の整数定数・整数引数のオーバーロードは使用しません。`ScriptBarrier` は一つの `Condition` 内で待機と所有状態の更新を行い、待機後に期限のない別のロック取得を挟みません。

[2026-09-20の検証記録](release-fixes-validation-20260920.ja.md)には、raw importのバイト範囲、親子全9通りの言語の組み合わせ、ロールバック、プロセス状態の復元、stdio／HTTPの結果を記録しています。

## 実機検証

対応するJDKと実際のGhidraインストール先を設定します。ローカルコマンドとリソース管理を検証する例です。

```bash
GHIDRA_RUNTIME_VALIDATION=1 \
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra \
GHIDRA_RUNTIME_BINARY_PATH=/bin/ls \
uv run pytest \
  tests/test_runtime_readonly_commands.py \
  tests/test_runtime_mutating_commands.py \
  tests/test_runtime_resource_safety.py
```

`/bin/ls` はmacOS/Linuxの例です。ほかの環境では適切なバイナリを指定してください。変更系の検証にはテスト専用のプロジェクトを使います。起動中のMCPサーバーやGUIと同じローカルプロジェクトを開かないでください。

`tests/test_runtime_mcp_transport.py` は同じ実機フラグで、実際のCLIを別プロセスとして起動し、stdioとlocalhostのStreamable HTTPを検証します。専用プロジェクトと小さなraw binaryを自動生成するため、`GHIDRA_RUNTIME_BINARY_PATH` は不要です。入出力スキーマ、変更とロールバック、大きな結果の取得に加え、HTTPの初期化なしの呼び出し・セッションIDなしの応答・別接続からのリソース取得を確認します。

Jythonまで検証する場合は、使用するGhidraと同じバージョンのJython拡張を導入し、`GHIDRA_RUNTIME_VALIDATION=1`に加えて`GHIDRA_JYTHON_RUNTIME_VALIDATION=1`を指定して、`tests/test_runtime_script_commands.py`と`tests/test_runtime_mcp_transport.py`を実行します。この追加フラグではJythonが未導入なら失敗にし、MCPのstdio／HTTPにもJythonのケースを追加します。通常のGhidra設定から分離する場合は、Javaの`-Dapplication.settingsdir=...`で専用の設定領域を使い、その領域のGhidra拡張ディレクトリへインストールします。

推奨APIへの移行後の実測結果は[2026-09-16の実機検証記録](recommended-api-runtime-validation-20260916.ja.md)にまとめています。

| 検証対象 | 追加で設定する環境変数 |
| --- | --- |
| 共有プロジェクト同期 | `GHIDRA_RUNTIME_SHARED_PROJECT_LOCATION`、`GHIDRA_RUNTIME_SHARED_PROJECT_NAME`、`GHIDRA_RUNTIME_SHARED_DOMAIN_PATH`、`GHIDRA_RUNTIME_SHARED_SERVER_USER`（または `GHIDRA_SERVER_USER`）、`GHIDRA_SERVER_PASSWORD` |
| BSim | `GHIDRA_BSIM_RUNTIME_VALIDATION=1`、`GHIDRA_INSTALL_DIR`、`GHIDRA_BSIM_URL`、`GHIDRA_BSIM_PASSWORD` または `GHIDRA_BSIM_PASSWORD_ENV` |
| BSimの検索・読み込み・デコンパイル | 上記に加え `GHIDRA_BSIM_PROJECT_LOCATION`、`GHIDRA_BSIM_PROJECT_NAME`、`GHIDRA_BSIM_QUERY_DOMAIN_PATH`、`GHIDRA_BSIM_QUERY_FUNCTION` |
| Ghidra ServerにあるBSim一致元の読み込み | 上記に加え `GHIDRA_BSIM_REMOTE_CACHE_DIR`。パスワード認証では `GHIDRA_SERVER_USER` と `GHIDRA_SERVER_PASSWORD` の両方を設定 |

[validate_bsim_runtime.sh](../scripts/validate_bsim_runtime.sh)はBSim実機フラグを有効にし、パスワード変数がなければTTYで入力できます。同じリポジトリへ接続する場合も、キャッシュのローカル `.gpr/.rep` パスは分けてください。

共有側のcheckout、commit、別クライアントからの更新取得、試験ファイル削除は `tests/test_runtime_registry_shared_sync_commands.py` で検証します。BSimのカテゴリ・メタデータ変更には `GHIDRA_BSIM_MUTATION_VALIDATION=1` が必要です。カテゴリ定義は試験後も残るため、使い捨てのDBを指定してください。

<a id="native-builds"></a>

## ネイティブデコンパイラのビルド

| プラットフォーム | コマンド |
| --- | --- |
| Linux ARM64 | `./scripts/build_linux_arm64_decompiler.sh` |
| Apple Silicon macOS | `./scripts/build_decompiler_natives.sh --platform mac_arm_64` |
| Intel macOS | `./scripts/build_decompiler_natives.sh --platform mac_x86_64` |

Linux ARM64用スクリプトは、ほかのホストでは `linux/arm64` のDockerコンテナへ切り替えます。各ビルドは `dist/ghidra_*_<platform>_decompiler_overlay.tar.gz`、追加済みの `dist/ghidra_*_<platform>_decompiler.zip`、対応する `.sha256` を生成します。各プラットフォームに `decompile` と `sleigh` の両方が必要です。

[リリースワークフロー](../.github/workflows/release-decompiler-natives.yml)は、ネイティブのhosted runnerである `ubuntu-24.04-arm`、`macos-15`、`macos-15-intel` を使います。利用者向けの説明は[配布物の選び方](usage.ja.md#native-decompiler-artifacts)にまとめています。

## リリース手順

1. Pythonのテスト・パッケージ検証と、変更に関係する実機検証を行います。
2. タグ作成前に `release-decompiler-natives` を手動実行し、`mecha-ghidra-release-assets` artifactを検証します。
3. [ghidra_release.env](../scripts/ghidra_release.env)の `MECHA_GHIDRA_RELEASE_NATIVE_ASSET_RUN_ID` にrunを記録します。ネイティブファイルの内容を変えた場合は、検証済みassetのハッシュと[Dockerfile](../Dockerfile)の固定値をそろえます。
4. タグのビルドは検証済みのnative ZIPを再利用し、Pythonパッケージは最終タグから作り直します。公開したnative ZIPのハッシュが固定値と一致することを確認します。
5. 利用者向けの2つのZIP（Ghidra一式と追加ファイル）、Python source distributionの添付を確認します。PyPI公開はリリース対象外です。

手動実行はartifactをアップロードし、リリースは公開しません。既存タグの再実行はリリースノートを置き換えずassetを更新し、公開時に旧assetと単独の `.sha256` を削除します。リリースノートにはZIPの選び方と追加したプラットフォームのパスを記載します。バージョンやハッシュの既定値を複数の文書へコピーせず、正式なリリース設定へリンクしてください。

## ドキュメントの保守

READMEは目的・最初の利用・ページ案内に絞ります。操作手順は専用ガイド、正確な引数はツールスキーマで管理してください。英語と日本語を同時に更新し、参照されるアンカーを維持して、相対リンクとJSON/TOML例を検証します。日本語のBSim管理ガイドを直すときは、過去に検証したバージョンの記録を保持してください。
