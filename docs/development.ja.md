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

[`test_layering.py`](../tests/test_layering.py)が依存方向を検査します。presentationはapplicationを使い、applicationはinfrastructureが実装する接続インターフェースを定義し、infrastructureは `ghidra_headless` を使います。`domain` と `contracts` は上位層をimportせず、`ghidra_headless` は `ghidra_mcp` をimportしません。applicationが必要とする新しい機能は[ports.py](../src/ghidra_mcp/application/services/ports.py)へ追加します。

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

対応範囲は `mcp>=2.1.1,<3` です。`MCPServer`、`Tool.from_function`、`read_resource`、`run()` のキーワード引数など、公開APIを使います。CIの `latest-mcp-sdk` が範囲内の最新版を検証し、Dependabotが `mcp`／`mcp-types` の更新をまとめます。

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
5. 利用者向けの2つのZIP（Ghidra一式と追加ファイル）、Python source distributionの添付を確認します。PyPI公開はリリース担当者が別途行います。

手動実行はartifactをアップロードし、リリースは公開しません。既存タグの再実行はリリースノートを置き換えずassetを更新し、公開時に旧assetと単独の `.sha256` を削除します。リリースノートにはZIPの選び方と追加したプラットフォームのパスを記載します。バージョンやハッシュの既定値を複数の文書へコピーせず、正式なリリース設定へリンクしてください。

## ドキュメントの保守

READMEは目的・最初の利用・ページ案内に絞ります。操作手順は専用ガイド、正確な引数はツールスキーマで管理してください。英語と日本語を同時に更新し、参照されるアンカーを維持して、相対リンクとJSON/TOML例を検証します。日本語のBSim管理ガイドを直すときは、過去に検証したバージョンの記録を保持してください。
