[English](development.md) | [日本語](development.ja.md)

# 開発ガイド

## 開発・テスト

- 依存関係の更新: `uv add <package>` / `uv remove <package>`
- コード整形・型チェックなど必要に応じてツールを追加し、`uv run <tool>` で実行してください。
- テスト実行: まず `uv sync --extra test` でテスト依存（`pytest`, `pytest-mock`）をインストールし、`uv run pytest` でユニットテストを実行できます。
- Ghidra 実機テストは `GHIDRA_RUNTIME_VALIDATION=1` を指定したときだけ実行されます。`GHIDRA_INSTALL_DIR` と `GHIDRA_RUNTIME_BINARY_PATH` を設定し、shared project sync まで検証する場合は `GHIDRA_RUNTIME_SHARED_PROJECT_LOCATION`、`GHIDRA_RUNTIME_SHARED_PROJECT_NAME`、`GHIDRA_RUNTIME_SHARED_DOMAIN_PATH`、`GHIDRA_RUNTIME_SHARED_SERVER_USER`（または `GHIDRA_SERVER_USER`）、`GHIDRA_SERVER_PASSWORD` も設定してください。
- BSim 実機テストは `GHIDRA_BSIM_RUNTIME_VALIDATION=1` を指定したときだけ実行されます。`GHIDRA_INSTALL_DIR`（Ghidra 12.1 検証対象）、`GHIDRA_BSIM_URL`、`GHIDRA_BSIM_PASSWORD` または `GHIDRA_BSIM_PASSWORD_ENV` を設定してください。query、matched executable load、decompile まで検証する場合は、さらに `GHIDRA_BSIM_PROJECT_LOCATION`、`GHIDRA_BSIM_PROJECT_NAME`、`GHIDRA_BSIM_QUERY_DOMAIN_PATH`、`GHIDRA_BSIM_QUERY_FUNCTION` を設定します。`./scripts/validate_bsim_runtime.sh` は実機テスト用 flag を設定し、password 系環境変数がない場合は TTY で BSim password を入力できます。
- 起動中の MCP サーバーが同じ Ghidra project を開いている場合は、実機テスト用に別のローカル project cache を用意してください。同じ shared repository を指していても、`.gpr` / `.rep` のローカルパスが別なら project lock の競合を避けられます。

## native decompiler 配布物のビルド

- `./scripts/build_linux_arm64_decompiler.sh` を実行すると、`linux_arm_64` 向け decompiler overlay と patched Ghidra 配布物を生成できます。
- Apple Silicon macOS のような Linux ARM64 以外のホストでは、このスクリプトは自動で `linux/arm64` Docker コンテナにフォールバックします。
- Apple Silicon macOS では `./scripts/build_decompiler_natives.sh --platform mac_arm_64` で `mac_arm_64` 向け overlay と patched Ghidra 配布物を生成できます。
- Intel macOS では `./scripts/build_decompiler_natives.sh --platform mac_x86_64` で `mac_x86_64` 向け overlay と patched Ghidra 配布物を生成できます。
- 既定の出力先は次のとおりです。
  - `dist/ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_linux_arm_64_decompiler.zip`
  - `dist/ghidra_*_mac_arm_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_mac_arm_64_decompiler.zip`
  - `dist/ghidra_*_mac_x86_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_mac_x86_64_decompiler.zip`
  - ローカル検証用の対応する `.sha256`
- GitHub Actions の `.github/workflows/release-decompiler-natives.yml` では、release 用 Linux ARM64 decompiler overlay を native hosted runner `ubuntu-24.04-arm` 上でビルドします。upstream 公式 Ghidra 12.1.2 ZIP には `mac_arm_64` と `mac_x86_64` の decompiler binaries が含まれています。
- version tag push では Python の test/package gate と native build の完了後に GitHub release asset を公開します。手動 workflow 実行では release 公開はせず、workflow artifact としてアップロードします。同じtagを再実行した場合は、既存release notesを置換せずassetだけを更新します。
- GitHub release へは、利用者向け ZIP asset を 2 つ publish します。
  - `ghidra_12.1.2_decompiler_natives_all.zip`: Linux ARM64 decompiler ファイルを追加済みの、そのまま使える Ghidra 12.1.2 配布物
  - `ghidra_decompiler_natives_all.zip`: 既存の Ghidra 12.1.2 install へ追加する Linux ARM64 decompiler ファイルだけの overlay ZIP
- release tagからtest済みの `ghidra_mcp` wheel と source distribution も同じGitHub releaseへ添付します。PyPIへの公開はrelease ownerが別途実施します。
- release overlay が追加する native decompiler path は次のとおりです。
  - `Ghidra/Features/Decompiler/os/linux_arm_64/decompile`
  - `Ghidra/Features/Decompiler/os/linux_arm_64/sleigh`
- 通常のリポジトリ snapshot は、GitHub 標準の `Source code (zip)` / `Source code (tar.gz)` を使います。
- release page 本文には、どちらの ZIP を使うかの説明と上記の追加パスを書きます。`.sha256` や古い legacy release asset は publish 時に削除します。
