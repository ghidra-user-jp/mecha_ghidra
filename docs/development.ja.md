[English](development.md) | [日本語](development.ja.md)

# 開発ガイド

## 開発・テスト

- 依存関係の更新: `uv add <package>` / `uv remove <package>`
- コード整形・型チェックなど必要に応じてツールを追加し、`uv run <tool>` で実行してください。
- テスト実行: まず `uv sync --extra test` でテスト依存（`pytest`, `pytest-mock`）をインストールし、`uv run pytest` でユニットテストを実行できます。

## Linux ARM64 decompiler 配布物のビルド

- `./scripts/build_linux_arm64_decompiler.sh` を実行すると、`linux_arm_64` 向け decompiler overlay と patched Ghidra 配布物を生成できます。
- Apple Silicon macOS のような Linux ARM64 以外のホストでは、このスクリプトは自動で `linux/arm64` Docker コンテナにフォールバックします。
- 既定の出力先は次のとおりです。
  - `dist/ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_linux_arm_64_decompiler.zip`
  - 対応する `.sha256`
- GitHub Actions の `.github/workflows/release-linux-arm64-decompiler.yml` では同じ build を `ubuntu-24.04-arm` 上で実行し、workflow artifact と release asset の両方に publish します。
