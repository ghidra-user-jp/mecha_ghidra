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
  - ローカル検証用の対応する `.sha256`
- GitHub Actions の `.github/workflows/release-linux-arm64-decompiler.yml` では同じ build を `ubuntu-24.04-arm` 上で実行します。
- GitHub release へは、用途が分かりやすい user-facing asset 名で publish します。
  - `mecha_ghidra_docker_arm64_*.zip` / `*.tar.gz`: Apple Silicon / Linux ARM64 の Docker 関連成果物
- 通常のリポジトリ snapshot は、GitHub 標準の `Source code (zip)` / `Source code (tar.gz)` を使います。
- release page 本文にも、公開している各 asset の用途を英語で説明し、SHA-256 も直接表示します。そのため `.sha256` の release asset は publish せず、古い legacy checksum asset も publish 時に削除します。
