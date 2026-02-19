# 開発ガイド

## 開発・テスト

- 依存関係の更新: `uv add <package>` / `uv remove <package>`
- コード整形・型チェックなど必要に応じてツールを追加し、`uv run <tool>` で実行してください。
- テスト実行: まず `uv sync --extra test` でテスト依存（`pytest`, `pytest-mock`）をインストールし、`uv run pytest` でユニットテストを実行できます。
