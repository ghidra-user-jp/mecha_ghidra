# batch_read の実装・検証

2026-09-14。[使い方・入出力・上限](tools.ja.md#batch-read)。

同一ターゲットの `get_function`、`get_comments`、`get_data_type`、`get_xrefs`、`get_call_edges` を1〜20件まとめて実行する。通常のツール定義から型を共有し、全件の入力と公開設定を確認してから既存コマンドを呼ぶ。処理は1回のターゲット／プロジェクトロック内で順次実行し、結果ID・成功／失敗／未実行件数・revisionの整合性を保つ。

実Ghidraでは5種類の個別実行とバッチ実行の結果が一致し、バッチのコア呼び出しが1回であることを確認した。処理中の編集を検出すると全体を拒否する。これは呼び出し数の検証であり、並列化・実LLMの所要時間やトークン削減率を測ったものではない。

出力量はバッチ全体の `content` と `structuredContent` を合わせたツール応答で制限する（SDKのサーバー情報とJSON-RPC外枠を除く）。項目の選択と大きい結果の参照化に対応し、全項目を1つの結果キャッシュへ保存する。SDKテストでは、Unicode、長いエラー、最小出力予算、キャッシュ拒否、複数項目の状態取得、公開JSON Schemaとの一致を確認した。

検証結果は **通常テスト1,307件成功・36件スキップ**、追加した **実Ghidraテスト3件成功**。通常テストのスキップは実環境を要する条件付きテストで、今回の3件も含む。Ruff、書式、`git diff --check`も成功。

```sh
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
git diff --check
```

実環境の検証はGhidra 12.1.2と独立した一時プロジェクトを使用した。

```sh
mkdir -p /private/tmp/mecha-batch-validation/java-home
GHIDRA_RUNTIME_VALIDATION=1 \
GHIDRA_INSTALL_DIR=/Users/samsepi0l/ghidra/ghidra_12.1.2_PUBLIC \
JAVA_TOOL_OPTIONS=-Duser.home=/private/tmp/mecha-batch-validation/java-home \
.venv/bin/python -m pytest tests/test_runtime_batch_read.py -q
```

稼働中のMCPサーバーは再起動していない。ツール一覧への反映には、更新したソースでのサーバー起動とクライアント側のツール一覧更新が必要。
