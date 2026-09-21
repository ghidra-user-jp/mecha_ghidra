# コンテキスト圧縮の実装・検証結果

2026-09-14。提案したエラー参照化、プレビュー、取得・検索、JSON項目取得、ページ変換、直列化、メモリ管理、短いツール説明を作業ツリーへ実装した。

以下の測定とテスト件数は `batch_read` 追加前の記録です。追加後の仕様・上限は[読み取りのバッチ実行](tools.ja.md#batch-read)を参照してください。

## 比較結果

同じローカル環境・合成入力・インストール済みMCP SDKで比較した。文字数はCallToolResultをJSON化した文字数であり、モデルのトークン数ではない。時間はウォームアップ後9回の中央値。一時メモリは入力構築後にtracemallocを開始した処理中の追加ピークで、プロセスRSSではない。JVM・ネットワーク・LLM推論時間は性能表に含めない。

| 対象 | 変更前 | 変更後 | 削減 |
| --- | ---: | ---: | ---: |
| Script失敗の応答JSON | 351,779 文字 | 4,526 文字 | 98.7% |
| 10万文字の全文取得・追加呼び出し | 25 回 | 9 回 | 64.0% |
| 10万文字の全文取得・応答合計 | 114,242 文字 | 107,955 文字 | 5.5% |
| ページ付き1万件の圧縮＋SDK応答生成 | 23.93 ms | 10.97 ms | 54.2% |
| ページ付き1万件の一時メモリ | 2.692 MiB | 1.794 MiB | 33.4% |
| 近接する検索20一致の応答JSON | 12,718 文字 | 5,496 文字 | 56.8% |
| 100候補の検索応答調整 | 9.697 ms | 1.597 ms | 83.5% |
| 100候補の検索JSON化 | 100 回 | 18 回 | 82.0% |
| 4,000文字の取得時の応答JSON化 | 12 回 | 1 回 | 91.7% |
| 1,000行を100行ずつ読むときの行変換 | 5,509 回 | 1,000 回 | 81.8% |

近接する20一致の比較は、新しい `merge_context=true` を有効にした値。既定のfalseは従来の文脈形式を維持する。検索継続用メタデータの追加で、通常形式ではこの入力の1応答に19件が収まり、次のカーソルで残りを読める。統合形式では20件と元の文脈を保持する。

ページ付き1,000件の初回プレビューは、項目0件から9件表示へ変わった。初回JSONは943文字から2,095文字に増えるが、実データと次ページ情報が見える。合成プレビューは `preview_kind=summary`、生テキストの取得開始位置は `continue_offset_chars=0` と明示する。

新しい引数・説明の追加により、既定55ツールの定義JSONは36,519文字から37,865文字へ増えた。変更後のshort設定では34,093文字（full比約10%減）。短縮説明に必要な選択条件があることはテストしたが、LLMの選択精度は未測定。

全文取得の総量は改善しても、最初から全文を返した101,833文字より多い。必要な項目・フィールド・検索箇所だけ読む経路が文脈節約に有効。2万件のフラットリストの一時メモリは3.586→3.587MiBで実質同等だった。

## 実装と確認した条件

| 提案 | 実装 | 検証 |
| --- | --- | --- |
| 長い失敗診断の参照化 | `result_errors.py`、MCPエラー境界。小さいエラーとinline形式は維持 | SDK境界と実PyGhidraでisError、SCRIPT_FAILED、execution_state、transaction_outcomeを維持。変更がロールバックされ、2,000行の元診断を取得可能 |
| 項目を含むページプレビュー | `result_compaction.py`。先頭itemsと元のhas_more/next_cursor | 元itemsの先頭部分との一致、全文の保存、合成表示のraw offset=0 |
| 大きな既定取得・高速判定 | `result_tools.py`。まず全候補が収まるか1回判定 | Unicode・引用符・改行を含む全文の再構成と応答テキスト上限、25→9回 |
| 検索の候補調整 | 全候補確認後、件数を二分探索 | 最大100候補のJSON生成回数と時間、応答上限 |
| Unicode正規化の不要コピー削減 | ASCIIの早期判定、変更された枝だけコピー。特殊コンテナは一度だけ実体化 | サロゲート修復、順序、未変更枝の共有、SDKの状態を持つ変換への既存回帰テスト |
| 性能回帰テストの修正 | `_inline_result_wire_chars`の実装モジュールを差し替え | 全文wire直列化を避け、文字列を一度だけエンコードする検査 |
| 検索文脈の共有 | `merge_context=true`、contextsとcontext_index | 全一致の位置・文字列と各元contextを復元可能 |
| 検索の早期終了・継続 | `count_mode=none`、count_complete、next_cursor | ゼロ長一致、lookbehind、サイズ調整で省いた候補、結果・パターンの同一性。既定はbounded集計 |
| JSON項目・フィールド取得 | `result_json.py`、遅延する文字位置索引 | ルート配列と/items、Unicode、索引再利用、選択フィールド、単一項目超過時に飛ばさないこと |
| 変換をページ選択後へ移動 | xrefs/call edges/disassembleで表示変換を遅延 | 1,000行の変換回数と、変換中にrevisionが変わった場合の拒否 |
| disassembleのアドレス継続 | 次の未返却命令から開始。関数範囲をAddressSetで保持 | 実Ghidraで非連続bodyを維持し、前の命令を再変換しない。古いoffsetカーソルとクエリ・revision検査も維持 |
| JSON直列化の再利用 | JSON生成時のbytesからサイズ・hashを計算し、plain strだけ保持 | 再エンコードを避ける検査、辞書の不要な整形JSON生成を避ける検査、ピークメモリ比較 |
| メモリ予算 | `--result-cache-max-memory-bytes`。文字列・メタデータ・索引を計上 | ASCII主体＋絵文字の文字列、索引分の計上、LRU追い出し時の解放 |
| 短いツール説明 | 全77仕様の明示的short_description | 180文字以下、全仕様をカバー、run_script・disassemble・BSimなどの選択条件 |
| ドキュメント | 日英設定説明、成功短縮・エラー短縮の出力スキーマ | SDK実応答のJSON Schema検証 |

ブロック圧縮による保存形式の変更は、提案時から実メモリ圧迫が確認された場合の条件付き候補だったため導入していない。今回のメモリ予算は保持オブジェクトの計上であり、プロセス全体のRSS上限を保証しない。

## 検証コマンド

通常テスト: **1,266 passed / 33 skipped**。skipは実環境が必要なテストの実行条件によるもの。Ruffと差分の空白検査も成功。

```sh
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts/benchmark_compaction.py
git diff --check
```

Ghidra 12.1.2・独立したテストプロジェクトで、以下の実環境テスト **12件が成功**した。

```sh
GHIDRA_RUNTIME_VALIDATION=1 \
GHIDRA_INSTALL_DIR=/Users/samsepi0l/ghidra/ghidra_12.1.2_PUBLIC \
JAVA_TOOL_OPTIONS=-Duser.home=/private/tmp/mecha-compaction-validation/java-home \
.venv/bin/python -m pytest tests/test_runtime_tool_revision.py \
  tests/test_runtime_script_commands.py::test_runtime_large_script_failure_keeps_rollback_and_retrievable_diagnostics -q
```

## 性能測定の再実行

比較元はコミット `536c8010a4ae3868aa0ea0fb2d78ed6ccf80aff1` の表示処理・ページ処理。既存の作業ツリーにあったScriptツール契約は保持し、新しい明示的短縮説明だけ外した比較用ソースを一時ディレクトリに構築する。元の作業ツリーは変更しない。対象モジュールのSHA-256、Python/SDKバージョンと測定条件はJSONに記録した。

```sh
.venv/bin/python scripts/benchmark_compaction.py \
  --baseline-ref 536c8010a4ae3868aa0ea0fb2d78ed6ccf80aff1 \
  --output docs/compaction-benchmark-before.json
.venv/bin/python scripts/benchmark_compaction.py \
  --output docs/compaction-benchmark-after.json
```

[変更前の測定](compaction-benchmark-before.json) / [変更後の測定](compaction-benchmark-after.json) / [使い方](configuration.ja.md#large-results)
