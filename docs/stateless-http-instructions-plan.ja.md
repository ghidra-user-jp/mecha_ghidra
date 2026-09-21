# ステートレスHTTPとサーバー instructions

更新日: 2026-09-16

HTTPは公式Python SDKの推奨設定に固定し、公開ツールに合った検索案内を生成する。互換モードや切り替えオプションを設けない実装として、この作業ツリーに反映した。

## HTTPの実装

`src/ghidra_mcp/presentation/transport.py` から、SDKの `Server.streamable_http_app()` に以下を渡す。

```python
stateless_http=True
json_response=True
```

これは[公式Python SDKの推奨例](https://github.com/modelcontextprotocol/python-sdk/blob/main/examples/snippets/servers/streamable_config.py)と同じ設定である。`--transport http` と `--transport streamable-http` の両方に適用する。ステートフルに戻す独自設定・分岐は追加しない。

新仕様 `2026-07-28` では元々セッションを使わない。`stateless_http=True` により、SDKが受け付ける以前の仕様の要求でもセッションIDを発行しない。プロトコル処理は公式SDKに任せ、独自の互換層やバージョン判定は実装しない。[SDKの説明](https://py.sdk.modelcontextprotocol.io/run/deploy/)

HTTPは最終結果をJSONで返す。SSEによる進捗通知・keepaliveは使わないため、クライアントとプロキシには解析時間に合ったタイムアウトが必要になる。起動ログにステートレス・JSON応答を明記する。既存のHost/Origin検証は継続する。

Ghidraのターゲット、プログラムの変更状態、ロック、結果キャッシュはサーバー共通の状態として保持する。クライアントは同じ `target` と返された `result_id` を次のHTTP要求で指定する。キャッシュの既存の容量制限と追い出し規則は適用され、プロセス再起動でキャッシュは失われる。複数プロセス間の状態共有は行わない。

応答が失われた場合でも変更処理が完了している可能性がある。変更操作の自動再実行は導入しない。HTTP要求のキャンセルだけで、同期Ghidra処理の停止やロールバックまで保証するものではない。

stdioを維持し、旧HTTP+SSEは削除する。Streamable HTTPのステートフル互換設定は設けない。

## instructionsの実装

新規 `src/ghidra_mcp/presentation/server_instructions.py` の `build_server_instructions()` に、公開フィルター適用後の `ToolSpec` 集合と表示設定を渡す。生成処理はGhidraの現在状態を参照せず、同じ公開設定なら同じ順序・内容を返す。

文章は以下の順に生成する。

1. 扱う作業: Ghidraプロジェクトでのバイナリ静的解析。
2. 検索すべき場面と主要機能: デコンパイル、ディスアセンブル、参照・呼び出し関係、メモリ・文字列・型等の有効な機能。
3. 利用開始: 公開中なら `list_targets` を案内し、対象を受け取るツールがあれば `target` とサーバー上のパスを説明する。
4. 詳細説明: `ghidra://docs/tools` とツール別ドキュメントリソース。
5. 結果取得: resourceモードなら `read_result`、`search_result`、結果リソース、継続位置の扱い。
6. 結果確認: `isError`、status、完了情報を確認し、完了済みの変更を自動で繰り返さないこと。

機能の案内は有効なツール名とカテゴリ・safety tagに基づく。readonly構成で編集操作を案内しない。カテゴリ内の1ツールだけを公開する場合も、同じカテゴリの未公開操作を案内しない。BSim・共有リポジトリ・スクリプトは公開中の機能に限る。`batch_read` は対応済みの読み取りをまとめる機能として案内し、未実装の一括デコンパイル等を記載しない。

全ツールの引数・スキーマは複製しない。`tools/list` による標準のツール発見を維持し、検索・遅延読み込みの実行はクライアントが担う。

文章は英語とし、UTF-8の1,900バイト以内をテストで確認する。これはMecha側の設計上限であり、MCPプロトコルの制約ではない。[サーバー作者向けガイド](https://code.claude.com/docs/en/mcp#for-mcp-server-authors)の推奨と、2KBでの切り詰めを考慮している。固定テンプレートを使い、実行時の機械的な末尾切り捨ては行わない。

## 検証

`tests/test_http_transport_contract.py` で、実際の起動設定からASGIアプリを構築し、ネットワークのポートや実Ghidraを使用せずにHTTP境界を検証する。

| 検証 | 確認する結果 |
| --- | --- |
| 最初の要求でのツール実行 | 初期化なしで呼び出せ、セッションIDなしのJSONで応答する |
| 結果の後読み | 別の要求から同じresult_idを取得・検索・リソース参照でき、解析を再実行しない |
| 処理待機中の別要求 | 偽の同期解析を待機させてもターゲット一覧を取得でき、解析の最終結果は一度だけ返る |
| 機能発見 | `server/discover` に新しいinstructionsが含まれ、公開ツールの一覧と一致する |
| 初期化要求 | SDKが受け付けるinitialize要求でもセッションIDを作成しない |
| アクセス先制限 | 不正なHost/Originが拒否される |
| 入力検証 | 型の不正な入力がバックエンドまで到達しない |

`tests/test_server_instructions.py` は default / readonly / full、resource / inline、カテゴリ単独、ツール単独、個別enable/disable、ツール0件を検証する。非公開操作の案内がないこと、結果取得の説明が表示設定に一致すること、順序の安定性、文量を確認する。

通常のpytest全体、Ruff、フォーマット、Pythonコンパイル、差分の確認を行う。実Ghidra専用の検証は通常テストと分け、稼働中のサーバーを再起動しない。HTTP境界テストは、各AIクライアントでの検索精度、実ネットワーク切断時の同期Ghidra処理の停止、プロキシのタイムアウト動作を保証するものではない。

2026-09-16の検証結果（ローカルPython 3.12、MCP SDK 2.1.1）:

- 追加したHTTP境界・instructionsテスト: 28件成功。
- 通常テスト全体: 1,335件成功、実Ghidra/BSim専用の36件をスキップ。実機検証の環境フラグを無効にして実行。
- `ruff check src tests`、`ruff format --check src tests`、`python -m compileall -q src`、`git diff --check`: 成功。新規ファイルの末尾空白も確認。
- resourceモードのinstructions: default 1,202バイト、readonly 1,049バイト、full 1,370バイト（UTF-8）。
- 稼働中のサーバーの再起動、Dockerの再ビルド、実Ghidraの起動は行っていない。

## 更新ファイル

- 通信: `src/ghidra_mcp/presentation/transport.py`
- 説明生成・組み込み: `src/ghidra_mcp/presentation/server_instructions.py`、`mcp_server.py`
- テスト: `tests/test_http_transport_contract.py`、`tests/test_server_instructions.py`、既存の `test_cli_session.py`
- 利用説明: `docs/configuration.md` / `.ja.md`、`docs/clients.md` / `.ja.md`
- Docker: HTTPエンドポイントがセッションを必要とするという古いコメントを修正。ヘルスチェックの処理内容は同じ。

OAuth、利用者別権限、プロセス間の状態共有、出力スキーマの公開、独自ツール検索はこの変更の対象外とする。


## 推奨APIへの移行（2026-09-16追補）

低レベル `Server` の公開ハンドラーに移行し、SDK関数メタデータの上書きを撤去した。標準構成56ツールすべてに `outputSchema` を公開し、送信する構造化データを検証する。通常値とバッチは `structuredContent.result`、通常ツールの圧縮参照情報とエラーは直下に置く。取得・バッチ応答の予算にはテキストと構造化データの両方を含める。詳細は [設定](configuration.ja.md) と [開発](development.ja.md) を参照。

旧HTTP+SSEを削除し、JavaスレッドIDを `threadId()`、Javaクラス参照を `jpype.JClass` に統一した。PyGhidraの例外伝播用パッチは変更していない。

全体テストは **1344 passed, 36 skipped**。追加した検証には公開SDKクライアントでの構造化出力・エラー・容量超過と、JVMを起動しない実stdio往復を含む。実Ghidraの検証、稼働中サーバーの再起動、Docker再構築は実施していない。
