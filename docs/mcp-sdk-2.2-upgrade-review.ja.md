# MCP SDK 2.2.0 更新検討・採用（2026-09-20）

## 結論

現在のMecha Ghidraに、2.2.0への更新を理由とする追加の実装修正は見つからなかった。`mcp` と `mcp-types` だけを2.1.1から2.2.0へ変更した隔離環境で、現行ソースのオフラインテストと実Ghidraを使ったstdio／HTTPテストが成功した。

検討時は隔離環境だけで確認し、その後の更新指示に基づいて2.2.0を採用した。リポジトリの依存下限とlockfileを更新し、通常の `.venv` も同期済み。稼働サーバーの再起動は行っていない。

## 変更点と適用判断

[公式リリースノート](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.2.0)と、公開済みパッケージの実装を確認した。

| 2.2.0の変更 | 現行実装との関係 | 判断 |
| --- | --- | --- |
| HTTPクライアントのリダイレクトを同一origin等に制限 | 本体はMCPサーバー。テストのクライアントはlocalhostの直接URLへ接続する | 実装変更不要。別ホストへの転送に頼るクライアント設定では接続先を最終URLにする |
| 旧プロトコルのstateful HTTPセッションに30分のidle期限と10,000件の上限 | `stateless_http=True` を設定し、新プロトコルもセッション不要で動く | 上限無効化やセッション維持処理の追加は不要。Ghidraのプロジェクト状態とは別の仕組み |
| OAuthのissuer検証、`issuer=` と `validate_token_resource` の追加・警告 | MCPのOAuth provider／`AuthSettings`／`TokenVerifier` を現在使用していない | 今回の更新に伴う設定追加は不要 |
| ツールの `outputSchema` の `$ref` をスキーマ内に限定 | 入出力160スキーマ内の17参照を確認。すべて内部参照で解決可能 | 修正不要。詳細は下記 |
| MCPのRootModelラッパーを型エイリアスへ変更 | MCPメッセージunionの `.root`、unionの直接生成・`model_validate` に依存していない | 修正不要。既存の型付きリクエスト・結果と新 `Client` で検証成功 |
| セッション解放などのSDK内部修正 | 公開 `Server`／標準transportを使用している | SDKの更新で適用され、アプリ側の再実装は不要 |

OAuthを将来追加する場合は、その設計時にissuerとトークンの対象リソースの検証を決める。今回使っていない機能のために設定を追加しない。

### スキーマの参照制限

[上流PR #3394](https://github.com/modelcontextprotocol/python-sdk/pull/3394)はクライアントの出力検証を変更し、スキーマ外への参照を解決しない。Mecha Ghidraの `wire_output_schema()` は `$defs` を文書ルートに残しており、`#/$defs/...` が有効な構成になっている。

全ツールを公開したカタログは取得補助ツール込みで80件。入出力160スキーマをJSON Schemaとして確認し、17件の `$ref` がすべて文書内のJSON Pointerとして解決できることを確認した。外部参照・未解決参照は0件。実際のツール結果は既存テストと実機通信テストでも2.2.0のクライアントで検証した。

### 直前に修正済みの移行漏れ

存在しないリソースに対する `MCPError(ErrorData(...))` は2系のコンストラクタと合わず、`TypeError` になっていた。前の確認で `MCPError(code=INVALID_PARAMS, message=..., data={"uri": ...})` へ修正済みで、今回もそのソースを検証した。これは2.2.0で新たに必要になった変更ではなく、2.1.1でも必要だった2系への移行修正。

## 検証結果

| 対象 | 結果 |
| --- | --- |
| 依存解決 | `mcp` と `mcp-types` の2パッケージだけを2.2.0へ更新。他のパッケージのバージョンは変更なし |
| オフライン全体 | 1372 passed / 88 skipped。`MCPDeprecationWarning` をエラー扱いで実行 |
| Ghidra実機のMCP通信 | 4 passed。stdio／HTTP × PyGhidra／Jython |
| 全ツールのスキーマ | 80ツール・160スキーマ・17内部参照を確認。外部参照・未解決参照なし |

実機通信テストは、ツール検出、初期ハンドシェイク不要の呼び出し、raw import、解析、編集、構造化結果、大きな結果の取得、子スクリプト、例外時のロールバックを含む。

環境はmacOS arm64、Python 3.12.11、Ghidra 12.1.3、Temurin JDK 21、同版のJython拡張。PyGhidraは本プロジェクトで固定している上流コミット `263160cf57db21a9e25f1e0a8bc42fde5b8824eb`、JPype1は1.5.2。Windows／Linux／Dockerおよび他のPythonバージョンでの実行は今回確認していない。

検証環境とログは `/private/tmp/mecha-mcp22-review-ng91lgm9/` に保存した。`dependency-changes.json`、`offline.log`／`offline.xml`、`real-mcp-transport/runtime.log`／`result.xml`、`check_schemas.json` が証跡。

## 採用した変更

1. `uv.lock` の `mcp` と `mcp-types` を2.2.0へ更新。他の依存バージョンは検証時から変更していない。
2. 依存下限を `mcp>=2.2.0,<3` とし、日英の開発ドキュメントの対応範囲も更新した。
3. `uv sync --frozen --extra dev --offline` で通常の `.venv` へ反映し、`uv pip check` で整合性を確認した。
4. 反映後の通常環境でもMCP通信・構造化結果・server instructionsの39テストが成功。`MCPDeprecationWarning` をエラー扱いとし、結果を検証ディレクトリの `activated.xml` に記録した。

通常CIのPython 3.10／3.12／3.14は更新後のlockfileを使用する。既存の `latest-mcp-sdk` は助言用であり、今回そのリモートCIの結果を確認したわけではない。

進捗通知や `subscriptions/listen` の追加は機能拡張として別途検討できるが、2.2.0へ更新するための前提ではない。
