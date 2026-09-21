# 自動配置される構造体のリリース前レビュー（2026-09-21）

追記: 以下の指摘は[構造体の配置修正と検証](release-packed-layout-fix-20260921.ja.md)で対応済みです。以下は修正前のレビュー記録です。

[前回のデータ型修正](release-datatype-fixes-20260921.ja.md)後を確認し、追加で **P2を1件** 再現しました。今回はレビューのみです。製品ソース・既存テスト188ファイルに変更はありません。

## P2: 自動配置が有効な構造体で明示offsetが守られない

対象: `src/ghidra_headless/handlers/commands/mutating_data_types.py:16–20`

`_place_struct_member()` は、すべての構造体に `growStructure()` と `replaceAtOffset()` を使います。しかし、Ghidraのpackingが有効な構造体では、前者は拡張せず、後者は再配置によって実際のoffsetを決めます。`parse_c_declarations` で通常のC構造体を作るだけで、この条件になります。

次の宣言を `parse_c_declarations` に渡します。

```c
struct Packet { char tag; int value; char tail; };
```

x86-64での配置は `tag=0, value=4, tail=8, length=12` です。その後、以下の `add_struct_members` を呼びます。

```json
{
  "struct_name": "Packet",
  "members": [{"name": "extra", "type": "char", "offset": 4}]
}
```

呼び出しは成功しますが、`extra` は指定した4ではなく **1** に配置され、変更対象外の `tail` も **8から2** に移動します。構造体長は12から3に縮みます。保存・再読み込み後にも、この配置が残ります。

`offset=4` による既存の `value` の置換自体は現行APIの動作です。問題は、明示したoffsetと変更対象外のフィールド位置まで変わることです。バイナリの既知の配置に合わせて型を編集したつもりでも、その配置と異なる型を保存してしまいます。

同じ原因で、padding内の `offset=2` への追加も実際は1に入り、末尾の `offset=12` や範囲外の `offset=16` は `Offset ... is beyond end of structure (12).` で失敗します。前回直した「通常の構造体を末尾以降へ拡張する」処理だけでは、自動配置が有効な構造体を扱えません。

| 条件 | 実際の結果 |
| --- | --- |
| 自動配置あり、offset=2 | 成功するが、実際はoffset=1 |
| 自動配置あり、offset=4 | 成功するが、実際はoffset=1、tailが8→2、長さ12→3 |
| 自動配置あり、offset=12 / 16 | どちらも拡張できず失敗 |
| 自動配置あり、offset省略 | 既存配置を維持し、次のcharをoffset=9に追加 |
| 通常の構造体、offset=2 / 4 / 12 / 16 | すべて指定位置に配置、tag=0とtail=8を維持 |

修正方針: 明示offsetを受け取る場合は、既存配置を維持した手動配置へ切り替えてから拡張・置換する必要があります。公開APIの `setPackingEnabled(false)` を編集トランザクション内で呼ぶ試作では、上記4条件すべてが成功し、保存・再読み込み後も指定位置と変更対象外のフィールド位置を維持できました。offsetを省略する通常の追加は、従来どおり自動配置を維持できます。明示offsetによる編集が自動配置を解除することは、ツール説明にも記載するのが適切です。

試作は一時テスト内で製品の補助関数を差し替えたもので、製品には適用していません。外部ライブラリの非公開APIへのパッチは使用していません。

## 検証結果

| 検証 | 結果 |
| --- | --- |
| プログラム操作・ヘッドレス補助処理・入力検証・ページング・ランタイム実行・パスポリシー・batch/result関連の既存テスト | **151 passed**（30.37秒） |
| 実Ghidraの最終実行 | **4 failed / 42 passed**（57.01秒） |
| 上記のうち、既存のデータ型・ツール回帰テスト | **29 passed** |
| 上記のうち、今回の追加検証 | **4 failed / 13 passed** |
| 製品ソース・既存テストの不変確認 | **188ファイル変更なし** |
| `git diff --check` | 成功 |

4失敗は未修正の製品に対して期待するoffsetを検査した再現テストです。13成功には正常系、失敗時のロールバック、誤配置の保存後の持続、公開APIを使った修正方針の実現性確認を含みます。「42 passed」は製品の不具合が直ったという意味ではありません。

実行環境はGhidra 12.1.3 / Java 21 / macOS arm64です。専用JVM・一時プロジェクトを使い、`MCPDeprecationWarning` をエラー化しました。Ghidra同梱の `SoftwareModeling-src.zip` で、packing時の `growStructure()` の無処理と、`replaceAtOffset()` の再配置仕様も照合しています。

メモリ・シンボル操作、型解決、変更処理の結果返却、batch/result周辺も確認しましたが、今回追加で報告できる確定不具合は上記1件です。通常テスト全件、外部BSim・共有リポジトリ接続、Docker・他OS、配布物ビルドは今回再実行していません。

[検証資料](release-packed-layout-review-evidence-20260921.zip)に、再現テスト・正常系と試作テスト・実行条件・ログ・JUnit XML・入力と結果・ローカルGhidraのAPI根拠・ソースの不変確認を保存しています。
