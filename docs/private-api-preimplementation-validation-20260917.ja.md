# 非公開API依存解消の実装前検証（2026-09-17）

実機で検証した結果、公開APIへの移行とPyGhidraパッチの条件付き適用・将来の削除は実装可能。ただし、当初の手順には **Raw Binaryの数値変換** と **異なるランタイムから呼ぶJython子スクリプトへの実行環境共有** を追加する必要がある。

今回の変更は一時ディレクトリ内の試作・テストと、この検証記録だけ。本番ソース、依存定義、ロックファイルは変更していない。

## 検証環境と対象

- macOS arm64、Ghidra 12.1.2、Java 21、Python 3.12、JPype 1.5.2。
- Jython 2.7.4は隔離したGhidra設定ディレクトリの公式拡張を使用。Jythonを必要とするテストのスキップは0件。
- 現行PyGhidra: 作業環境の3.1.0。
- 上流候補: [公式コミット263160cf57db21a9e25f1e0a8bc42fde5b8824eb](https://github.com/NationalSecurityAgency/ghidra/commit/263160cf57db21a9e25f1e0a8bc42fde5b8824eb)のPyGhidra 3.2.0ソースからwheelをビルド。取得した33ファイルのGit blob SHAとSHA-256を検証し、ソースの変更がないことも照合した。
- wheel SHA-256: `5e17b9d8b638d310264352329e3086af3c6e3e969fd28c596e35714c703d050c`。
- 上流候補は専用ディレクトリから読み込み、既存venvへはインストールしていない。正式版Ghidra 12.2や未公開の将来リリースを検証したという意味ではない。

## 最終結果

| 実行 | 成功 | 失敗・エラー・スキップ | PyGhidraパッチ |
|---|---:|---|---|
| 現行3.1.0＋修正した移行試作 | 76 | すべて0 | 必要時のみ適用 |
| 上流3.2.0候補＋修正した移行試作 | 69 | すべて0 | 未適用 |
| 上流候補でMechaインポート処理へ接続 | 3 | すべて0 | 未適用 |

76件の内訳はRaw Binary 16件、起動時検査8件、親子ランタイム・異常終了33件、既存スクリプト実機テスト19件。69件では、現行3.1.0専用の障害注入・負例7件を実行対象から外し、標準実装での検査を実行した。除外した7件をスキップ成功として数えてはいない。

Raw Binary 16件のうち1件と、現行の起動時検査8件のうち1件は、現行コードの問題を再現する負例である。「現行コードに問題がない」ことを意味する合格数ではない。

## 1. Raw Binaryの公開API置換

試作は公開APIの `RandomAccessByteProvider` → `BinaryLoader.findSupportedLoadSpecs()` → `LoaderMap` / `LcsHintLoadSpecChooser` → `BinaryLoader.getDefaultOptions()` → `Option.getArg()` → `ProgramLoader.Builder.addLoaderArg()` / `load()` を使用した。非公開メソッドへのリフレクションは置換候補の経路に含まない。

実機で確認した内容:

- Base Address、File Offset、Length、Block Nameの単独・組み合わせ指定。languageと明示的compilerの反映。
- メモリブロックの開始アドレス、サイズ、名前、実際の全バイト列。
- 不明な言語、範囲外オフセット、負の長さ、未対応Overlayの拒否。
- メタデータ処理中・保存直前の障害注入でも、ByteProviderと読み込み済みProgramを解放。
- ByteProviderはclose後のreadByteが失敗し、取得したProgramは `isClosed()` が真になる。
- 成功／保存失敗を20回繰り返して、当該JVMのファイル記述子数は181→181。
- プロジェクトを閉じた後、再度開けること。
- Mechaの `_import_program_raw_locked` へ試作を一時接続して、実際のツール経由でentry_address、entry_offset、analyze_importedのtrue／false、保存後の再読み込み・デコンパイルを確認。再読み込み・close時のネイティブデコンパイラ終了も確認した。

### 見つかった数値変換の問題

現行の本番メソッドをそのまま実行すると、`file_offset=16, length=24` は **実際にはオフセット22、長さ36** になる。Ghidraの `HexLong` オプションが接頭辞のない文字列も16進数として解釈するため。

試作では整数のFile OffsetとLengthを `hex(value)` で渡し、意図した16バイト・24バイトを実測した。非公開APIの置換だけではこの問題は直らないため、移行時の必須修正に含める。

補足: length省略時はGhidra標準のファイル全長がブロック長となり、オフセットによる不足分はゼロ埋めされる。この挙動も全バイト比較で確認した。OverlayはこのGhidra版の新規インポート向けCLI引数として公開されておらず、明示的に拒否する。

## 2. パッチ前検査・条件付き適用・失敗時停止

現行3.1.0では、標準Providerに生成したRuntimeErrorスクリプトを実行させると例外が飲み込まれることを、パッチ適用前に確認した。検証済みバージョンにだけ既存パッチを適用し、再検査で例外伝播に変わることを確認した。

上流候補では最初の検査で例外が伝播し、そのまま標準Providerを使用した。検証用フックでMechaパッチの適用関数・サブクラス生成関数を呼ぶと失敗するようにし、呼ばれていないことと `compat_state.bound=false` を確認した。

現行3.1.0で、未知バージョン、予想外の検査結果、検査中例外、適用中例外、適用無効、差し替え後の例外の6パターンを注入した。これらは未知の実バージョンをインストールした試験ではなく、実Ghidra上の制御分岐と停止動作の試験。

- 未検証版・検査異常時にはパッチを適用しない。
- 適用後に失敗した場合は元のクラスへ戻す。
- 失敗時はJava・PyGhidra・Jythonすべてのスクリプトを利用不可として表示し、共通実行入口でも拒否。
- カタログ／インラインの親スクリプトを経由して、子だけが実行される経路も止まる。
- スクリプト停止中も、プログラム情報やコメントの読み取りは利用可能。

負例として、PyGhidraだけを利用不可と表示した状態でJava親を許可すると、未修正3.1.0のPython子が失敗しても変更が確定することを再現した。停止はPyGhidraの直接呼び出しだけでなく、スクリプトの共通入口に置く必要がある。

検証用試作では初期化順序にも問題が出た。検査結果を再利用する場合でも、Provider取得前のBundleHost初期化を行うように修正して最終検証を通した。

## 3. 上流修正版でのロールバック・ランタイム連携

親・子それぞれJava／PyGhidra／Jythonの9通りについて、正常終了、子の例外を親が捕捉、未捕捉の3パターン、計27ケースを実行した。

- 正常終了・捕捉済み例外: 親が完了し、変更が確定。
- 未捕捉例外: 実行失敗となり、親・子の変更が開始前の状態へ戻る。
- PyGhidraのSystemExit(None/0/3/文字列)、KeyboardInterrupt、協調タイムアウトと次回実行の回復。
- JythonのSystemExit 9パターン、タイムアウト、既存のロールバック試験。
- sys.argv／sys.pathの復元と、一時追加したsys.modules項目の除去。

### 上流修正だけでは残ったJythonの問題

Jythonの実行環境を用意する現行処理は、最上位がJythonの場合だけ有効。このためJava／PyGhidraからJython子を呼ぶ場合、子の標準出力が結果に入らず、子の例外が親に伝播しない。また、初回生成されるCleanerスレッドが残留スレッドとして検出されるケースがあった。

これは上流PyGhidra候補だけへ交換しても再現した。上流候補での初回比較は61成功・6失敗・後処理エラー1件で、6失敗はいずれもJava／PyGhidra→Jythonの組み合わせだった。

試作ではJythonが利用可能な場合、最上位の言語によらず公開API `GhidraJythonInterpreter.get()` と `GhidraState.addEnvironmentVar()` で実行環境・出力先を準備し、終了時に環境変数削除とcleanupを行った。既存の実行処理の条件を検証プロセス内で差し替えて評価した結果、27ケースすべてが成功した。スレッド検出を無効化したり、問題のスレッドを除外する変更はしていない。

JythonでJava由来の例外を捕捉する試験スクリプトは、PythonのExceptionに加えて `java.lang.Exception` を捕捉している。Jython→PyGhidraの未捕捉例外はJPypeの `PyExceptionProxy` としてerror.messageに現れる既存制約があるが、ロールバックは成功する。上流候補では元のPython例外もstderrに記録された。

## 実装時に採用する条件

1. Raw Binaryのメタデータ取得を公開APIに置換し、整数引数は明示的な16進文字列に変換する。
2. BundleHost初期化 → パッチなしの検査 → 検証済み3.1.0のみ適用 → 再検査の順序にする。
3. 検査・適用失敗時はスクリプト全体を停止し、部分的な差し替えを残さない。
4. Jythonが導入されている場合は、Java／PyGhidra親からも子へ実行環境が伝わるように準備・解放する。
5. 上流の修正版正式リリースへ移行するとき、この実機試験を再実行したうえで3.1.0用パッチを削除する。

## 記録と再現

- 一時検証ディレクトリ: `/private/tmp/mecha-private-api-validation-20260917`。
- 最終結果: `stable-final/result.xml`、`upstream-verified-final/result.xml`、`upstream-integration-final/result.xml`。
- 同じ各ディレクトリの `runtime.log` / `runtime-state.json` に実行ログ、PyGhidraの読込元、パッチ適用状態を保存。
- 失敗した試行も `stable`、`stable-revised`、`upstream-original`、`upstream-final` として保存。後の成功ログで上書きしていない。
- 本番のPythonソース、pyproject.toml、uv.lockの計111ファイルは検証前後のSHA-256が一致。
- [検証用コード・最終ログ・上流wheelの保存アーカイブ](private-api-validation-20260917.zip)。検証用コードはこのMacの既存リポジトリと前回用意したJython拡張のパスを使用するため、別環境での再実行時はパスを設定し直す必要がある。

公式API: [BinaryLoader](https://ghidra.re/ghidra_docs/api/ghidra/app/util/opinion/BinaryLoader.html)、[ProgramLoader.Builder](https://ghidra.re/ghidra_docs/api/ghidra/app/util/importer/ProgramLoader.Builder.html)。例外伝播修正の背景: [公式Issue #9288](https://github.com/NationalSecurityAgency/ghidra/issues/9288)。
