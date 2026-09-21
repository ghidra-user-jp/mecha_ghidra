# リリース前の既知問題の修正・検証（2026-09-20）

## 修正内容

- raw importの整数 `file_offset`／`length` を `hex()` でloaderへ渡す。Ghidraの `HexLong` は接頭辞のない文字列も16進数として解釈するため、従来の `16`／`24` は22／36バイトとして扱われていた。
- raw loaderのオプション取得を公開APIへ移行。`FileByteProvider(File, null, AccessMode.READ)`、`BinaryLoader.findSupportedLoadSpecs()`、`LcsHintLoadSpecChooser.choose()`、`getDefaultOptions()`、`Option.getArg()` を利用する。非公開の `ProgramLoader` メソッドへのリフレクションと推測によるオプション名のフォールバックを撤去した。非推奨の `RandomAccessByteProvider` は導入していない。
- PyGhidraを上流コミット `263160cf57db21a9e25f1e0a8bc42fde5b8824eb` に固定し、非公開runnerへ介入する `pyghidra_compat.py` を撤去。標準providerを使う起動時の例外伝播チェックだけを残す。
- 例外伝播チェックが失敗・未実行なら、Java・Jython・PyGhidraの実行をトランザクション開始前に拒否。Java/Jython親からPyGhidra子を呼ぶ経路も同じ対象になる。
- Jython拡張がある場合は、親言語によらず `GhidraState` に共有interpreterを設定し、子Jythonの出力・例外を同じ実行へ返す。未処理例外なら親の変更もロールバックする。

## 依存更新と配布方針

2026-09-20にPyPI JSONを直接確認した時点で、PyGhidraの最新正式版は3.1.0。採用したソースのバージョン表記は3.2.0だが、正式リリースではない。

- [上流コミット](https://github.com/NationalSecurityAgency/ghidra/commit/263160cf57db21a9e25f1e0a8bc42fde5b8824eb)
- [例外伝播の上流Issue](https://github.com/NationalSecurityAgency/ghidra/issues/9288)
- Pythonプロジェクトの場所: `Ghidra/Features/PyGhidra/src/main/py`
- アーカイブSHA-256: `45b5ac4bb3f613145e69c514d1f59573d73420055fae32f48574d1b0e66072f0`

直接URL依存は `pyproject.toml` とwheelの `Requires-Dist` に入り、`uv.lock` にハッシュを記録する。初回の取得にはGhidraのソースアーカイブが必要になる。PyPI公開は予定していないため、v1.0は検証済みの上流コミット固定で進め、正式版への切り替えを公開条件に含めない。ローカルwheel／ソースからの導入は検証済み。今後依存を更新する際にはlockfileを更新し、実機・パッケージ検証を再実行する。

## 検証環境

- macOS arm64、Python 3.12.11、Temurin JDK 21
- Ghidra 12.1.3 PUBLIC、同版の公式Jython拡張（Jython 2.7.4）
- PyGhidra 3.2.0相当の上記コミット、JPype1 1.5.2
- 一時ディレクトリのvenv、Ghidra設定、テスト用プロジェクトを使用。既存のサーバー、ユーザープロジェクト、リポジトリの `.venv` は更新・再起動していない。

## 結果

| 対象 | 結果 | 確認した内容 |
| --- | --- | --- |
| オフライン全体 | 1369 passed / 88 skipped | 入出力契約、公開API経由のloader設定、例外チェックの失敗・リソース解放、全言語の実行入口の拒否など |
| `test_runtime_script_commands.py` | 52 passed | 親3言語×子3言語×成功・親で捕捉・未処理の27ケース、出力・編集・ロールバック、既存のscript実機テスト |
| `test_runtime_resource_safety.py` | 6 passed | rawの指定範囲の内容・長さ・ベースアドレス・再オープン後の内容、リソースの解放 |
| その他のローカル実機テスト | 19 passed | readonly 1、mutating 3、tool revision 11、batch read 3、worker thread 1 |
| `test_runtime_mcp_transport.py` | 4 passed | stdio／HTTP × PyGhidra／Jython |
| 標準PyGhidra 3.1.0での拒否確認 | 成功 | 例外の握りつぶしを起動時に検出。3言語のinline実行を拒否し、`get_program_info` は成功 |
| wheel／sdist作成、新規venvへのwheel導入 | 成功 | 直接依存をメタデータへ保持、`runtime_check.py` を収録、旧パッチを除外、`uv pip check` と `ghidra-mcp --help` が成功 |
| `uv lock --check --offline`、Ruff、`git diff --check` | 成功 | 固定依存とlockfileの一致、lint／format |

実機81件は複数の実行結果の合計で、単一の81件実行ではない。rawの3ケースは `(file_offset, length) = (16, 24), (10, 16), (0, 32)` とし、元データのスライスと読み込み後の全バイトを照合した。

PyGhidraの追加ケースでは、`SystemExit(None)` と `SystemExit(0)` は上流仕様どおり成功し、非ゼロ／文字列の終了は失敗してロールバックすることを確認した。`KeyboardInterrupt` のロールバックと `sys.argv`／`sys.path`／`sys.modules` の復元、協調的なタイムアウト後の再実行も確認した。

### 検証中に修正・確認した点

- `ProgramLoader.loaders(String...)` は単純名を解決するため、`"BinaryLoader"` を使う。完全修飾名の文字列では実機ロードが失敗した。
- 空のスクリプト集でinline実行だけを試すfixtureも、スクリプトrootを作成するよう修正した。
- 出力検証の範囲は下記の公開出力関数。CPythonのプロセスstderrへの書き込みをツールのstderrとして扱う誤ったテストを修正した。
- PyGhidra 3.1.0の拒否確認に使ったJavaソースは、クラス宣言を独立行に置く必要があった。入力検証エラーとなった初回結果を除外し、修正後に3言語のランタイム拒否を確認した。

### 出力と検証範囲の制限

| 言語 | 捕捉を検証したstdout | 捕捉を検証したstderr |
| --- | --- | --- |
| Java | `println` | `printerr` |
| PyGhidra | `print` | `printerr` |
| Jython | `print` | `sys.stderr.write` |

Ghidra 12.1.3のJython親→Jython子は子のscript writerを引き継がないため、子の `println`／`printerr` の出力は捕捉できない。共有interpreter経由のPython出力を使う。CPythonの `sys.stdout`／`sys.stderr` やJavaの `System.out`／`System.err` の直接書き込みもスクリプト別の捕捉対象外。プロセス全体の出力先を置き換える修正は加えていない。

今回の実機検証はmacOS arm64／Ghidra 12.1.3に限る。Windows・Linux・Dockerでの起動、共有リポジトリ、BSim、他のPython/Ghidraバージョンは今回の実機検証に含めていない。

## 再実行

対応するJDKとGhidra、同版のJython拡張を一時設定ディレクトリへ準備したうえで、[開発手順](development.ja.md#実機検証)の環境変数を設定し、次を実行する。`GHIDRA_RUNTIME_BINARY_PATH` はホストで解析可能なバイナリを指定する。

```sh
uv sync --frozen --extra dev
uv run pytest -q
GHIDRA_RUNTIME_VALIDATION=1 GHIDRA_JYTHON_RUNTIME_VALIDATION=1 uv run pytest -q \
  tests/test_runtime_script_commands.py tests/test_runtime_resource_safety.py \
  tests/test_runtime_readonly_commands.py tests/test_runtime_mutating_commands.py \
  tests/test_runtime_tool_revision.py tests/test_runtime_batch_read.py \
  tests/test_runtime_worker_thread.py tests/test_runtime_mcp_transport.py
```

今回のローカル証跡は `/private/tmp/mecha-release-fixes-20260920/` にある。成功したscript実機結果は `final-script-runtime/`、rawの6件は `final-local-runtime/result.xml` 内の `tests.test_runtime_resource_safety`、残りは `other-local-runtime/` と `mcp-transports/`。`final-local-runtime/` 全体は出力関数の修正前のため9件失敗を含み、全件成功としては扱っていない。旧版の拒否確認は `old-runtime-negative-verified.log`、オフライン結果は `final-offline.log`、ビルド・導入確認は `build.log` と `artifact-cli-help.txt`。
