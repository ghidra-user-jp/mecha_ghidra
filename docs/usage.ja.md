[English](usage.md) | [日本語](usage.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# はじめに

Mecha Ghidraを導入し、MCPクライアントから最初のプログラムを開くまでの手順です。シェル例はBash/zsh用です。`/absolute/path/...` はサーバーが動くマシン上の実際のパスに置き換えてください。Ghidra同梱の環境を使う場合は[Dockerガイド](docker.ja.md)へ進んでください。

## ドキュメント一覧

| やりたいこと | 読むページ |
| --- | --- |
| 導入して最初のバイナリを解析する | このページを続けて読む |
| AIアシスタントを接続する | [MCPクライアント](clients.ja.md) |
| 公開ツール、パス、出力サイズを変える | [設定](configuration.ja.md) |
| 必要なツールを探す | [ツール一覧](tools.ja.md) |
| コンテナで動かす | [Docker](docker.ja.md) |
| Ghidra Serverで解析結果を共有する | [共有プロジェクト](shared-projects.ja.md) |
| 類似する関数を探す | [BSim](bsim.ja.md) |
| エラーの解決や古い設定の更新をする | [トラブルシューティング・移行](troubleshooting.ja.md) |
| ソースコードの変更やリリースを行う | [開発](development.ja.md) |

<a id="requirements"></a>

## 前提環境

| 項目 | 必要なもの |
| --- | --- |
| Python | 3.10以上 |
| パッケージ管理 | [uv](https://docs.astral.sh/uv/getting-started/installation/) |
| Ghidra | OS・CPUに対応するネイティブデコンパイラを含むインストール一式 |
| Java | 使用するGhidraが要求するJDK。Ghidra 12.1系はJDK 21 |
| MCPクライアント | Streamable HTTPまたはstdioに対応したもの |

ビルド対象のGhidraは[ghidra_release.env](../scripts/ghidra_release.env)で12.1.4に固定されています。Ghidra ServerとBSimデータベースは必要な場合だけ用意します。

<a id="native-decompiler-artifacts"></a>

### ネイティブデコンパイラ

Ghidra 12.1.4の公式ZIPには、Linux ARM64とmacOSの両アーキテクチャ向けネイティブデコンパイラが含まれていません。[Mecha Ghidraのリリース](https://github.com/ghidra-user-jp/mecha_ghidra/releases)から用途に合う配布物を選んでください。

| 配布物 | 用途 |
| --- | --- |
| `ghidra_12.1.4_decompiler_natives_all.zip` | ネイティブファイルを追加済みのGhidra一式 |
| `ghidra_decompiler_natives_all.zip` | 既存のGhidra 12.1.4へ展開する追加ファイル |
| GitHubの `Source code` アーカイブ | Mecha Ghidraのソースコード。Ghidra本体は含まれない |

追加先は `Ghidra/Features/Decompiler/os/{linux_arm_64,mac_arm_64,mac_x86_64}/` で、対応する `decompile` と `sleigh` を含みます。Ghidra本体とネイティブファイルのバージョンをそろえてください。自分で生成する場合は[ネイティブビルド](development.ja.md#native-builds)を参照してください。

<a id="local-setup"></a>

## 1. インストールして起動する

```bash
git clone https://github.com/ghidra-user-jp/mecha_ghidra.git
cd mecha_ghidra
uv sync
```

以下で作成する `samples` に、解析対象を `sample.bin` として置いてください。PE、ELF、Mach-Oなど、Ghidraが認識できる実行ファイル形式を使います。生のバイナリは、ツールスキーマに従って言語やインポート方式を指定する必要があります。

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
mkdir -p projects samples exports

uv run mecha_ghidra \
  --project-location "$PWD/projects" \
  --project-name analysis \
  --transport http \
  --allowed-import-root "$PWD/samples" \
  --allowed-project-root "$PWD/projects" \
  --allowed-export-root "$PWD/exports"
```

この起動例は `projects/analysis.gpr` を指す `default` ターゲットを登録します。プロジェクトの作成やプログラムの読み込みはまだ行いません。サーバーを起動したまま、別のアプリケーションから以下のMCPツールを呼び出します。

サーバーはGhidraの起動（JVMとGhidraの初期化、`--domain-path` で指定したプログラムの読み込み）を待たずに、MCPの受付を始めます。接続とツール一覧の取得はすぐに終わり、Ghidraを使うツール呼び出しだけが起動の完了を待ちます。起動が終わると、サーバーログに `Ghidra ready in ...` と所要時間が出ます。

PowerShellでは `$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"` で環境変数を設定してください。シェルコマンドは1行にするか、PowerShellの継続記法に置き換えます。

## 2. クライアントを接続する

Streamable HTTPの接続先は `http://127.0.0.1:8081/mcp` です。設定方法は[MCPクライアント](clients.ja.md)にまとめています。接続後に `list_targets` を呼び、`default` が登録されていることを確認してください。

<a id="first-analysis"></a>

## 3. プロジェクト作成・インポート・読み込み

以下は**MCPツールの名前とJSON引数**です。シェルで実行するコマンドではありません。`/absolute/path/to/mecha_ghidra` をリポジトリの絶対パスに置き換えてください。

最初の1回だけ、`create_project` で空のプロジェクトを作成します。

```json
{
  "project_location": "/absolute/path/to/mecha_ghidra/projects",
  "project_name": "analysis"
}
```

`import_program` でファイルを取り込みます。取り込みはバックグラウンドのジョブとして実行され、呼び出しは最大`wait_seconds`秒（既定20秒）待ってからジョブの記録を返します。ジョブは既定でGhidraの自動解析まで行います。解析が不要な場合だけ`analyze_imported=false`を指定してください。読み込みでは解析しないため、プログラムは[`analyze_program`](#saving-and-analysis)を実行するまで未解析のままです。

```json
{
  "target": "default",
  "binary_path": "/absolute/path/to/mecha_ghidra/samples/sample.bin"
}
```

`state`が`queued`または`running`の間は、返された`operation_id`で`get_operation`を呼びます。こちらも最大`wait_seconds`秒待つため、`state`が`succeeded`または`failed`になるまで続けて呼んでかまいません。ジョブの状態確認には、このツールを使います。`list_targets`はジョブの実行中でもすぐに返りますが、ジョブの状態は示しません。

```json
{"operation_id": "<returned-operation-id>"}
```

成功時の **`result.program`** がプロジェクト内のパスです。通常は `/sample.bin` になります。この値を`load_project_program`の`domain_path`に渡します。MCP `structuredContent`を直接読む場合、ジョブの記録は通常の`result`包絡の内側にあるため、パスは`structuredContent.result.result.program`です。

取り込み・解析・スクリプトのジョブは1つの待ち行列を共有し、受け付けた順に1件ずつ実行されます。待機できるのは16件までで、満杯なら`OPERATION_QUEUE_FULL`を返し、何も受け付けません。待機中・実行中のジョブは`cancel_operation`で取り消せます（[長い呼び出し](#long-calls)）。取り消したジョブは待ち行列の枠を使いません。応答を失った場合、ジョブが待機中・実行中のうちに同じ引数で再送すると、二重に実行せず同じジョブを返します。取り消し中のジョブと同じ解析やスクリプトを送り直すと、その後に実行する新しいジョブになります。同じ取り込みは、取り消し中のジョブがまだプログラムを残しうるため、それが終わるまで再試行可能な`IMPORT_IN_PROGRESS`になります。再送せずに照会したい場合は、取り込み時に自分で生成したUUIDを`request_id`に指定し、後で`get_operation`に`{"request_id":"<same-UUID>"}`を渡します。同じ`request_id`で引数を変えた再送は拒否されます。入力ファイルは、ジョブが終わるまで変更・削除しないでください。

`failed`の場合、`operation_error`には元のエラーの`code`・`message`・`hint`が残ります。失敗後にプロジェクトへ何が残ったかは`operation_error.details.output_state`で分かります。

| `output_state` | 意味 | 次の操作 |
| --- | --- | --- |
| `absent` | 何も書き込まれていない | 原因を解消して取り込み直す。ロック待ちなど一時的な原因なら`retryable`が`true` |
| `created` | プログラムがプロジェクトに存在する | `load_project_program`で読み込む。このサーバープロセスは再起動まで同じ名前の取り込みを受け付けない |
| `uncertain` | 後始末を確認できなかった | プロジェクトを確認する。このサーバープロセスは同じ名前の取り込みを受け付けない |

解析のジョブは、トランザクションを巻き戻したなら`absent`、コミットの後に失敗したなら`created`、失敗の後始末ができなかったなら（`details.cleanup_error`）`uncertain`を示します。

ジョブの記録はサーバーのメモリ上にだけあります。完了したジョブが4,096件を超えると古いものから消え、再起動ですべて失われます。そのため`OPERATION_NOT_FOUND`は未実行の証明になりません。プロジェクト内を確認してから、ジョブを投入し直してください。サーバーの停止時には、実行中の解析をキャンセルします。取り込みは解析途中のプログラムを削除し、解析のジョブは変更を巻き戻します（`OPERATION_SHUTDOWN`、`output_state: absent`）。

```json
{
  "target": "default",
  "domain_path": "/sample.bin"
}
```

取り込みで解析済みなので、応答の`is_analyzed`は`true`です。続いて `list_functions` を `{"target":"default","limit":20}` で呼びます。返された関数のアドレスを選び、`decompile_function` に `{"target":"default","address":"<function-address>"}` として渡してください。C風の疑似コード、または[大きな結果を取得するための案内](configuration.ja.md#large-results)が返れば、解析を始められる状態です。

次回以降は、既存プロジェクトを再利用します。作成とインポートを省き、プログラム一覧から対象を読み込んでください。`create_project` は `overwrite=true` を指定しない限り既存プロジェクトを拒否します。通常の再起動で上書きは不要です。

<a id="project-concepts"></a>

## プロジェクト・プログラム・ターゲット

| 名前 | 意味 | 例 |
| --- | --- | --- |
| Project location | プロジェクトを置くホスト側ディレクトリ、または既存の `.gpr` ファイル | `/work/projects`、`/work/projects/analysis.gpr` |
| Project name | ディレクトリと組み合わせる、拡張子なしの名前 | `analysis` |
| Domain path | プロジェクト内部のプログラムのパス | `/samples/sample.bin` |
| Target | サーバープロセス内でプロジェクトやプログラムを識別する名前 | `default`、`reference` |

`--project-name` と `project_name` に `.gpr` は付けません。付いている名前は拒否されます。既存の `.gpr` ファイルを指定するときは、そのパスを `project_location` に渡し、`project_name` を省略してください。ローカルプロジェクトは `.gpr` ファイルと隣接する `.rep` ディレクトリの組です。

`register_target` はプロジェクト情報だけを登録し、`open_program` はターゲットを追加してプログラムを開きます。`load_project_program` は既存ターゲットのプログラムを読み込み・切り替えます。登録名は `list_targets` で確認できます。多くのプログラム操作ツールは `target` を受け取り、省略時は `default` を使います。

<a id="saving-and-analysis"></a>

## 保存と自動解析

編集後、保存のタイミングを明確にしたい場合は `save_project_program` を呼びます。プログラムの切り替えや `close_session` でも未保存の変更を保存します。プログラム編集ツールの呼び出しごとにトランザクションが作られ、`undo_program_change` と `redo_program_change` で操作できます。履歴はセッション内だけに残り、再読み込みすると失われます。解析済みか、未保存の変更があるか、取り消せるかは `get_program_info` で確認します。

読み込みでは解析しません。`load_project_program`と`open_program`は、プログラムをそのまま開き、`is_analyzed`を返します。起動時の`--domain-path`で開くプログラムも解析せず、同じ値は`get_program_info`で確認できます。`false`なら、関数一覧やdecompileの前に`analyze_program`を実行してください。未解析のままでは関数がほとんど見つからず、多くのツールが役に立ちません。

`analyze_program`は、取り込みと同じくバックグラウンドのジョブとして実行されます。応答は最大`wait_seconds`秒待ち、その後はジョブが終わるまで`get_operation`を呼びます。成功時の`result`は`{"program": "/sample.bin", "analyzed": true, "forced": false}`です。解析済みのプログラムは、`force=true`を指定しない限りそのままです（`analyzed: false`）。解析の結果は保存されず、未保存の変更になります。`save_project_program`、プログラムの切り替え、`close_session`で保存されます。

| 状況 | 結果 |
| --- | --- |
| ジョブの実行中 | ジョブがターゲットとそのプロジェクトを占有する。そこへの他の呼び出しは`LOCK_TIMEOUT`になり、`details.operation_id`で待つべきジョブが分かる |
| ジョブの開始前に、ターゲットの再読み込み・クローズ・別プログラムの読み込みがあった | `SESSION_CHANGED`。何も解析していない。いま読み込んでいるプログラムについて投入し直す |
| 同じプログラムに引数の違う解析のジョブが待機中・実行中 | `ANALYSIS_IN_PROGRESS`。`details.operation_id`でそのジョブが分かる |
| 解析の失敗、または解析中のサーバー停止 | 解析は巻き戻される（`output_state: absent`）。解析の確定後の失敗だけは`created`で、変更は適用済み・未保存 |

読み取り専用で開いた過去バージョンは解析できません（`READ_ONLY_PROGRAM`）。共有プログラムは先にチェックアウトが必要です（`CHECKOUT_REQUIRED`）。

同じローカル `.gpr/.rep` をサーバーで開く前に、Ghidra GUIで閉じてください。GUIとMCPを併用する場合は、[共有リポジトリに対する別々のローカルキャッシュ](shared-projects.ja.md)を使います。

<a id="long-calls"></a>

## 長い呼び出し

どの呼び出しも、クライアントを待たせるのは最大で約50秒です。多くのクライアントやプロキシが呼び出しに設ける60秒の期限（HTTPで接続したClaude Codeなど）の内側で返ります。

- `import_program`・`analyze_program`・`run_script`はバックグラウンドのジョブです。`wait_seconds`以内にジョブの記録を返し、1件ずつ実行されます。
- それ以外の呼び出しは、40秒たっても終わらなければ、`deferred: true`と`operation`のジョブの記録を返し、サーバー上で処理を続けます。結果は`operation.operation_id`で`get_operation`を呼んで受け取ります。`result`にはそのツールが返すはずだった値がそのまま入り（プログラムを扱うツールなら横に`source`も入ります）、失敗なら`operation_error`にそのツールのエラーが入ります。1件も読めなかった`batch_read`は、各項目のエラーを含む結果全体を`operation_error.result`に残します。同じツールを呼び直すと2回実行されるので、呼び直さないでください。40秒以内に終わる呼び出しの応答は今までどおりです。
- 同時に実行する呼び出しは40件までで、空いた実行枠は待っている呼び出しに到着順に渡します。その40秒のうちに空きの実行枠を得られなかった呼び出しは実行されず、再試行可能な`OPERATION_QUEUE_FULL`（`output_state: absent`）になります。`request_id`がある場合は、同じIDで送り直せば実行されます。
- Ghidraの起動中に届いた呼び出しも、起動を待つのは最大40秒で、その後は再試行可能な`LOCK_TIMEOUT`になります。
- 先送りした呼び出しの実行中に、同じtargetかprojectを使う呼び出しは`LOCK_TIMEOUT`になります。`details.operation_id`が、待つべき呼び出しを示します。
- `cancel_operation`は、待機中・実行中のジョブを止めます。まだプログラムを変更し始めていないジョブは、その場で`OPERATION_CANCELLED`で終わります。実行中のジョブは、次の取り消しの確認で巻き戻して終わります。先送りした呼び出しは取り消せません。
- サーバーは停止時に、実行中のジョブを取り消し、先送りした呼び出しの終了を待ってからプロジェクトを閉じます。SIGTERM・SIGINT（Ctrl+C）・SIGHUP（端末やsshの切断）のどれでもこの手順で止まり、終了コードは128にシグナル番号を足した値です。この後始末の間（起動中の手順の終了を待つ間も含む）に届いたシグナルは、プロジェクトを閉じ終わるまで待たせます。SIGKILLで止めると、後始末は行われません。

通常のツール呼び出しが実行枠を待っている間にクライアントが要求を取り消すと、ツールは実行されません。`request_id`がある場合は、記録が`failed`になり、`OPERATION_CANCELLED`と`output_state: absent`が残ります。同じIDの再送はこの取り消し結果を返すため、再試行には新しいIDを使います。すでに実行枠を得た呼び出しは、クライアントが要求を取り消してもサーバー上で続行します。

結果を読むには`get_operation`が要るため、先送りは`get_operation`を公開しているときだけ行います。
