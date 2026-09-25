# 長い処理のジョブ化の設計

2026-09-24。基準は、importと解析をジョブにした作業ツリー（未コミット）。**同日に実装した（第14節）。** [import_programの非同期化](import-program-jobs-design.ja.md)と[analyze_programのジョブ化](analyze-program-jobs-design.ja.md)の続き。同日、今回のリリースで長い処理をすべてジョブにする、と決まった。第10節の決めることも同日すべて決まった（先送りは40秒、HTTPとstdioの両方）。MCPのTasksとの関係は第13節にまとめた。

## 1. 結論

どのツール呼び出しも、応答まで最大50秒で返るようにする。そのために、処理を次の2種類に分ける。

| 種類 | 対象 | 動き |
| --- | --- | --- |
| キューのジョブ | `import_program`、`analyze_program`（実装済み）、`run_script`（新規） | 受付の順に1件ずつ実行する。応答は常にジョブの記録。停止時にキャンセルする |
| 先送りできる呼び出し | 上記と、記録を読むだけのツールを除く、すべてのツール | 今までどおりすぐ実行する。40秒で終わらなければ、応答をジョブの記録に切り替え、処理は続ける |

どちらの結果も`get_operation`で取得する。1本の待ち行列にすべてを並べる案は採らない。数秒で終わる読み込みまでが、1時間のスクリプトの後ろで待たされるからである。ツールごとにimportと同じ形のジョブにする案も採らない。ほぼ全ツールの応答の形が変わるうえ、プログラムの大きさに比例して遅くなる読み取りを取りこぼすからである。

あわせて、キューのジョブを取り消す`cancel_operation`を加え、`list_targets`をロック待ちしないようにする（第6節・第7節）。

## 2. 長くなり得る処理

調査の結果、上限のない処理はツールの大半に及ぶ。

| 分類 | ツール | 時間を決めるもの | 時間の上限 | 失敗・中断で残るもの |
| --- | --- | --- | --- | --- |
| スクリプト | `run_script` | スクリプトそのもの | `timeout_seconds`（既定300秒、最大3600秒）。monitorを見ないスクリプトは止まらない | programの変更は1つのtransaction。ファイル・通信・threadは戻らない |
| BSim（プログラム全体） | `bsim_register_target`、`bsim_query`（`scope=program`）、`bsim_apply_matches`、`bsim_update_target_signatures` | 関数の数×decompile、データベースの大きさ | なし | 登録・更新はSQLなら1 transaction。改名は失敗分を除いて確定する |
| BSim（その他） | `bsim_load_matched_executable`、データベースだけのツール | 通信、programを開く時間 | なし | 新しいセッション。キャッシュのprojectは残る |
| 共有project | 同期の10ツールすべて | リポジトリ全体のrefresh（読み取りでも実行）、転送量 | `get_version_diff`だけ60秒（完了後に判定） | checkout状態、`.keep`、開き直し失敗によるtargetの解除 |
| 読み込み・保存 | `open_program`、`load_project_program`、`save_project_program`、`close_session`（削除を含む）、`list_project_programs`、`create_project` | DBの大きさ、DBの更新、ファイルの数 | なし | 保存の失敗は前回の保存に戻る |
| 書き出し | `export_program` | DBの大きさ（`.gzf`は2回走査） | なし | `binary`は途中までのファイル |
| 編集 | `apply_edits`、`parse_c_declarations` | 変数の編集ごとに3回decompile、ヘッダの大きさ | 件数と長さだけ | 1つのtransaction |
| 読み取り | `decompile_function`、`batch_read`、`search_bytes`、`list_strings`（`filter`）、`list_functions`（`filter`）、`search_symbols`、`list_namespaces`、`get_xrefs`・`get_call_edges`のページ送りなど | 上限時間、またはプログラムの大きさ | decompile 120秒、batch_read 最大60秒。他はなし | なし |

どの処理にもサーバー側の期限はない。クライアントが待つのをやめても、threadは処理とロックを持ち続ける。そのため、再送すると`LOCK_TIMEOUT`になるか、同じ処理が2回走る。クライアントの呼び出し期限は第5.5節にまとめた。ドキュメントどおりにHTTPでつないだClaude Codeは60秒で切るので、今は60秒を超える呼び出しが失敗する。

## 3. 方針

- 応答は最大50秒で返す。キューのジョブの`wait_seconds`と`get_operation`は上限50秒のまま、先送りは40秒とする。
- 重く、プロセスやCPUを占有する処理だけをキューのジョブにする。importと解析はCPUとメモリを大きく使う。`run_script`はプロセス全体のscript barrierを排他で取るため、どのみち他の処理と並ばない。
- それ以外は先送りできる呼び出しにする。実行のしかた、ロック、エラーは今と同じで、40秒以内に終わる呼び出しの応答は変わらない。
- 記録・照会・停止時の扱いは、キューのジョブと共通の仕組みを使う（`OperationManager`）。
- ツールごとの切り替えフラグは設けない。

## 4. キューのジョブ：run_script

### 4.1 受付

Ghidraのロックを取らずに次を確かめ、誤りはjobを作らずにその場で返す。

- scriptのrootがない（`SCRIPTS_DISABLED`）、`script_id`が見つからない・曖昧（`SCRIPT_NOT_FOUND`、`AMBIGUOUS_SCRIPT`）、runtimeが使えない（`SCRIPT_RUNTIME_UNAVAILABLE`）。今もロックの前に確かめている項目で、受付に移す。
- targetにプログラムが読み込まれている（`PROGRAM_NOT_OPEN`。2026-09-25までは`SESSION_NOT_FOUND`）。今はscript barrierを取った後で分かる。解析と同じく、セッションの世代番号を記録する。

同じ引数の再送は、待機中・実行中のjobに合流する。引数の違うスクリプトは、同じtargetでも別のjobとして並ぶ（解析のような`*_IN_PROGRESS`は設けない）。引数の上限は、インラインの`source`（最大256 KiB）が入るよう、スクリプトだけ広げる。比較にはSHA-256を使い、`source`は実行まで記録に持つ。

### 4.2 実行

workerは今の経路（`ScriptService` → runtime → `RuntimeCoreExecution.call(exclusive=True)`）を通し、`OperationControl`を渡す。

- ロック（LockManager、script barrier、operation lock、target・project）を取った直後に`check_active`。
- 世代番号が違えば`SESSION_CHANGED`で、何も実行しない。runtimeの世代の確認は、今は常に行っている。これを、`expected_generation`がある場合だけに改める。エラー文の「nothing was analyzed」は、ジョブ全般の文に直す。
- 隔離とcheckoutの確認の後、スクリプトがprogramやbundleに手を付ける直前に`begin`。
- ジョブのmonitorを、スクリプトの`TimeoutTaskMonitor`の委譲先にする（今は`TaskMonitor.DUMMY`）。これで、`timeout_seconds`とキャンセルの両方がスクリプトに届く。
- ロックが空くのを待つ間は失敗させず、`waiting_for_lock`のまま待つ。`--script-queue-timeout-seconds`は1回の待ちの長さになり、ジョブの失敗にはつながらない。

### 4.3 結果と失敗

成功時の`result`は、今の`run_script`の結果と同じ形（`stdout`、`stderr`、`transaction_outcome`など、最大で約200 KB）。記録を一定の大きさに保つため、`result`が大きなときは、他のツールと同じく結果の保存先へ移し、記録には案内（`result_id`など）を入れる。

失敗時の`output_state`は、`transaction_outcome`から決める。

| `transaction_outcome` | `output_state` |
| --- | --- |
| `rolled_back`、`unchanged` | `absent` |
| `committed` | `created`（保存はされていない） |
| `unknown`（targetは隔離される） | `uncertain` |
| どれでも、`execution_state`が`invalid`（残ったthreadや解析が、巻き戻しの後もprogramを変え得る。targetは隔離される） | `uncertain` |

`output_state`はprogramの変更だけを表す。ファイル・通信などの外部への影響は分からない、とツール説明に書く。

失敗の詳細（`stdout`・`stderr`・例外）は、AIがスクリプトを直すのに要る。そのため、4 KiBを超えても捨てない。成功の`result`と同じく大きなものは結果の保存先へ移し、記録には`transaction_outcome`・`execution_state`・`output_state`と、保存先の案内を残す。今の同期の`run_script`も、大きなエラーは保存先へ移している。

### 4.4 停止時

停止時はスクリプトのmonitorをキャンセルする。monitorを確かめるスクリプトは巻き戻って終わる。確かめないスクリプトには、今と同じくロックの待ち時間（既定30秒）だけ待つ。それでも終わらなければ、今と同じく`close_all`はprojectを閉じずに進む。今の`close_all`は、実行中のスクリプトを止める手段がなく、30秒待って何も閉じずに諦めている。ジョブにすると、協調するスクリプトなら後始末まで終えられる。

### 4.5 スクリプト実行中のthread監視

実行中のスクリプトは、プロセス全体の`Thread.start`を監視し、許可した名前以外のthreadを迷子とみなしてtargetを隔離する。先送りの実行やジョブのworkerのthreadがスクリプトの実行中に起動すると、正常に終わったスクリプトのtargetまで隔離される。今の作業ツリーでも、同期のスクリプトの実行中にimportを受け付けると起こり得る。これらのthreadの名前を許可の一覧に加える。

## 5. 先送りできる呼び出し

### 5.1 動き

1. 呼び出しは、今と同じくすぐに実行する。
2. 40秒以内に終われば、今と同じ応答を返す（成功・エラー・大きな結果の案内とも同じ）。
3. 40秒で終わらなければ、ジョブの記録（`kind`はツール名、`state`は`running`）を返し、処理は続ける。終わった時点で、記録に結果かエラーを入れる。

ジョブの記録を作るのは、先送りした呼び出しだけとする。40秒以内に終わる呼び出しは、何も残さない。

### 5.2 応答の形

先送りの応答は、大きな結果の案内（`truncated: true`）と同じく、目印の項目で見分けられる形にする。

```json
{"deferred": true, "tool": "save_project_program", "target": "default", "operation": {"operation_id": "…", "kind": "save_project_program", "state": "running"}}
```

各ツールの出力スキーマに、この形を別案として加える。テキストの内容にも、「まだ実行中なので、`get_operation`で`operation_id`を確かめる」と書く。多くのクライアントはテキストしかモデルに渡さないためである。

### 5.3 結果の取得

`get_operation`の`result`には、そのツールが返すはずだった値がそのまま入る。一覧や文字列もあり得るので、記録の`result`は任意のJSONを許す。大きな結果は、通常の呼び出しと同じく結果の保存先へ移す。大きな結果をそのまま返す設定（`large_result_mode`がinline）では、記録に結果が残り続ける。そのため、記録に残す結果の合計に上限（結果の保存先と同じ128 MiB）を設け、超えたら古い記録から結果だけを捨てる。捨てた記録には、結果を失ったことを示す印を付ける。失敗なら、`operation_error`にツールのエラー（`code`・`message`・`hint`・`details`）が入る。`output_state`は付けない。何が残ったかは、ツールごとの今のエラーの詳細（同期の`partial_success`など）で分かる。

### 5.4 再送と同時実行

同じ引数の再送は、今と同じく、もう一度実行される。先送りの応答には`operation_id`があるので、応答を受け取ったクライアントは`get_operation`で追える。同じ呼び出しを1つにまとめると、`undo_program_change`を2つのクライアントがそれぞれ1回ずつ呼んだ場合に、1回しか戻らなくなる。そのため、まとめることはしない。

同時に走る呼び出しの数は、今のthread数の上限（40）で抑える。先送りした後も処理を続けている呼び出しは、その枠を使い続ける。枠が埋まっていると、新しい呼び出しは今と同じく空くまで待つ。この待ちは40秒に数えない。40件の長い呼び出しが同時に走るのはまれなので、ここは今の動きを保つ。

先送りした呼び出しがtargetやprojectのロックを持っている間に、別の呼び出しが同じtargetかprojectのロックを待って`LOCK_TIMEOUT`になったら、キューのジョブと同じく`details.operation_id`にその呼び出しの記録を示す。AIが再送したり別のツールを呼んだりしても、実行中の処理へ案内される。

### 5.5 40秒の根拠

先送りの応答は、クライアントが呼び出しを切る前に届かなければ意味がない。2026-09-24に確かめた期限は次のとおり。

| クライアント・経路 | 期限 |
| --- | --- |
| Claude Code（HTTP） | 最初の応答バイトまで、60秒・サーバーごとの`timeout`・`MCP_TIMEOUT`の最大。既定は60秒。このサーバーのHTTPはSSEを使わず、結果ができるまで何も送らない |
| TypeScript SDKの既定、nginxの`proxy_read_timeout`、AWSのロードバランサー | 60秒 |
| Codex | 300秒（`tool_timeout_sec`） |
| Claude Code（stdio） | 応答ごとの期限はない。全体は`MCP_TOOL_TIMEOUT`（既定約28時間）、応答も進捗もない状態は30分で切る。v2.1.212以降は、メインの会話で2分を超えた呼び出しを自分でバックグラウンドに回す |

最も多い期限は60秒なので、先送りは60秒より前でなければならない。60秒では、Claude Codeが切った後に応答が届く。間に合う上限は50秒（余裕10秒）で、40秒（余裕20秒）を採った。余裕は、要求を受けてから計り始めるまでと応答を送るまでに使う。

ロックの待ち時間の既定は30秒で、40秒はこれより長い。そのため、ロックが空かずに失敗する呼び出しは、先送りにならず、今と同じ`LOCK_TIMEOUT`で返る。運用者が`--lock-timeout-seconds`を40秒より長くした場合は、ロック待ちの途中で先送りになり得る。

### 5.6 対象外

記録を読むだけで、Ghidraに触れないツールは先送りしない。`get_operation`、`cancel_operation`、`read_result`・`search_result`（結果の保存先を読むツール）、ロックを取らなくなった`list_targets`（第7節）が該当する。MCP以外からの直接の呼び出し（テストなど）も対象外で、今のまま同期で返る。

### 5.7 停止時

先送りした呼び出しは、今の同期の呼び出しと同じく、停止時にキャンセルしない。今のtransportは、終了する前に実行中の呼び出しの完了を待っている。先送りの呼び出しは応答と切り離して動かすので、この待ちがなくなる。そこで、停止時は先送りの実行が終わるのを待ってから、`close_all`に進む。ロックを取る呼び出しなら`close_all`のoperation lockでも待てる。しかし、BSimのデータベースだけのツールはロックを取らないため、この待ちがないとJVMの停止中も走り続ける。

### 5.8 stdioにも入れる

stdioのClaude Codeは、長い呼び出しを自分でバックグラウンドに回して待つ（第5.5節）。そこへ先送りを入れると、Claude Codeが待つはずの呼び出しを、AIが`get_operation`で待つことになり、往復が増える。それでもstdioにも入れる。TypeScript SDKの既定（60秒）のままのstdioのクライアントでは、先送りがないと呼び出しが失敗するからである。失敗より、往復が増える方がよい。

## 6. cancel_operation

キューのジョブは受付の順に1件ずつ動く。1時間かかる誤ったスクリプトを受け付けると、後ろのジョブがすべて止まる。今の`run_script`にも、クライアントから止める手段はない。止まるのは、自分の`timeout_seconds`だけである。そこで、キューのジョブを取り消すツールを加える。

| ジョブの状態 | 動き |
| --- | --- |
| 待機中 | その場で終える。`state`は`failed`、codeは`OPERATION_CANCELLED`（新設）、`output_state`は`absent` |
| 実行中 | 停止時と同じくmonitorをキャンセルする。importのloaderの実行中など、キャンセルできない段階では、次の区切りで効く。結果は`OPERATION_CANCELLED`と、種類ごとの`output_state` |
| 終了済み・先送りの呼び出し | `VALIDATION_ERROR`で何もしない |

importの設計ではキャンセルのツールを見送った（[import_programの非同期化](import-program-jobs-design.ja.md)第4節）。見送ったのは、ジョブがimportだけで、停止時にしかキャンセルが要らなかったためである。スクリプトがキューに入ると、この前提が変わる。

## 7. list_targetsをロック待ちしない

`list_targets`は、各targetのロックを順に取って`ProgramSession.to_dict()`を読む。ジョブが1つでも実行中なら、30秒待って`LOCK_TIMEOUT`になる。`bsim_load_matched_executable`も、同じ呼び出しを内部で使うため失敗する。ジョブが増えると、最初に呼ぶべきこのツールがほぼ使えなくなる。

ロックが要るのは、`to_dict()`がGhidraからdomain pathを読むためである。そこで、セッションを開いたときにdomain pathを`ProgramSession`へ控え、`to_dict()`はその値を返すようにする。開いている間にdomain pathは変わらない。project名と場所はPythonの値である。これで`list_targets`はGhidraにもtargetのロックにも触れず、ジョブの実行中でもすぐに返る。

## 8. 公開契約と互換性

| 変更 | 非互換か |
| --- | --- |
| `run_script`の応答がジョブの記録になる。`request_id`・`wait_seconds`を受け取る | 非互換 |
| 先送りの応答の形が、すべての先送りできるツールの出力に加わる | 追加。ただし40秒を超える呼び出しは、今の結果ではなくジョブの記録を受け取る |
| `get_operation`の`kind`がツール名全般になる（`Literal`から文字列へ）。`result`が任意のJSONになる | 追加 |
| `cancel_operation`と`OPERATION_CANCELLED`を加える | 追加 |
| `list_targets`がロックを待たない | 挙動の改善。出力は同じ |

サーバーの案内文（上限1,900バイト、今は1,698バイト）に、「40秒で終わらない呼び出しはジョブの記録を返すので、`get_operation`で追う」の1文を加える。

## 9. 検証

| 観点 | 合格条件 |
| --- | --- |
| 先送り | 40秒以内に終わる呼び出しは、応答が今とバイト単位で同じ。遅い呼び出しは先送りの形で返り、処理は続き、`get_operation`で結果・エラー・大きな結果の案内を取れる |
| スキーマ | 先送りの形を含む全ツールの出力スキーマが検証を通り、MCPのtransport（stdio・HTTP）で実際の応答がスキーマに合う |
| 停止時 | stdioのEOFとSIGTERMの両方で、先送りの実行（ロックを取らないBSimのツールを含む）が終わってから`close_all`とJVMの停止に進む |
| 記録の大きさ | inlineの設定で大きな結果の記録が増えても、残す結果の合計が上限を超えない。捨てた記録にその印が付く |
| run_scriptのジョブ | 受付の即時の拒否、再送の合流、FIFO、`SESSION_CHANGED`、`output_state`、大きな`stdout`、停止時とcancelでの巻き戻し（実Ghidra）、monitorを見ないスクリプトでの停止の上限 |
| thread監視 | スクリプトの実行中に起動したジョブ・先送りのthreadで、targetが隔離されない |
| cancel_operation | 待機中・実行中・終了済み・先送りの各場合 |
| list_targets | ジョブの実行中でもすぐ返り、内容が今と同じ |
| 変異テスト | 主要な分岐を1つずつ壊し、テストが検出する |

## 10. 決めたこと

2026-09-24に、次のとおり決めた。

1. 方式：キューのジョブは`import_program`・`analyze_program`・`run_script`の3つとし、他はすべて先送りできる呼び出しにする。重いBSimの処理（登録・全体の検索・一括改名）もキューに入れる案は採らなかった。CPUの取り合いを避け、停止時に登録前でキャンセルできる利点はあるが、そのツールの応答が非互換になる。
2. 先送りの時間：40秒。60秒は、60秒の期限に間に合わない（第5.5節）。20秒にするとimportのジョブの既定と揃うが、ロック待ちで失敗する呼び出しまで、一度先送りの応答を返すようになる。
3. `cancel_operation`を加える。
4. `list_targets`をロック待ちしないようにする。
5. 先送りはHTTPとstdioの両方に入れる（第5.8節）。

## 11. 調査で見つかった別の問題

- `.gzf`の書き出しに未保存の変更が入るかどうか：コードの注記と説明は「保存済みの状態だけ」としている。一方、Ghidraの`BufferMgr.saveAs`は変更中のバッファも書く。実Ghidraで確かめ、説明を直す。
- [共有プロジェクト](shared-projects.md)は、pullが`UNSAFE_MERGE_REQUIRED`を返すと書いている。実際にクライアントが受け取るcodeは`MERGE_REQUIRED`である。
- BSimのエラーの多くは、`code`・`retryable`・`details`のない文字列だけで返る。先送りの記録でも、そのまま文字列だけになる。2026-09-25に直した。BSimのツールの入口（`BsimService`の11のメソッド）で、失敗をすべて`DomainError`にする。`code`はメッセージの先頭の`BSIM_...`で、`retryable`は`BSIM_DATABASE_UNREACHABLE`だけがtrueになる。次の手がメッセージにないコードには`hint`を付ける。メッセージは`BsimService`が自分で作り、認証情報を伏せているので、そのまま公開の文言にする（`presentation/error_mapper.py`）。ソースにあるBSimのコードがすべて`ErrorCode`にあることは、テストで確かめる。
- 停止時は、ジョブのworkerを期限なく待ち、その間はシグナルを保留する（importの設計で決めた方針）。ジョブにスクリプトが加わるため、第4.4節のとおりスクリプトだけは待つ時間に上限を付ける。

## 12. 対象外

- ジョブの永続化と再起動後の追跡。
- MCPのTasks（第13節）。
- 先送りの呼び出しのキャンセル。同期とBSimの転送は、Ghidraにキャンセル可能なmonitorを渡せば巻き戻せる（checkout・add・checkin）。ただし、今回は扱わない。
- projectごとにキューを分ける並列実行。キューに入るのが重い3種類だけなら、今は1本で足りる。
- 進み具合の報告（何%まで進んだか）。

## 13. MCPのTasksとの関係

MCPには、長い処理をクライアントに待たせる仕組みとしてTasksがある。2025-11-25版では本体の実験的な機能だったが、2026-07-28版で本体から外れ、拡張`io.modelcontextprotocol/tasks`（SEP-2663）になった。仕様・スキーマ・TypeScriptのパッケージ（`@modelcontextprotocol/ext-tasks`）は[ext-tasks](https://github.com/modelcontextprotocol/ext-tasks)にある。

| 項目 | 内容 |
| --- | --- |
| 動き | サーバーは`tools/call`に、結果の代わりにタスク（`CreateTaskResult`）を返せる。クライアントが`tasks/get`で状態と結果を取り、`tasks/cancel`で取り消す。待つのはクライアントで、AIではない |
| 決め方 | タスクにするかどうかは、サーバーが呼び出しごとに決めてよい。ただし、その要求で拡張への対応を示したクライアントにしか返してはならない（MUST NOT） |
| 旧版との互換 | 2025-11-25版の実験的なTasksとは、通信の形に互換がない |

2026-09-24時点の対応状況は次のとおり。

| 対象 | 状況 |
| --- | --- |
| Claude Code | 対応なし。HTTPのサーバーとは既定で2026-07-28版で接続するが、変更履歴にTasksの記載がなく、対応の要望は実装されないまま閉じられている |
| Codex | 対応なし。リポジトリにTasksを使うコードがない |
| VS Code（Copilot） | 2025-11-25版の旧Tasksだけ |
| ChatGPT | 対応の要望が出ている段階 |
| Python SDK 2.2.0 | 2026-07-28版は話せるが、Tasksの実装はない。低レベルの`Server.add_request_handler`で`tasks/*`を足せる。ツールの呼び出しにタスクを返す経路（`on_call_tool`の型は`CallToolResult`）が通るかは未確認 |

今回は取り入れない。主なクライアントが対応しておらず、入れても使われないからである。パッケージもTypeScript向けで、そのままは使えない。

ただし、この設計はTasksとよく噛み合う。「40秒で終わらなければ切り替える」は、サーバーが呼び出しごとにタスクにするか決める、という拡張の決め方そのものである。記録の項目もほぼそのまま対応する。

| ジョブの記録 | Tasks |
| --- | --- |
| `operation_id` | `taskId` |
| `state`（`queued`・`running` / `succeeded` / `failed`） | `status`（`working` / `completed` / `failed`・`cancelled`） |
| `poll_after_ms` | `pollIntervalMs` |
| `result`・`operation_error` | 終わった`tasks/get`の`result`・`error` |
| `cancel_operation` | `tasks/cancel` |

CodexかClaude Codeが対応したら、拡張への対応を示したクライアントにはタスクを返し、それ以外には今の先送りの応答を返す入口を、同じ`OperationManager`の上に足す。そのときは、ext-tasksのJSON Schemaに合わせ、TypeScriptのパッケージのクライアント側の部品を動作確認に使う。

## 14. 実装

2026-09-24に実装した。設計からの差分と、実装で決めた点は次のとおり。

| 項目 | 実装 |
| --- | --- |
| 先送り | `presentation/deferred_calls.py`。同期のツール呼び出しをanyioのworker threadで実行し、40秒で終わらなければ`OperationManager.defer_call`で記録を作って応答する。thread・応答・記録のどれに結果を渡すかは、呼び出しごとの小さな状態機械（pending・running・finished・abandoned）が1つのロックで決める。取り消された要求の呼び出しは、threadが始まる前なら実行しない |
| 同時実行の上限 | 呼び出しの枠は40のまま、`threading.BoundedSemaphore`で数える。先送りした呼び出しも終わるまで枠を使う。anyioの既定のthread上限は、この呼び出しには使わない（二重に数えないため） |
| 記録の結果 | 先送りした呼び出しのthreadが、要求が返すはずだった`CallToolResult`を作り（出力スキーマの検証も同じ）、その`structuredContent`から`result`か`operation_error`を記録する。大きな結果は、通常の呼び出しと同じく結果の保存先への案内になる |
| 対象 | `ToolSpec.deferrable`（ジョブのツールと`list_targets`以外）。`get_operation`が公開されていなければ先送りしない。出力スキーマの別案は約400文字で、全ツールを公開したtools/listが約2.9万文字（9.7%）増えた |
| 停止時 | `OperationManager.tracked_call`が、threadで動く呼び出しを数える。`shutdown`は、ジョブのworkerの後に、この数が0になるまで待つ |
| ロック待ちの案内 | `lock_holder`が、実行中のジョブに加えて、実行中の先送りの呼び出しも対象にする |
| run_scriptの受付 | `ScriptService.prepare_run`。カタログ・runtime・引数・タイムアウトを確かめ、インラインの`source`は書き出さずに検査だけする。予約は（種類、project、domain path、世代、引数の指紋）で、同じ引数の再送だけが合流する |
| run_scriptの開始 | ジョブの`begin`は、スクリプトのtransactionが始まる直前に呼ぶ。core commandに`on_begin`を渡し、ハンドラが`begin_command`の依存を通して呼ぶ。隔離・`expected_revision`・開いたままのtransaction・解析中の確認で断った失敗は、`output_state`が`absent`になる |
| run_scriptの失敗 | `output_state`は`transaction_outcome`から決める。transactionが始まった後で終わり方が分からない失敗は`uncertain`。詳細は4 KiBで切らず、`OperationManager.present`（`presentation/operation_presentation.py`）が大きな結果・エラーを結果の保存先へ移す |
| 記録の大きさ | 記録が持つ結果とエラーの合計を数え、128 MiBを超えたら古い記録から捨てて`result_discarded: true`を付ける |
| cancel_operation | まだ`begin`していないジョブは、workerがロックを待っていても、その場で`OPERATION_CANCELLED`（`absent`）で終える。workerはロックを得た後に`check_active`・`begin`で断る。`begin`後はmonitorをキャンセルする。`get_operation`がなければ公開しない |
| 停止時のスクリプト | 実行中のスクリプトは、monitorをキャンセルした後、`--lock-timeout-seconds`だけ待つ。monitorを見ないスクリプトは待たずに進む |
| list_targets | `ProgramSession`が開いた時点のproject名・場所・domain pathを控え、`to_dict()`はGhidraを呼ばない。`list_targets`はregistryのロックだけで答える。スクリプトの実行後は、名前の変更に備えてdomain pathを読み直す |
| thread監視 | ジョブのworker（`ghidra-jobs`）を許可の一覧に加えた。先送りの呼び出しはanyioのworker threadで動くので、元から許可されている |
| 文書の誤り | 共有プロジェクトの`UNSAFE_MERGE_REQUIRED`を、クライアントが受け取る`MERGE_REQUIRED`に直した |

`.gzf`の書き出しに未保存の変更が入るかどうか（第11節）は、実Ghidra（12.1.3）で確かめた。保存していないコメントを付けて書き出し、別のprojectへ取り込むと、そのコメントが残っていた。つまり未保存の変更も入る。「保存済みの状態だけ」としていたツール説明とコードの注記を直した。

### レビューで直した点

実装後のレビューで、次の7点を見つけて直した。

| 問題 | 直し方 |
| --- | --- |
| JPypeは、Javaを初めて呼んだPythonのthreadを`Thread-N`という名前のdaemon threadとしてJVMにつなぐ。スクリプトの実行中にサーバーのthreadがそうなると、スクリプトが残したthreadとみなされ、targetが隔離される（実Ghidraで再現した） | ツール呼び出しと受付のthreadは、最初のJava呼び出しの前に、Pythonの名前のままJVMにつなぐ（`attach_server_thread`）。スクリプトのJava側のthread比較は、サーバーのthread名（`_SERVER_THREAD_RE`）を除く。受付の`loaded_program`は、控えたdomain pathを読み、Javaを呼ばない。`cancel_operation`は、JVMを起動したイベントループのthreadで動かす |
| 任意の`target`を持つツール（`bsim_load_matched_executable`）が先送りされると、`target`が`null`になり、応答も記録もスキーマに合わなかった | `target`がなければ空文字にする |
| checkoutの確認が、未変更で未登録のプログラムを開き直すと世代が変わり、待機中のジョブが理由なく`SESSION_CHANGED`になった | この内部の開き直しでは世代を引き継ぐ（`carry_generation`） |
| 引数の大きさをASCIIのJSONで測っていたため、日本語を含む有効な`source`が拒否された | UTF-8で測る。上限は、JSONのエスケープで膨らんだ256 KiBの`source`と64 KiBの`args`が収まる1 MiBにした |
| `execution_state`が`invalid`でも、巻き戻していれば`absent`と報告していた | `uncertain`にする |
| targetを持たない先送りの呼び出し（BSimのデータベースだけのツールなど）も、ロックを持つものとして案内していた | targetを持つ呼び出しだけを案内の対象にする |
| monitorを見ないスクリプトの停止時の待ちについて、注記が実際より多くを約束していた | 注記を直した。`close_all`は、スクリプトが使っていないprojectを閉じて進む。ただしプロセスは、スクリプトが終わるかシグナルを受けるまで終われない（今までと同じ） |

### 検証

| 対象 | 結果 |
| --- | --- |
| JVMを使わないテスト | 1,826件成功、243件スキップ。新しく`tests/test_script_operations.py`、`tests/test_deferred_calls.py`、`tests/test_deferred_transport.py`（stdioとHTTPの実際のtransport。stdioのEOFで先送りの呼び出しを待ってから閉じることを含む）を加えた |
| 実Ghidra | `GHIDRA_RUNTIME_VALIDATION=1`と`GHIDRA_RUNTIME_BINARY_PATH=/bin/ls`で`tests/test_runtime_*.py`を実行し、449件成功、44件スキップ、1件失敗、6分35秒。失敗はGhidra Serverが必要な共有projectの1件（`GHIDRA_RUNTIME_SHARED_PROJECT_LOCATION`が未設定）で、変更の前から同じ。新しい`tests/test_runtime_long_calls.py`は、実行中のスクリプトを`cancel_operation`で巻き戻すこと、先送りの呼び出しが直接の呼び出しと同じ結果を返すこと、名前を付けてつないだthreadがスクリプトの実行中にtargetを隔離しないこと（名前のないthreadでは隔離される対照を含む）を確かめる |
| tools/list | 全ツールを公開して30.4万文字。先送りの別案は74ツールで約2.9万文字（9.7%）。2026-09-25に、全ツールに共通する応答（保存した結果の通知、先送りの応答、エラーなど）を`tools/list`では短い形にした（完全な形は`ghidra://docs/tools/{tool}`）。全ツールとscriptsを公開して約15.9万文字、既定のプロファイルで約11.1万文字になった |
| サーバーの案内文 | 全ツールを公開して1,829バイト（上限1,900） |
