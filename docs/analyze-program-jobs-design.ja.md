# analyze_programのジョブ化とloadの自動解析廃止の設計

2026-09-24。基準: `3c8e684`（main）とimportジョブ化の作業ツリー。**2026-09-24に実装した。実装で決めた点と検証の結果は第12節。** [import_programの非同期化と結果追跡の設計](import-program-jobs-design.ja.md)の続きとして、同じジョブ管理を解析へ広げる。

## 1. 結論

Ghidraの自動解析を実行する場所を、importジョブ（既定で解析する）と`analyze_program`の2か所だけにし、どちらもバックグラウンドのジョブにする。`load_project_program`・`open_program`（起動時のセッションを含む）は解析を行わず、常にすぐ返す。未解析なら応答の`is_analyzed=false`で知らせ、`analyze_program`へ誘導する。

これで、解析の終わりまでMCPの呼び出しが返らない経路はなくなる。ただし、解析以外にも長くかかり得る同期の操作は残る（第11節）。loadの挙動が変わる破壊的変更なので、1つのリリースにまとめて入れる。

## 2. 変更前の状態

解析は次の3か所で走る。importジョブ以外は同期処理で、クライアントの呼び出し期限（Codexの公開実装で300秒）に当たり得る。

| 経路 | 現在の挙動 | 根拠 |
| --- | --- | --- |
| `import_program` | ジョブ内で解析し保存する（既定） | [operations.py](../src/ghidra_mcp/application/services/operations.py) |
| `analyze_program` | coreコマンドとして同期実行。`force=true`で再解析。保存しない（未保存の変更として記録） | [mutating_symbols.py](../src/ghidra_headless/handlers/commands/mutating_symbols.py)、[core_helpers.py](../src/ghidra_headless/handlers/core_helpers.py)の`_analyze_program` |
| 初回load | 未解析かつ書き込み可能なら、targetとプログラムの組ごとに1回だけ解析し保存する | [target_lifecycle.py](../src/ghidra_mcp/infrastructure/ghidra_adapter/runtime/target_lifecycle.py)の`_analyze_program_on_first_load_locked` |

初回loadの解析は`_initialize_opened_session_locked`から呼ばれ、次の4経路で起こり得る。

- `open_program`（`create_session`）。起動時の`--session`・`--domain-path`もこの経路
- `load_project_program`
- セッションの差し替えに失敗したときの、元のセッションの復旧
- プログラム削除の前に同期状態を確かめるための開き直し

checkout・pullなど同期操作の後の開き直しは別の経路（`_run_with_reopened_program_locked`）で、解析しない。共有projectでcheckoutしていないプログラムは、load時の解析が見送られ、記録も残らない。checkout後も解析されないため、現状でも利用者が`analyze_program`を呼ぶ必要がある。

既存のコードも、隠れた長時間解析を避ける方針をとっている。decompilerのシンボルが必要な編集では、解析を勝手に始めず`PROGRAM_NOT_ANALYZED`で`analyze_program`を案内する（core_helpers.pyの注記）。loadの自動解析だけがこの方針の例外になっている。

## 3. 方針

- 解析はimportジョブと`analyze_program`ジョブの2か所だけで行う。
- `analyze_program`は、既存のジョブ管理に種類（`kind`）を1つ足して実装する。受付、待機、記録、再送、停止時のキャンセルはimportと同じ仕組みを使う。
- load系の操作は解析しない。応答に解析状態を含める。
- 解析の結果は、これまでの`analyze_program`と同じく保存しない。挙動の変更を「非同期になること」に絞る。
- ワーカーは1本のまま、importと解析を受け付けた順に実行する。解析はCPUとメモリを大きく使うため、並列にはしない。

## 4. 公開契約

### 4.1 analyze_program

| 引数 | 内容 |
| --- | --- |
| `target` | 解析するプログラムを読み込んでいるtarget |
| `force` | 既定false。trueなら解析済みでも再解析する |
| `request_id` | 任意のUUID。importと同じ意味 |
| `wait_seconds` | 既定20秒、上限50秒。importと同じ意味 |

応答はimportと同じジョブの記録で、`kind="analyze_program"`となる。成功時の`result`は次の形とする。

```json
{"program": "/sample.bin", "analyzed": true, "forced": false}
```

`analyzed=false`は、解析済みで`force=false`だったため何もしなかったことを示す（現在の戻り値と同じ意味）。解析の結果は保存しない。保存は`save_project_program`で行う。

`get_operation`の出力の`kind`は`Literal["import_program", "analyze_program"]`に広げる。記録の他の項目は変えない。

### 4.2 load_project_program・open_program

- どちらも解析を行わない。
- 応答に`is_analyzed`（真偽値）を追加する。名前は`get_program_info`の同じ項目に合わせる。
- ツール説明に、`is_analyzed=false`なら関数一覧やdecompileの前に`analyze_program`を実行することを書く。

### 4.3 エラーコード

importジョブ用に追加したコードのうち、次の4つは解析ジョブにもそのまま当てはまる。公開後に名前を変えると互換性をもう一度壊すことになるので、importジョブを最初に公開するリリースで、ジョブ共通の名前へ改めた（2026-09-24）。

| 旧 | 新 |
| --- | --- |
| `IMPORT_QUEUE_FULL` | `OPERATION_QUEUE_FULL` |
| `IMPORT_SHUTDOWN` | `OPERATION_SHUTDOWN` |
| `IMPORT_WORKER_UNAVAILABLE` | `OPERATION_WORKER_UNAVAILABLE` |
| `IMPORT_WORKER_FAILED` | `OPERATION_WORKER_FAILED` |

`IMPORT_IN_PROGRESS`・`IMPORT_OUTPUT_UNCERTAIN`・`TARGET_REBOUND`はimport固有として残す。解析には`ANALYSIS_IN_PROGRESS`（同じプログラムに引数の違う解析jobが待機中・実行中）を追加する。待機中にtargetが別のプログラムへ切り替わった場合は、既存の`SESSION_CHANGED`を使う。

## 5. 受付と実行

### 5.1 受付

受付はGhidraのロックを取らず、登録情報だけを読む。importの受付と同じ専用のthread枠で動かす。

1. targetにプログラムが読み込まれていなければ`PROGRAM_NOT_OPEN`（targetが登録されていなければ`TARGET_NOT_REGISTERED`。2026-09-25まではどちらも`SESSION_NOT_FOUND`）、過去バージョンを読み取り専用で開いていれば`READ_ONLY_PROGRAM`を即時に返す。
2. セッションの世代番号と、読み込み中のプログラムのdomain pathを記録する。世代番号は、`ProgramSession`が作成時に持つ通し番号とする。セッションを作る・開き直すと必ず新しいオブジェクトになるため、番号も必ず変わる。portには、project key・domain path・世代番号をまとめて返す`loaded_program(target)`を追加する。
3. 予約の資源キーは`(project key, domain path, 世代番号)`とする。同じ引数の再送は同じjobを返し、引数が違えば`ANALYSIS_IN_PROGRESS`とする。当初はimportの出力予約と同じ辞書で管理する案だったが、実装レビューで2つの問題が見つかり改めた（第12節）。
4. checkoutの要否など、共有projectの状態確認はリポジトリへの通信を伴い得るため、受付では行わない。実行時の確認に任せる。

### 5.2 実行

ワーカーは既存のcoreコマンドの実行経路を通し、quarantine、checkoutの要否、未保存の変更の記録という既存の検査をすべて保つ。解析用に次の3点を足す。

- **世代の確認:** targetとprojectのロックを取った後に、記録した世代番号と現在の世代番号を比べる。違えば`SESSION_CHANGED`で何もせずに終える。importの`TARGET_REBOUND`と同じ考え方で、待機中にreload・close・別プログラムのloadがあったとき、取り違えて解析しないためである。
- **停止の確認:** importと同じく、ロック取得後に`check_active`、解析の直前に`begin`を呼ぶ。
- **キャンセル:** セッションの`FlatProgramAPI`はキャンセルできないmonitorで作られている（`core_runtime.py`）。解析の呼び出しの間だけ、キャンセル可能なmonitorを持つ`FlatProgramAPI`を作って使う。monitorはコマンドの引数に混ぜず、実行コンテキスト経由で渡す。`analyzeAll`の後にmonitorを確認し、キャンセルされていれば解析済みの印を付けずに例外にする。解析はtransactionの中で動くので、例外で変更はすべて巻き戻る。

ロック取得のタイムアウトで実行を始められなかった場合は、importと同じく失敗にせず、`waiting_for_lock`のまま待ち続ける。

### 5.3 失敗時の出力状態

解析の変更は1つのtransactionにまとまっているため、例外で失敗すれば変更は残らない。`output_state`の判定はimportの枠組みを流用する。

| 状況 | `output_state` |
| --- | --- |
| 実行前の失敗（`SESSION_CHANGED`、checkoutが必要、停止など） | `absent` |
| 解析中の例外・キャンセル（transactionは巻き戻る） | `absent` |
| transactionの確定後の失敗（未保存の変更の記録など） | `created`（変更は適用済み。保存はされていない） |

### 5.4 ロック待ちの案内

解析jobの実行中は、そのtargetのロックをjobが持ち続ける。同じtargetへの他の操作は、従来どおり`LOCK_TIMEOUT`になる。このとき`details.operation_id`に、そのtargetで実行中のjobのIDを付ける。エージェントは、何の完了を待てばよいかを`get_operation`で確認できる。importジョブの実行中にも同じ案内が付く。

## 6. loadから解析を外す影響

- `_initialize_opened_session_locked`から解析を外す。第2節の4経路がすべて解析しなくなる。
- 解析済みの組を覚えておく`analyzed_loads`（`RuntimeSessionStore`とその利用箇所で約20か所）は不要になるため削除する。使われていない`_analyze_program_if_needed`も削除する。
- 起動時の`--domain-path`で未解析のプログラムを指定しても、起動処理の中で解析しなくなる。[起動時間の設計](startup-latency-design.ja.md)の目的とも合う。
- 共有projectの手順は変わらない。checkoutしてから`analyze_program`を実行する。これまでは同じプログラムを別のtargetで初めて開いたときに解析が走ることがあったが、それもなくなる。[共有プロジェクト](shared-projects.ja.md)に手順を明記する。
- 未解析のままのプログラムに`list_functions`などを使うと、関数がほとんど見つからない。load応答の`is_analyzed`、`get_program_info`、ツール説明で案内する。

## 7. 互換性とリリース

変わるのは次の4点で、いずれも既存の利用者から見える。

- `analyze_program`の戻り値が、解析結果からジョブの記録に変わる。
- `analyze_program`はregistryのツールになるため、`target`が必須になる（coreのツールにあった既定値`default`はなくなる）。
- load系の操作が解析しなくなる。これまで「loadすれば解析済みになる」ことに頼っていた手順は、`analyze_program`を足す必要がある。
- load系の応答に`is_analyzed`が加わる。追加だけで、既存の項目は変えない。

importジョブ化もまだ公開前であれば、両方を同じメジャーリリースにまとめることを勧める。破壊的変更を利用者に2回求めずに済み、第4.3節のエラーコード名も1回で決められる。

## 8. 前提となる修正

停止時にjobの解析をキャンセルして巻き戻す処理は、終了処理が最後まで動くことが前提である。[起動時間の設計](startup-latency-design.ja.md)の第6節によると、stdioで起動したサーバーは、JVMの起動後にSIGTERMのハンドラをJVMに置き換えられ、終了処理が途中で打ち切られる。HTTP（Docker）とstdioのEOFでは問題は起きない。

この不具合はimportジョブにも当てはまる。stdioでSIGTERMを受けると、解析途中のプログラムの削除とprojectのcloseが行われない。importジョブを公開するリリースで直した（2026-09-24）。修正は2つからなる。

- JVMの起動直後に、SIGTERMのハンドラを登録し直す（同節の案）。
- 後始末の後は、exitハンドラ（JVMの停止を含む）を実行し、Pythonのthreadの終了を待たずにプロセスを終える。stdioのtransportはstdinを非daemonのthreadで読む。stdinが開いたままSIGTERMを受けると、このthreadが戻らず、登録し直しただけではプロセスが終わらなかった。

実JVMのテストで、遅くした`close_all`が最後まで走り、SIGTERMの2.03秒後に終了コード143で終わることを確かめた。どちらの修正を外してもテストは失敗する（登録し直さないと0.39秒で打ち切られ、threadを待つと終わらない）。

実装レビューを受けて、さらに3点を直した。threadを待たずに終えるかどうかは、SIGTERMを受けたかどうかで決める（後始末の一部が例外を出しても、ログを残して143で終える）。ハンドラが例外を送出するのは最初の1回だけにした。起動時のスクリプト確認が、SIGTERMを確認の失敗として握りつぶさないようにした。

修正前からある次の3点は、今回は直さない（2026-09-25に3点とも直した。[importの設計](import-program-jobs-design.ja.md)の第7節を参照）。stdinが開いたままのSIGINTは、後始末に入らない（asyncioのSIGINT処理がmain taskをキャンセルし、stdinを読むthreadの完了を待つ）。SIGHUPはJVMが処理し、後始末をせずに終了する。JVMの作成からGhidraの初期化が終わって登録し直すまでの数秒間に届いたSIGTERMは、JVMが処理する。

## 9. 検証

| 観点 | 合格条件 |
| --- | --- |
| 受付 | セッションなし・読み取り専用を即時に拒否する。Ghidraのロックを取らない |
| 再送・重複 | 同じ引数の再送は同じjob。同じプログラムに引数の違う解析は`ANALYSIS_IN_PROGRESS` |
| 世代の確認 | 待機中にreload・close・別プログラムのloadがあれば`SESSION_CHANGED`。何も解析しない |
| 既存の検査 | quarantine、checkoutが必要、読み取り専用がジョブの中でも同じエラーになる。成功後は未保存の変更として記録される |
| キャンセル | 停止時に解析が止まり、transactionが巻き戻る。解析済みの印も関数も残らない（実Ghidra） |
| ロック待ち | 他の操作の`LOCK_TIMEOUT`に、実行中のjobの`operation_id`が付く |
| load | load・open_program・起動時・復旧・削除前の開き直しのいずれでも解析しない。`is_analyzed`が正しい |
| 既存テスト | 初回loadの解析を前提にした単体テストと実Ghidraテストを、`analyze_program`ジョブを使う形に直す |

## 10. 決めたこと

次の3点は、2026-09-24に案のとおりと決めた。

1. 解析の結果を保存しない（現在の`analyze_program`と同じ）。保存する案もあるが、利用者の編集もまとめて保存されてしまう。正常終了時とセッションを閉じるときには、未保存の変更は従来どおり保存される。
2. 第4.3節のエラーコード名の変更を、importジョブを公開するリリースで先に行う。
3. 第8節のSIGTERMの修正を、importジョブを公開するリリースに含める。

## 11. 対象外の長い処理

この設計でジョブになるのは解析だけである。2026-09-24、今回は解析系に限ると決めた。次の操作は同期のまま残り、大きなプログラムや遅い環境ではクライアントの呼び出し期限に当たり得る。

| 操作 | 長くなる理由 | 時間の上限 |
| --- | --- | --- |
| `run_script` | スクリプトの実行時間そのもの | `timeout_seconds`（既定300秒、最大3,600秒）。既定値はCodexの呼び出し期限と同じ |
| `bsim_register_target`、`bsim_query`（`scope=program`）、`bsim_apply_matches` | プログラム全体の関数について署名を作り、データベースを検索する | なし |
| `add_project_program_to_version_control`、`commit_project_program`、`pull_project_program`、`checkout_project_program` | Ghidra Serverとの間でプログラム全体を送受信する | なし（通信の期限に依存） |
| `export_program` | 大きなプログラムを`.gzf`へ書き出す | なし |
| `load_project_program`、`save_project_program`、`close_session` | 大きなプログラムの読み込み・保存。読み込み時のデータベース更新を含む | なし |
| `decompile_function` | 1関数のdecompile | 120秒 |
| `batch_read`、`get_version_diff` | 読み取りの時間予算・差分計算 | 60秒 |

上限のある操作は、単独ではCodexの300秒を超えない。問題になり得るのは上限のない操作と`run_script`である。次に扱う候補は`run_script`で、既定の実行時間の上限がクライアントの期限と同じため、最も期限に当たりやすい。スクリプトはプログラムを書き換え、失敗時の隔離（quarantine）も伴うため、ジョブ化には解析とは別の設計が要る。BSimの全体処理と共有projectの送受信は、利用頻度を見て判断する。

## 12. 実装

2026-09-24に実装した。設計からの差分と、実装で決めた点は次のとおり。

| 項目 | 実装 |
| --- | --- |
| ジョブ管理 | `import_operations.py`を`operations.py`（`OperationManager`）に改め、importと解析で1つの待ち行列とworkerを共有する。種類ごとに違うのは、受付・実行・結果の形・失敗後の出力状態・予約の解放だけ。workerのthread名は`ghidra-jobs` |
| 世代番号 | `ProgramSession`に作成時の通し番号（`serial`）を持たせ、`RuntimeSessionStore.session_generation`で読む。open・reload・reopenはどれも新しいセッションを作るので、番号を増やす箇所を1つずつ追う必要がない。portは`session_generation(target)`の代わりに、受付に要るproject key・domain path・世代をまとめて返す`loaded_program(target)`とした |
| 世代の確認 | core実行の経路（`RuntimeCoreExecution.call`）で、ロック取得の直後に`check_active`を呼び、project keyと世代を比べる。待機中にtargetが閉じられた場合も`SESSION_CHANGED`にする |
| monitor | `core.execute`の`task_monitor`引数でスレッドの実行コンテキストへ置き、`analyze_program`のハンドラは`current_task_monitor`という依存として受け取る。`_analyze_program`には引数で渡るので、JVMなしのテストでも確かめられる |
| ロック待ちの案内 | `tool_dispatcher`で、ジョブがロックを持っている間の`LOCK_TIMEOUT`に`details.operation_id`とhintを付ける。target・projectのロックでは同じtargetか同じprojectのジョブ、runtimeとscript barrierのロックでは実行中のジョブを対象にする。ジョブがロックを持つかどうかは、ロック取得の直後に呼ばれる`check_active`で記録する |
| 予約 | importは「project key・名前」、解析は「project key・domain path・世代番号」を種類ごとの予約にする。種類の違うjobは互いを止めない（workerが1本なので同時には動かない）。同じ辞書で両方を管理すると、後始末を確認できなかったimportが名前を予約し続け、そのプログラムの解析まで`IMPORT_OUTPUT_UNCERTAIN`で拒否された。世代番号をキーに入れないと、再読み込みの後の新しい要求が、`SESSION_CHANGED`で終わる古いjobに合流した |
| 失敗後の出力状態 | 解析の失敗は`absent`。transactionの確定後の失敗だけ`created`（`output_created=true`）。解析のジョブは、失敗しても予約を残さない |
| 解析済みの判定 | `force=false`で解析を省く条件を、`shouldAskToAnalyze`から`is_analyzed`と同じ"Analyzed"の印に改めた。`shouldAskToAnalyze`は、Ghidraの「今後確認しない」を選んだプログラムでも偽を返すため、`is_analyzed=false`なのに解析されない状態が残った |
| 受付と開き直し | 受付はtargetのロックを取らないため、reload・checkout・pullが開き直している最中の閉じたセッションに当たることがある。この場合は再試行できる`SESSION_CHANGED`を返す |
| load | `_initialize_opened_session_locked`から解析を外し、`analyzed_loads`と`_analyze_program_if_needed`を削除した。load・open・reloadの応答に`is_analyzed`を加えた。判定は`get_program_info`と共通の関数にした |
| 公開契約 | `analyze_program`はregistryのツールになり、`request_id`と`wait_seconds`を受け取る。registryのツールなので`target`が必須になった（coreのツールにあった既定値`default`はない）。`bsim_register_target`の説明とBSimのドキュメントに、未解析なら先に解析するよう書き足した |

### 検証

| 観点 | 結果 |
| --- | --- |
| JVMなしのテスト | 1,789件成功、237件スキップ（実Ghidraが必要なもの） |
| 実Ghidra | `GHIDRA_RUNTIME_VALIDATION=1`と`GHIDRA_RUNTIME_BINARY_PATH=/bin/ls`で`tests/test_runtime_*.py`を実行し、443件成功、44件スキップ（Jython・BSim・PEの検体が未設定）、6分2秒。Ghidra Serverが必要な共有projectの1件は対象外。loadが解析しないこと、ジョブでの解析・保存・開き直し、停止時のキャンセルとtransactionの巻き戻し、stdioのSIGTERMを含む |
| 変異テスト | 解析ジョブとSIGTERMの修正に24種の変異を当て、すべて検出した。初回は3種（世代の確認、キャンセルの登録、閉じたtargetの判定）を見逃したため、待ち行列にいる間の差し替えと、monitor経由の停止を確かめるテストを足した |
| 独立レビュー | 契約と文書、並行処理、SIGTERMの3観点で行った。契約と文書の12件はすべて直した。並行処理の6件は4件を直し（予約の分離と世代、解析済みの判定、開き直し中の受付）、2件は既存の方針どおりとした（停止中の失敗をキャンセルとして報告する点、停止を待つ間のシグナルの保留）。SIGTERMの5件は3件を直し（後始末が失敗してもthreadを待たずに終える、ハンドラを1回だけにする、起動時の確認）、2件は第8節のとおり別途直す |
