# Fable相談 第1回（受信した回答）

2026-09-21。Claude Code 2.1.278 / `claude-fable-5-1` / effort high。設計書のみを入力し、ツールは無効。設計判断の参考資料であり、すべての提案を採用したものではありません。採否と現在の推奨は[相談記録](../../project-worker-fable-consultation.ja.md)を参照。

---

# Mecha Ghidra 並列化設計レビュー（設計書本文のみに基づく）

前提の明示: 以下は提示された設計書の記述だけを根拠にしています。現行コード・Ghidra同梱ソース・MCP SDKの実装は確認しておらず、性能数値も測定していません。設計書中の「現行はこうなっている」という記述は設計者の記録として扱い、それとの突き合わせは相談元で行ってください。実機probeが必要な事項は(5)に分離しました。

---

## (1) 全体評価

方針は妥当です。「1 project = 1常駐プロセス」「Javaオブジェクトを越境させない」「親にJVMを置かない」「同一project内は直列のまま」「自動再実行・自動killをしない」「既存80ツールの契約を維持」という骨格は、確定要件と整合しており、fork不可というJPypeの制約にも合っています。障害時の「実行結果不明」を第一級の状態として扱っている点、H2の解放経路を公開APIに限定して未検証と明記している点も良いです。

一方で、以下の傾向があります。

- **複数資源を同時に取る操作が3種類ある**（target切り替えの旧・新project枠、project枠＋DB枠、結果処理枠）。いずれも「一定順序で」と書かれていますが、順序そのものが確定しておらず、実装者に委ねられています。同一project内は直列でよいという要件を使えば、いずれも単一資源の逐次取得へ落とせます。
- **枠不足時の挙動が未決定**（ワーカー上限に達したときの3つ目のproject、DB枠待ちの扱い、unresponsive後のキュー残）。
- **補助JVMがスクリプト一覧のためにも起動する**のは、要件「無駄な処理を増やさない」に照らして過剰です。
- **状態機械に「隔離」「切り替え中」が無い**のに本文では多用されています。
- IPCの結果転送は「完了通知と転送を区別する」という方針は正しいものの、**プロトコル上どの順序で何が届いた時点で「実行済み」と確定するか**が書かれておらず、方針が実装で成立しない可能性があります。

実装前に確定すべき判断は主に上記5点で、機能追加は不要です。むしろ削れます。

---

## (2) 重要な指摘

### 指摘1: ワーカー上限に達したときの動作が未定義で、待機予算の記述と矛盾する（§5, §11）

**発生状況**: `--max-project-workers=2`で project A・B が両方Programロード済み。project C への初回`open_program`が来る。§11は「Programのあるワーカーを追い出さない」「Program・orphan・実行中要求のないワーカーだけを終了して枠を空ける」としていますが、空くワーカーが無い場合にどうなるかが書かれていません。§5の「起動期限→キュー期限」の流れは、起動できる前提です。エラー候補に`WORKER_CAPACITY_EXCEEDED`がありますが、これがキュー数超過（§5の32/256）なのか、ワーカー枠不足なのかも区別されていません。

さらに、`close_session`でtargetを全部閉じたworkerは「Programのないワーカー」になりますが、これを自動終了するのか、次のprojectが来るまで保持するのか（JVM再起動120秒を毎回払うのか）が決まっていません。「スクリプト実行済みのプロセスを別projectへ使い回さない」ため、実質毎回再起動になります。

**修正案**:
- ワーカー枠不足は**待たずに即エラー**（`WORKER_CAPACITY_EXCEEDED`をこの意味に限定し、キュー超過は既存busy相当に分ける）。理由: 起動枠が空くのは他projectの`close_session`という利用者操作でしか起きず、期限付きで待つ意味が薄い。エラーdetailsに「どのprojectがProgramを保持しているか」を含めれば利用者が判断できる。
- Programが0になったworkerは「idle」とし、枠不足時にだけ終了して枠を空ける（設計書の方針を明記）。idle timeoutによる自動終了は初版では入れない。
- `--session`で起動時に複数projectを指定したときのeager/lazyと、指定数が上限を超えた場合の扱い（起動失敗にするのか、上限を自動で引き上げるのか）を決める。現行`--session`がloadまで行うなら、workersモードでは「登録のみ・初回要求でロード」に変わることになり、利用動作の変更になります。

### 指摘2: `open_program`による別projectへのtarget切り替えは、2枠同時取得を伴う複合操作にする必要がない（§4末尾, §5）

**発生状況**: target `x` が project A にロード済みで、`open_program(x, project_location=B)` が来る。設計書は「親が旧・新projectの操作枠を一定順序で予約し、Bで仮セッション作成・検証、Aの正常close後に公開」としています。これは2つのproject枠を同時に保持する操作で、A→B と B→A の切り替えが同時に来ると、順序が全順序（例: ProjectKeyの辞書順）でなければデッドロックします。§5の「資源の取り合いが循環する順序を作らない」と矛盾しかねません。加えて、B側ワーカーの起動待ち中にAの枠を握り続けると、Aの他targetがその間止まります。中間状態（Aをcloseしたが公開前、仮セッション回収失敗など）を親の登録表でどう表すかも未定義です。

**修正案**: 要件「同じprojectの別targetは直列化してよい、原子性の要件なし」を使い、**逐次2段階**にする。
1. 親がtarget `x` を「切り替え中」にして新規要求を止める。
2. Aのキューへ「`x`をclose（保存）」を投入し、完了を待つ。失敗なら`x`は引き続きAに属したまま元に戻す。
3. Bのキューへ「`x`をopen＋検証」を投入。成功で公開。失敗なら`x`は「登録あり・未ロード」に戻す（現行in-processでopen失敗した場合と同じ意味になるはず、要確認）。

これで同時保持する枠は常に1つになり、順序の定義が不要になります。「未保存変更があるときは切り替えを拒否する」制約を付けるかどうかは、現行`open_program`の挙動に合わせて確定してください。片方のワーカーが他方へRPCしない、という決定はこの形でも守れます。

### 指摘3: project枠＋DB枠の取得順序が未定、H2解放失敗でproject全体を隔離するのは過剰、probe不成立時の代替が未決定（§5, §8）

**発生状況**: project A で`bsim_query`（Program必要、H2 DB使用）と、project B で`bsim_update_target_signatures`（同じDB）が並ぶ。§5は「両方が空いた時点で開始」としていますが、「両方空く」瞬間を判定するには全projectキューとDBキューを横断する調停器が必要で、FIFOの単純さが崩れます。

また§8末尾は「projectワーカーでDBの解放に失敗した場合はそのprojectとDBを隔離」としています。H2の接続プールが残っただけで、Programや未保存変更は健全です。project全体を復旧ツール（`discard_changes=true`必須）でしか解除できない状態にするのは、利用者に未保存変更の破棄を強いる過剰な防御です。

さらに「公開APIによる解放で成立しない場合はDB操作の専有プロセス化を別途設計する」とありますが、これはフェーズ1のprobe結果次第で§8全体が変わる判断です。実装前に「不成立の場合の初版の姿」を決めておかないと、フェーズ3で手戻りします。

**修正案**:
- 取得順序を **project枠 → DB枠** に固定し、DB枠待ち中はそのprojectのキューが止まることを受け入れる（同一project直列の要件内）。DB枠待ちにも通常の待機予算を適用。循環はproject→DBの一方向なので生じません。DBキューもFIFO。
- H2解放失敗は **DBだけを「worker Xが保持中」状態**にし、worker Xからの同DB要求は継続可、他workerからは待機→期限切れエラー。projectは隔離しない。worker Xの終了時に解放される。
- probe不成立時の初版として「workersモードではH2ファイルDBは最初に使ったworkerに固定（sticky）、他projectからの同H2 DBは`BSIM_DB_IN_USE`相当のエラー」を今のうちに採用候補として書き、専有プロセス化は延期と明記する。外部DB（PostgreSQL等）はこの制約の対象外であることも明記。

### 指摘4: 「実行済み・結果取得失敗」を区別する方針が、IPCプロトコルの順序で保証されていない（§6, §9）

**発生状況**: worker が編集を完了し、大きな結果を分割送信中に切断。§9の表は「完了通知後の転送失敗」を「実行済み」、「送信後・完了通知前の切断」を「不明」に分けていますが、§6のresponse定義は「完了・失敗の区別、結果、target状態差分」を1つのresponseとして書いており、完了通知がいつ届くのかが決まっていません。結果本体と同じframe列の末尾に完了印があるなら、転送途中の切断はすべて「不明」になり、区別の方針が空文になります。

**修正案**:
- responseを **completion header（request ID、成否、target状態、結果の識別子とサイズ）→ 結果本体 → end** の順に固定し、**headerが届いた時点で「実行済み」を確定**する。headerは小さいframe1つに収める。
- 結果本体は、親と子が同一ホスト・同一ユーザーである前提（loopback socket、`sys.executable`起動）を活かし、**workerが親の一時領域へ直接ファイルとして書き、headerにパスだけを載せる**方式を検討する。これで§6の「分割」「frame上限」「backpressure」「結果処理の実行枠」「再組立」を初版から削れます。親は読み取り・schema検証・`ResultResourceStore`登録だけを行う。worker停止後の残骸回収は既に設計書にある「worker終了後の一時領域回収」で足ります。
- この方式を採らない場合でも、header先送りの順序だけは確定してください。

### 指摘5: 状態機械に「隔離」「切り替え中」が無く、unresponsive後のキュー残とcancel完了時の結果分類が未定義（§9）

**発生状況**:
- 本文は「隔離状態」「DB枠を隔離」「同じprojectの全targetを隔離」を多用しますが、遷移図は`registered → starting → ready ⇄ busy`、`failed`、`unresponsive`のみです。隔離が`unresponsive`と同じなのか、別なのか、target単位の隔離（既存`close_session(discard_changes=true)`で解除できるもの）とproject単位の隔離の関係が読めません。
- projectが`unresponsive`になった時点でキューに残っている要求を、即時に`PROJECT_RESET_REQUIRED`で返すのか、期限まで待たせるのかが未記載。「新しいGhidra要求を拒否」は新規分だけです。
- cancelが実行中要求に届き、協調停止が成功した場合の結果が、通常のスクリプト例外（rollback済み）なのか、cancel完了なのか、また協調停止が間に合わず**操作が正常完了した場合**に編集が反映されている事実を利用者へ返すのかが決まっていません。「実行前は未実行」だけが定義されています。

**修正案**:
- 状態を **project状態**（`registered/starting/ready/busy/unresponsive/failed`）と **target状態**（`unloaded/loaded/switching/isolated`）の2層に分け、「隔離」はtarget状態の`isolated`（既存close経路で解除可能）とproject状態の`unresponsive`（復旧ツールのみ）に用語を固定する。
- `unresponsive`遷移時にキュー残を即時エラーで返す（待たせない）。
- cancel応答の実行段階を`not_started / cancelled_rolled_back / completed / unknown`の4値にし、`completed`は「cancelは間に合わず編集は反映済み」を意味すると定義する。これは§9のerror details案（`not_started / completed / unknown`）に1値足すだけです。

### 指摘6: スクリプト利用可否の確定のために補助JVMを起動するのは過剰（§7, §11）

**発生状況**: 利用者が`list_scripts`を最初に呼ぶと、Programを持たない2 GiB・最大120秒のJVMが起動します。用途は「runtime利用可否の確定」だけで、実行はどのみち各projectワーカーのhandshakeで再確認します。§11も「scriptsの公開に必要な初回probe」を補助ワーカーの起動条件にしています。

**修正案**: `list_scripts`/`get_script_info`は親のcatalog（一覧・メタデータ・原本snapshot）だけで応答し、runtime利用可否は「未確認」または「最後にhandshakeしたワーカーの観測値」として返す。実行時に利用不可なら明確なruntimeエラーを返す、という設計書の既存方針だけで足ります。補助ワーカーの用途を **ProgramなしBSim DB操作のみ**に限定し、それも必要になった時点で起動する。これで「上限2でもJVM 3つ」になるのはBSim DB管理を使う場合だけになります。

### 指摘7: 復旧ツール`reset_project_sessions`の引数と対象指定に無駄がある（§9）

**発生状況**: `discard_changes`を必須にしつつ「`false`では停止・破棄を行わない」としているため、`false`の呼び出しは何もしないツール呼び出しになります。また対象を`target`で指定しますが、範囲はproject全体で、登録のみ（project未確定）のtargetを渡された場合の挙動が不明です。

**修正案**: いずれか。
- `discard_changes=false`を「dry-run: 影響target一覧・状態・実行結果不明の要求IDだけ返し、何もしない」と定義する（確認→実行の2段階として意味を持たせる）。
- あるいは引数を外し、ツール名を`reset_project_sessions`のまま「常に破棄」と説明で明示する。

対象は`target`と`project`の両方を受け付ける必要はなく、`list_targets`が公開するproject識別子を`project`引数で受ける方が範囲と一致します。対象が`ready`/`busy`（健全）なprojectだった場合は拒否し`close_session`へ誘導する、という設計書の方針は維持。

### 指摘8: 親の異常終了に備える「POSIXの小さな監視プロセス」は、必要性がprobeで決まる（§9「親・子の終了」）

**発生状況**: 「native処理が停止した子にPythonのEOF監視だけでは十分でない」を理由に監視プロセスを追加していますが、JPype経由のJava呼び出し中はGILが解放されるのが通例なので、worker内のPython監視スレッド（IPCのEOF検知またはppidの定期確認）が`os._exit`を呼べる可能性があります。JVMがハングしていても、Pythonプロセス自体の終了はできます。監視プロセスを足すと、その監視プロセス自身の起動・終了・失敗の管理が増えます。macOSでは`PR_SET_PDEATHSIG`相当が無いため、いずれにせよポーリングかEOF監視になります。

**修正案**: 初版は **worker内watchdogスレッド（IPC EOF ＋ ppid確認）＋ `start_new_session=True`**、Windowsは設計書通りJob Object（kill-on-close）とし、監視プロセスは「フェーズ1のprobeで、JVMがnativeで停止中にwatchdogスレッドが動かないことが確認された場合のみ追加」と条件付きにする。decompiler子プロセスはJVM終了時のパイプ切断で終了するかどうかもprobe項目（(5)参照）。

---

## (3) 簡素化・延期できる要素

| 要素 | 判断 | 理由 |
| --- | --- | --- |
| 結果の分割frame転送、frame上限、backpressure、結果処理専用の実行枠（§6） | 同一ホストのファイル経由に置き換え可 | 指摘4。親側の巨大JSON処理はファイル読み込みと検証だけになる。CPU処理を別スレッドへ逃がすなら専用CapacityLimiterを1つ持つだけでよい |
| target状態の**差分**転送（§4） | 該当projectの全target状態snapshotに | targetは少数。差分の適用順序・欠落の考慮が消える。「古い世代の応答は反映しない」だけ残す |
| サーバー全体256のキュー上限（§5） | 削除候補 | project別32×ワーカー上限2で実質64。全体上限は追加の公平性を生まない |
| 補助ワーカーのscript probe用途（§7） | 削除 | 指摘6 |
| target切り替えの複合操作（§4） | 逐次2段階へ | 指摘2 |
| H2解放失敗時のproject隔離（§8） | DB保持中状態のみへ | 指摘3 |
| POSIX監視プロセス（§9） | probe条件付きへ延期 | 指摘8 |
| リモートBSim DBの読み取り並列化（§8） | 設計書通り延期 | 妥当 |
| 各操作終了時のH2 pool dispose（§8） | 初版は毎回disposeでよいが、「DB枠を他workerへ渡す時だけdispose」は後の最適化候補として記録 | 同一workerの連続操作で毎回再接続するコストは未測定 |
| `SCRIPT_BARRIER`の各worker内保持（§2） | 維持でよいが、workerが単一実行スレッドなら実質no-op | 書き直さない方針は正しい。将来削除候補としてのみ記録 |
| loopback socket＋起動token（§6） | 維持可 | POSIXでUnix domain socketにすればtokenは不要になるが、Windows対応を1経路で済ませるならTCP+tokenが最も単純 |

---

## (4) 維持すべき決定

- 1 project = 1 プロセス、同一project内直列、Javaオブジェクトを越境させない、親にJVMを持たない。
- fork禁止、`sys.executable -m`での起動、shell非経由、認証情報をargv/ログに載せない。
- 通信チャネルとstdout/stderrを分離し、ログを常時読み出してpipe詰まりを作らない。
- 自動再実行なし、自動kill既定なし、通信断でexactly-onceを装わない、cancelはGhidra monitorへの協調停止。
- 「実行結果不明」を独立した結果状態として利用者に返す。header先送りにすれば方針が成立する（指摘4）。
- 復旧は明示ツール、旧プロセスの終了確認後にのみ新ワーカーを起動、lockファイルを消さない。
- 既存`generation`＋modification numberのrevisionを維持し、再ロード後の古いcursorを拒否。
- 結果キャッシュは親、worker停止後も既存の保持期限内で取得可。
- `--execution-mode`の既定値を`in-process`に保ち、workersモードの製品対応は実機検証後に別判断。
- 公開API限定、SHA-256検査を戻さない、MCP SDK 2.xのみ、PyPI対応なし。
- 受け入れ条件§13の「同期イベントでAを止めてBの完了を確認する」方式（時間差での推測をしない）。
- 「共有ファイルのcheckout・競合規則を迂回しない」「分散transactionとして扱わない」の明記。

---

## (5) 実機probeが必要な不確実性（未測定・未確認）

1. **H2 A→B→A**: 2 JVMで公開API（`getDataSourceIfExists` → `getActiveConnections()==0` → `dispose()`）による解放後、別JVMで開いてmetadata/vector更新が見えるか。不成立時の代替（指摘3のsticky案）を先に確定しておく。
2. **同一ホストでの複数JVM起動と設定分離**: Ghidraの設定領域・OSGi/コンパイルcache・一時領域を、OSの`HOME`を置き換えずに公開された設定方法だけで分離できるか。Jython検出が全workerで一致するか。
3. **watchdogの実効性**: JVMがnativeで停止中でも、worker内Pythonスレッドが`os._exit`できるか（JPype呼び出し中のGIL解放前提）。これで監視プロセスの要否が決まる。
4. **decompiler子プロセスの後始末**: JVM異常終了時にパイプ切断で自然終了するか、Job Object/セッション管理が実際に必要か。
5. **起動時間とRSS**: JVM初期化・handshakeまでの時間、1・2・4 project時の総RSS。`--worker-startup-timeout-seconds=120`、`--worker-max-heap=2GiB`、`--max-project-workers=2`はいずれも測定前の仮値。
6. **MCP SDK 2.2.0のcancel通知**: クライアントのcancel通知がtool呼び出しの非同期taskへどう届くか、切断時にSDKがtaskを取り消すか。「MCP切断だけでworkerをkillしない」は守れても、キュー待ち要求の除去タイミングがSDKの挙動に依存する。
7. **親のevent loop占有**: ファイル経由にしても、大きな結果のJSON復号・schema検証はCPU処理。専用CapacityLimiterでto_threadに逃がした場合のGIL影響を、`read_result`・`list_targets`の応答遅延で測る。
8. **case-insensitive FS上のProjectKey収束**（§4）: macOS/Windowsで別表記の`.gpr`パスが同一所有者に収束することの確認。
9. **inline sourceのstaging寿命**: 親の待機打ち切り後もworker側のcleanupがtransaction終了まで待てるか。

---

## (6) 修正版構成の要点

1. **単一資源取得の原則**: 親が同時に保持する枠は常に1つ。target切り替えは「旧project closeを待つ → 新project open」の逐次2段階。BSim付き操作はproject枠→DB枠の一方向順序で、DB待ち中はそのprojectキューが止まることを許容。
2. **枠不足は即エラー**: ワーカー上限に達し、Program 0のidle workerも無ければ`WORKER_CAPACITY_EXCEEDED`（キュー超過とは別コード）。`--session`のeager/lazyと上限超過時の扱いを確定。
3. **IPC response = header先送り**: completion headerで実行済みを確定、結果本体は親の一時領域へファイルで渡す。frame分割・backpressure・結果処理枠は削除。
4. **2層状態機械**: project（`registered/starting/ready/busy/unresponsive/failed`）とtarget（`unloaded/loaded/switching/isolated`）。`unresponsive`遷移でキュー残を即返す。cancel結果は`not_started/cancelled_rolled_back/completed/unknown`。
5. **補助ワーカーはBSim DB操作専用**: script一覧はcatalogのみ、runtime可否はhandshake観測値。
6. **H2**: 解放失敗はDB保持中状態のみ（projectは隔離しない）。probe不成立時はworkersモードでH2をstickyにする代替を初版案として明記。
7. **復旧ツール**: `project`指定、`discard_changes=false`はdry-run（または引数削除）。健全projectは拒否。
8. **終了管理**: `start_new_session=True`＋worker内watchdog（EOF＋ppid）＋Windows Job Object。監視プロセスはprobe結果で条件付き追加。
9. **§13受け入れ条件に追加**: 「ワーカー上限到達時の即エラー」「target切り替え中の同時要求で片方が拒否される」「header受信後の切断が`実行済み・結果取得失敗`に分類される」「`unresponsive`時にキュー残が即時エラーになる」の4項目。

修正版をいただければ、上記の各点が閉じているか再確認します。
