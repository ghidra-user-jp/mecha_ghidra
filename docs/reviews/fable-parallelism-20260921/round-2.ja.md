# Fable相談 第2回（受信した回答）

2026-09-21。Claude Code 2.1.278 / `claude-fable-5-1` / effort high。ユーザーの明示許可後、関連ソースをRead / Glob / Grepで確認。設計判断の参考資料であり、すべての提案を採用したものではありません。採否と現在の推奨は[相談記録](../../project-worker-fable-consultation.ja.md)を参照。

---

調査は完了しました。ここからは所見を日本語でまとめます。

## 1. Ghidra Server が置き換えるもの・置き換えないもの

**事実（本リポジトリのコードで確認）**
- Ghidra Server に対して本実装が使うのは、接続検証と DomainFile の checkout / checkin / merge / undoCheckout / addToVersionControl だけです。`src/ghidra_headless/session/project_handle.py:805-882` がその全経路です。
- Program オブジェクトはローカル JVM が `DomainFile.getDomainObject` で開きます。`project_handle.py:476` です。共有プロジェクトでもファイル内容をローカルキャッシュに取り込んで開く形で、サーバー側で Program は生成されません。
- 自動解析は同じ JVM 内の `flat_api.analyzeAll` です。`target_lifecycle.py:1073` を参照してください。
- スクリプトは同じ JVM 内で `script.execute(state, controls)` を呼びます。`src/ghidra_headless/scripts/execution.py:554` です。モジュール docstring も「Scripts run inside the server JVM」と明記しています。
- BSim の署名生成と類似検索も `SimilarFunctionQueryService(ctx.program)` のようにローカル Program を要します。`read_only_bsim.py:257`、`mutating_bsim.py:143-161` です。
- スクリプト実行中はプロセス全体の `SCRIPT_BARRIER` を writer として取り、別 project の通常操作も待ちます。`core_execution.py:41-47` と `locks.py:54-83` です。

**推論（一般公開情報に基づく。本リポジトリでは検証不能）**
- Ghidra Server はバージョン管理付きファイルストアであり、解析・デコンパイル・スクリプト実行の API を持ちません。本リポジトリに Server 実装はないので、この点は設計文書でも「公式文書に基づく前提」と明示すべきです。
- したがって Ghidra Server は「計算の並列化」を一切代替しません。代替するのは「複数プロセスが同じ解析対象を安全に扱う仕組み」です。`docs/shared-projects.ja.md:5-13` が説明する「リポジトリ 1 つ、ローカルキャッシュはプロセスごと」という運用が、Ghidra 自身が想定する複数プロセス構成です。

結論として、並列化が必要かは「複数 JVM を誰が起動・管理するか」の問題に還元されます。Ghidra Server を使う前提なら、その JVM 群を自作ワーカー基盤で管理する必要はなく、独立した Mecha プロセスとして起動してよい、が本質です。

## 2. 選択肢の比較と推奨

| 案 | 並列性 | 新規コード | 主な制約 |
| --- | --- | --- | --- |
| A. 単一プロセス | 通常操作は別 project で並行、スクリプトは全停止 | なし | 長いスクリプトで他 agent が `LOCK_TIMEOUT` を受け続ける |
| B. 複数 Mecha プロセス | project 単位で完全分離 | ほぼなし。文書と起動時ガードのみ | endpoint と target 名前空間、result cache がプロセス別 |
| C. 常駐ワーカー方式 | project 単位で分離 | IPC、supervisor、復旧ツール、H2 調停など大 | 検証・保守コストが最大 |
| D. Server へ委譲 | Server には実行機能がない | Server 横に実行プロセスを新設 | 実質 B をサーバーホストで動かす構成に収束 |

**推奨は B です。** 理由は、C が解決する問題のほとんどを OS のプロセス分離と Ghidra Server の共有モデルが既に解決しているためです。

- 「同じ project を二重に開かない」は、プロセスごとに別の `.gpr` を持てば Ghidra のプロジェクトロックがそのまま守ります。`is_project_lock_error` が `Unable to lock project` を `PROJECT_LOCKED` に写します。`error_utils.py:38-44` です。
- 「worker 停止時の隔離と復旧」は、プロセス再起動と systemd / launchd / Docker の再起動ポリシーになります。設計 §9 の `unresponsive` 状態や `reset_project_sessions` は不要です。
- 「別 project 間で共有 Program を編集する競合」は、両案とも Ghidra Server の checkout 規則に委ねるので差がありません。`error_mapping.py:73-78` が `ExclusiveCheckoutException` を `CHECKOUT_UNAVAILABLE` に写す経路は現行のまま使えます。
- 既に `--session` を複数指定できるので、1 プロセスに複数 target を載せる A と、プロセスを分ける B を混在させる中間構成も可能です。`cli.py:218-223` です。

**B の運用条件として設計文書に書くべき事項**
1. プロセスごとに `--project-location` と `--bsim-remote-cache-dir` を別にする。後者は `<cache_dir>/<host>_<port>_<repo>` で決まるため、共有すると 2 プロセスが同じキャッシュ `.gpr` を開いて `PROJECT_LOCKED` になります。`bsim_service.py:412-423` です。
2. Ghidra Server の認証はプロセス全体に 1 組です。`cli.py:569-570` です。プロセスを分ければユーザーを分けることもできます。同一ユーザーで別キャッシュから同時 checkout できるかは Ghidra 側の挙動で、本リポジトリでは確認できないため成立性確認項目です。
3. `result_id` はプロセス内キャッシュに閉じます。`docs/configuration.ja.md:20` の記述どおり、agent は返された endpoint で `read_result` を呼ぶ必要があります。
4. H2 ファイル DB は 1 プロセスのみが開く前提とし、複数プロセスで共有する場合は PostgreSQL / Elasticsearch を使う、と明記します。現行コードに H2 固有処理はなく、`BSimClientFactory.buildClient` と `close()` だけです。`java_backend.py:213-224` です。

**1 endpoint が必須だった場合の条件付き判断**
その場合も C の独自 IPC は作らず、「target 名 → 子 Mecha プロセスの HTTP endpoint」に転送する薄いルーターにします。既存の Streamable HTTP が `stateless_http=True` / `json_response=True` の JSON 応答なので、それ自体を worker との通信路として再利用できます。設計 §6 の長さ付き frame、bootstrap token、ログ分離、backpressure は全て不要になります。ルーターが持つ状態は「target → endpoint」と「result_id → endpoint」の 2 表だけです。この構成でも子プロセスの起動と再起動は OS 側に任せ、ルーターは監督者にしません。

## 3. 現行設計への修正点、簡素化、次の判断

**修正 1: open_program の別 project 切り替えは存在しない前提誤り**
`create_session` は同名 target にセッションがあれば `Session already exists` で拒否します。`target_lifecycle.py:139-140` と `150-151` です。ツール説明も「fails if the target already exists」と公開しています。`tool_spec.py:656-657` です。`load_project_program` は target が既に属する project の handle を使うので、こちらも project を跨ぎません。`session_store.py:260-270` です。project の再バインドが起きるのは「セッションを持たない登録済み target」に対する `register_target` か `open_program` だけです。`target_lifecycle.py:225-232` と `154` です。したがって設計 §4 の「旧・新 project の操作枠を予約して仮セッション作成後に公開する複合操作」は削除し、「セッションなしの target のメタデータを親が書き換える」だけにします。

**修正 2: H2 の 2 JVM 引き渡しは設計から外す**
設計 §8 の `BSimH2FileDBConnectionManager` 経路は Ghidra 同梱ソースの静的確認のみで、本リポジトリには対応コードも検証もありません。失敗時に「project と DB を隔離」する分岐まで作ると、復旧ツールと状態機械が肥大します。B なら「H2 は単一プロセス専用」で済み、C を採る場合でも同じ制約を置くのが最小です。設計文書には「引き渡しは未検証のため範囲外」と書き、`getActiveConnections()==0` 確認の手順は付録に落とします。

**修正 3: スクリプト利用可否のための補助 JVM は不要**
`list_scripts` は `providers.runtime_availability()` を JVM 上で問い合わせます。`script_execution.py:29-33` と `script_service.py:173-185` です。設計 §7 はこのために補助ワーカーを起動しますが、B ではプロセス内で完結し、ルーター構成でも子 endpoint に転送するだけで済みます。DB のみの BSim 6 ツールも同様に、どの子に転送するかを `bsim_url` から決めれば補助 JVM は不要です。

**修正 4: キャンセルの実効手段はプロセス再起動である点を明記**
`TimeoutTaskMonitor` は `execute_script` 内で生成され、外部から `cancel()` を呼ぶ経路は現状ありません。`execution.py:549-554` です。設計 §9 は協調停止を前提としますが、monitor を見ないスクリプトや Java スレッドは止められません。この現実を認めると、「project 単位で kill して再起動できる」ことが唯一の確実な復旧で、それは B が OS レベルで無償提供するものです。C を選ぶ理由がここでも弱まります。

**修正 5: 親が保持する dirty / 状態表示の位置づけ**
現行 `list_targets` は target ロック下で `session.to_dict()` を呼び、Ghidra から直接状態を読みます。`target_lifecycle.py:270-273` です。設計 §4 は親の表示を「最後に観測した状態」に変えますが、`create_project(overwrite)` の使用中判定は「登録済み target」と「開いている handle」の両方を見ています。`target_lifecycle.py:103-119` です。後者は worker しか知らないため、親だけで判定すると誤って上書きを許可します。B なら問題自体が消えます。

**修正 6: 1 project 1 実行枠なら worker 内のロック待機予算は二重化する**
設計 §5 は親側 FIFO で 1 実行枠に絞りつつ、worker 内の `SCRIPT_BARRIER` と `--lock-timeout-seconds` も残します。実行枠 1 なら worker 内の待機は原理的に発生せず、reader grace や `script_state` 付き `LOCK_TIMEOUT` は到達不能コードになります。C を続けるなら「待機とタイムアウトは親のみ、worker 内は timeout=None」と決めるべきです。

**簡素化・延期の一覧**
- 削除: 独自 IPC プロトコル、bootstrap token、worker 世代、`reset_project_sessions`、`unresponsive` 状態、補助 JVM、H2 引き渡し、OS 別の子プロセス回収、`--max-project-workers` の追い出し規則。
- 延期: 1 endpoint ルーター。必要が確定するまで着手しない。
- 残す: 別 project 間の並行性は B で達成。既存 80 ツールの契約変更はゼロ。

**最小の次の設計判断と成立性確認**
1. 判断: agent ごとに endpoint を分けてよいか。分けてよければ B を採用し、設計文書は「複数プロセス運用ガイド」に置き換えます。
2. 判断: 単一 endpoint が必須なら、転送ルーターの responsibilities を「target → endpoint」「result_id → endpoint」の 2 表に限定することを合意します。
3. 確認: 同一 Ghidra Server ユーザーで 2 つのローカルキャッシュから同時に checkout / checkin できるか。使い捨てリポジトリで実施します。
4. 確認: 2 プロセスが同じ `--bsim-remote-cache-dir` を指定した場合に `PROJECT_LOCKED` になることを確認し、起動時の重複検出を入れるか判断します。
5. 確認: 1 プロセスあたりの RSS を 1 検体、2 検体で測り、B で必要なプロセス数の目安を出します。設計 §11 の heap 既定値の議論はこの測定後にします。
