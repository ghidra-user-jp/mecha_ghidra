# Fableとの並列化設計相談

2026-09-21〜22。対象: `ef73f5f`上の設計。Claude Code **2.1.278**で`--model fable`を指定し、3回とも実際のモデルが**`claude-fable-5-1`**であることを確認した。今回の作業は設計相談とMarkdownの改訂に限る。

現在の推奨は[改訂設計](project-worker-parallelism-design.ja.md)。**既存Mechaを作業単位で複数起動し、Ghidra Serverを共有する構成を第一案とする。独自のworker基盤は延期する。** 接続先を単一にするかも設計判断に含めるというユーザーの指示を踏まえ、既存の動作を保ちやすく、リリース前の変更を小さくできる方を選んだ。

## 相談の実施

| 回 | 入力と権限 | 主な相談内容 | 記録 |
| --- | --- | --- | --- |
| 1 | 設計書全文。ツールなし。effort high | 当初のproject worker案の成立性、矛盾、過剰な複雑化 | [回答](reviews/fable-parallelism-20260921/round-1.ja.md)、[実行情報](reviews/fable-parallelism-20260921/round-1.metadata.json) |
| 2 | 関連ソースの読み取りをユーザーが明示許可。Read / Glob / Grepのみ。effort high | Ghidra Serverへ任せる構成、既存Mecha複数起動との比較、コードとの整合性 | [回答](reviews/fable-parallelism-20260921/round-2.ja.md)、[実行情報](reviews/fable-parallelism-20260921/round-2.metadata.json) |
| 3（9月22日） | 改訂設計書全文。ツールなし。effort medium | 複数Mechaを推奨する判断、単一接続先との不利益比較、残る設計上の問題 | [回答](reviews/fable-parallelism-20260921/round-3.ja.md)、[実行情報](reviews/fable-parallelism-20260921/round-3.metadata.json) |

[初回・ソース確認時の旧設計](reviews/fable-parallelism-20260921/reviewed-design.ja.md)も保存した。回答は相談相手の所見であり、以下の採否を経て設計へ反映した。思考過程、認証情報、アカウント情報はこれらの記録に含めていない。

当初、ソース読み取りを含む依頼が自動承認審査で拒否されたため、設計書だけで第1回を実施した。その後ユーザーが「ソースコードの読み取りも許可するよ」と明示し、第2回の読み取り専用レビューを実施した。以後その拒否による未完了事項はない。

## 採用した指摘

| 指摘 | 照合・判断 | 改訂内容 |
| --- | --- | --- |
| Ghidra Server利用と独自worker実装の必要性を分ける | 公式文書、MechaのProgram/実行経路、Ghidra 12.1.3のServer公開処理を確認 | 共有保存はServer、計算は各Mecha。既存Mechaの複数起動を推奨 |
| `open_program`による稼働中targetのproject切り替えは現行にない | `target_lifecycle.py`で同名のロード済みsessionを拒否することを確認 | 2つのprojectをまたぐ仮open・保存close・原子的切り替えの追加を撤回 |
| 一覧のprobeだけに補助JVMは不要 | 各Mechaなら現在のJVMで完結。worker案でも未確認状態を表示できる | 推奨構成に補助JVMを追加しない |
| H2を複数JVM間で引き渡す処理は初版には重い | 公開pool解放APIの静的確認はあったが実機検証は未実施 | H2は各Mecha専用。共有が必要なら外部DB。H2 handoffは推奨構成から除外 |
| DB解放失敗だけでproject全体の破棄へ誘導しない | DBの資源状態とProgramの健全性は別 | 正常なProgramのsave/closeを妨げる復旧案を撤回 |
| 親の状態同期と結果転送を簡素化する | 内部IPC方式を選ぶ場合にだけ必要 | 将来案としてsnapshot、実行終了と結果取得の区別、同一ホストspoolを記録 |
| worker上限・キュー・タイムアウトの仕様が未確定 | 独自worker方式では実装前に必要 | 当面は既存Mechaの個数を運用で決め、独自schedulerを実装しない |
| stdioのプロセス分離を前提条件にする | agent数とMCPプロセス数は一致するとは限らない | 別セッションまたは別server定義、固定した作業パス、別PIDの確認を明記 |
| 異常終了後のcheckoutをローカルロックと区別する | 現行sync statusはcheckout IDと一覧を取得でき、明示的な解除操作もある。異常終了時の実機確認は未実施 | 同じlocal projectを保全して再接続し、状態確認後に継続または明示的な解除を行う手順を追加 |
| Serverとクライアントの競合処理を分けて説明する | Serverによるcheckout排他・版登録と、クライアント側の同期・競合判断は別 | 担当表を分割し、Serverによる自動マージを意味しないことを明記 |

第3回では複数Mecha案を妥当とする回答を受け、上記最後の3点を反映した。対象を別検体・別作業としたときの推奨判断であり、クライアントの接続割り当てや複数JVMの資源消費まで不要になるという判断ではない。

## そのままは採用しなかった提案・留保

- **「薄いルーターは2つの対応表だけで十分」**: targetのない操作、BSimからの動的open、catalog/list集約、resource URI、子の再起動を含む設計が必要。単一受付が必要な場合の比較案に留める。
- **「OS管理へ任せれば復旧・子回収の問題が解消する」**: supervisorの新規実装は省けるが、未保存変更の損失、実行結果不明、decompilerの回収、projectロックの実機確認は残る。自動再起動・要求再送の方針は今回追加しない。
- **「worker内のロック期限はすべて無制限にしてよい」**: background処理やcleanupとの関係を検証せず一括変更しない。推奨構成は既存のロックと期限を維持する。
- **H2を最初のworkerへ固定するfallback**: DBのみの操作とtarget依存操作が違うworkerへ行くと、既存ツールが部分的に使えなくなる。黙ったfallbackとしては採用しない。
- **復旧ツールにdry-runや新しいproject IDを追加する**: 推奨構成では独自復旧ツール自体が不要。将来案でも、必要な利用上の判断を超える引数追加は避ける。
- **親の上書き判定だけでは不足**: 当初案にもworker側guardを残す記述はあった。この点を新規の実装不具合として数えず、単一受付を将来設計する際の必須条件として再確認した。

## 現時点での未検証事項

複数Mechaの実起動、同じServerアカウントによる別cacheからのcheckout/checkin、Ghidra設定・OSGi/cacheの分離、各ランタイムの並行実行、異常終了時の子回収とcheckout復旧、外部BSim、RSS/性能は今回実行していない。改訂設計の成立性確認項目として残した。設計への合意や静的確認を、動作検証の成功に置き換えていない。
