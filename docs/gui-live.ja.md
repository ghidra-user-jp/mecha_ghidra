[English](gui-live.md) | [日本語](gui-live.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# GUIでのライブ共有

`--backend gui` で起動すると、Mecha GhidraはGhidraのGUIを同じプロセスで起動し、GUIが開いたProjectとProgramを、そのままMCPクライアントと共有します。AIの変更はGUIの画面にその場で現れ、人間のGUIでの編集はAIの次の読み取りに現れます。Ghidra Serverへのcheck-inや、保存と再読み込みを挟む必要はありません。

このページでは、[起動](#startup)、[使い方](#usage)、[GUIのツール](#gui-tools)、[書き込みの扱い](#writes)、[保存と終了](#save-and-exit)、[使えない機能](#limits)、[残るリスク](#risks)を説明します。

<a id="startup"></a>

## 起動

GUIのバックエンドは、画面を表示できる環境（macOSのログイン中のデスクトップ、LinuxのXのディスプレイ）で、HTTPの接続方式だけで動きます。stdioの接続方式は、まだ使えません。

```bash
uv run mecha_ghidra --backend gui --transport http \
  --project-location /Users/me/analysis/project.gpr \
  --domain-path /sample.exe \
  --mcp-host 127.0.0.1 --mcp-port 8081 --mcp-path /mcp \
  --allowed-project-root /Users/me/analysis \
  --allowed-export-root /Users/me/analysis/exports
```

- `--project-location` には既存のProjectを指定します。GUIのバックエンドはProjectを作りません。
- `--domain-path` を付けると、起動の後にそのProgramをCodeBrowserで開き、既定のtargetに結び付けます。
- 起動は、headlessと同じく、Ghidraの準備を待たずに受付を始めます。GUIの準備ができるまでのツールの呼び出しは、`LOCK_TIMEOUT`（`details.lock="startup"`）と現在の段階（`details.stage`）を返します。使用許諾などの確認の画面が人間の操作を待っていれば、その題名も `details.modal_dialogs` に入ります。
- 画面を表示できないとき（macOSでログイン中のデスクトップがない、Linuxで `DISPLAY` がないか接続できない）と、ProjectのlockをほかのプロセスがもっているときはGUIを起動しません。ツールの呼び出しに `STARTUP_FAILED`（`details.stage` が `display` または `project_lock`）を返し、サーバーは終了します。GUIが立ち上がった後の段階の失敗（`--domain-path` のProgramがない、など）では、GUIは人間のために開いたままで、ツールの呼び出しには `STARTUP_FAILED`（`details.stage` がその段階）を返し続けます。Ghidraを終えるとサーバーも終わります。
- macOSでは、アプリケーションの名前を「Ghidra (Mecha)」にします（`-Dapple.awt.application.name`）。

GhidraのGUIは、利用者の通常のGhidraの設定（前回のウィンドウの位置、ツールの構成、使用許諾）を使います。前回終了したときに開いていたツールとProgramは、Ghidraが通常どおり復元します。

MCPクライアントの設定は、HTTPの通常の設定と同じです（[MCPクライアント](clients.ja.md)）。

<a id="usage"></a>

## 使い方

AIが `load_project_program` や `open_program` でProgramを読み込むと、GhidraのCodeBrowserのタブとして開きます。人間が見ている現在のタブは切り替わりません（ツールにProgramがまだないときだけ、最初のProgramが現在のタブになります）。既にGUIで開いているProgramは、同じものに結び付き、タブは増えません。

AIのtargetは、人間が見ているタブ、ウィンドウ、カーソルに追従しません。人間が別のタブに切り替えても、AIの呼び出しは読み込んだProgramに対して行われます。人間がタブを閉じると、そのtargetは失効し、以後の呼び出しは `PROGRAM_NOT_OPEN`（`details.reason="closed_in_gui"`）を返します。`load_project_program` で読み込み直せます。人間がこのサーバーのProjectを閉じるか別のProjectを開くと、このサーバーのtargetはすべて使えなくなり、以後の呼び出しは `SESSION_NOT_FOUND`（`details.reason="gui_project_closed"`）を返します。同じProjectを開き直しても戻らないので、Ghidraを終えてからサーバーを起動し直します。実行中の呼び出しは、Mechaが呼び出しの間だけProgramを保持するので、その途中でタブが閉じられても最後まで動き、終わった後にProgramが閉じます。

MCPクライアントの接続を切っても、GUIとtargetはサーバーに残ります。クライアントを再起動して接続し直すと、同じtargetで作業を続けられます。

未解析のProgramが現在のタブになると、Ghidraは自動解析の確認の画面を出します。Mechaはこの画面に答えず、人間の選択に任せます。読み込みの応答と `get_gui_context` の `modal_dialog` に、表示中の画面の題名が入ります。画面が出ている間も、読み取りは続けられます。読み込みでGhidraが先に尋ねるとき（checkoutの確認、強制終了の後の復旧など）は、人間が答えるまで待ちます。40秒を過ぎた呼び出しは先送り（`deferred: true`）の応答になり、結果は `get_operation` で受け取れます（[長い呼び出し](usage.ja.md#long-calls)）。

<a id="gui-tools"></a>

## GUIのツール

`gui` カテゴリの二つのツールは、GUIのバックエンドでだけ公開されます。GUIのバックエンドは、`apply_edits` で変数の名前を変えられないので、`symbol_comment_edit` カテゴリの `rename_variable` も公開します（[書き込みの扱い](#writes)）。

| ツール | 動作 |
| --- | --- |
| `get_gui_context` | 人間が見ているもの（CodeBrowserの一覧、アクティブなツールのProgram、位置、関数、選択範囲）と、そのProgramに結び付いたtargetとrevisionを返します。人間がほかのアプリケーション（AIとの会話の画面など）を使っていてGhidraが背面にあるときは、最後に使ったCodeBrowserを対象にします。表示もtargetも変えません |
| `show_in_gui` | targetのProgramを人間のCodeBrowserに表示し、`address` か関数の `name` を指定すればそこへ移動します。表示だけを変え、編集、保存、解析はしません |

`show_in_gui` は、人間が見たいと言ったときや、結果の確認を頼むときに使い、通常の解析の途中では呼ばない前提です。無効なアドレスや名前は、画面を変える前にエラーになります。表示はできたが移動できなかった場合は、`GUI_NAVIGATION_FAILED` を返します。表示で確認の画面（自動解析の確認など）が出て、移動がその後に回ったときはエラーにせず、確かめられなかった `shown` と `navigated` を `null` にし、`modal_dialog` に画面の題名を返します。

AIに書き込ませずに、画面の案内だけをさせるには、`--tool-profile readonly --enable-tool show_in_gui` で起動します。公開の規則は[ツール公開範囲](configuration.ja.md#tool-exposure)と同じで、GUIの二つのツールを外してもライブ共有そのものは変わりません。

<a id="writes"></a>

## 書き込みの扱い

Ghidraのtransactionは、どのスレッドから開始しても、開いているtransactionに合流します。一つの変更が失敗して巻き戻ると、合流したほかの変更も巻き戻ります。人間とAIが同じProgramを変えるため、GUIのバックエンドはAIの書き込みを次のように行います。

- 書き込みを始める前に、ほかのtransaction（自動解析、人間の操作の背景の処理など）が開いていないかを確かめます。開いていれば待ち、`--lock-timeout-seconds` の間に閉じなければ、何も変えずに `LOCK_TIMEOUT`（`details.lock="program_transaction"`、`details.transaction` にその説明）を返します。
- transactionの区間は、人間のGUIの編集と同じSwingのスレッドで実行します。人間の編集がAIのtransactionに入り込むことはないので、AIの書き込みが失敗しても、人間の編集は巻き戻りません（背景の処理は[残るリスク](#risks)を参照）。
- AIのtransactionの名前は `Mecha: ` で始まります（例：`Mecha: Apply annotation edits`）。GhidraのUndoの一覧で、AIの変更を見分けられます。
- `undo_program_change` と `redo_program_change` は、先頭の記録が `Mecha: ` で始まるときだけ戻します。先頭が人間の編集なら、`GUI_UNSUPPORTED`（`details.reason="foreign_undo"`、`details.top_undo_name`）を返します。
- `apply_edits` は、一括の編集を一つのtransactionとして、Swingのスレッドで実行します。そのため、変更の前後の記録にdecompileが要る種類（`rename_variable`、`set_local_variable_type`）は一括の編集に入れられず、`GUI_UNSUPPORTED`（`details.reason="edit_kind_decompiles"`）になります。変数の名前と型は、単独のツール `rename_variable` と `set_local_variable_type` で変えます。`rename_variable` はGUIのバックエンドだけが公開します。`dry_run=true` も使えません。`atomic=false` の2件目以降は、そのときほかのtransactionが開いていれば、合流せずにその項目だけが `LOCK_TIMEOUT` で失敗します。
- `rename_variable` と `set_local_variable_type` は、decompileの後に人間などがProgramを変えていれば、古い結果で上書きせずに、何も変えないまま `SESSION_CHANGED`（再試行できる）を返します。

失敗した書き込みの応答の `output_state` は、headlessと同じ意味です。

<a id="save-and-exit"></a>

## 保存と終了

ライブ共有のために保存する必要はありません。`save_project_program` は、GhidraのFile > Saveと同じ方法で、対象のProgram全体を保存します。人間の未保存の変更も含まれるため、「AIが変更した部分だけを保存する」ことはできません。Ghidraは保存のときにUndoの履歴を消すので、人間のUndoの履歴も消えます。`.gzf` の `export_program` も、Ghidraの仕様でUndoとRedoの履歴を消すことがあります。保存の先がないProgram（読み取り専用のもの、checkoutしていない版管理のファイルなど）では、Save Asの画面を出さずにエラーを返します。保存と `.gzf` のexportは、書き込みと同じく、ほかのtransactionが閉じるのを待ちます。閉じなければ、何もせずに `LOCK_TIMEOUT` を返します（transactionが開いたままの保存は、Ghidraがそれを巻き戻して保存するかを尋ねるためです）。

`close_session` は、targetとProgramの結び付きを外すだけで、ProgramはGUIに開いたまま残り、保存も破棄もしません。`discard_changes=true` は使えません。

Ghidraの終了は、人間がGUIのFile > Exitで行います。GhidraとMechaのサーバーは同じプロセスなので、Ghidraを終えるとサーバーも終わります。AIが開いて変更したProgramも、Ghidraの標準の保存の確認に含まれます。端末からSIGINT（Ctrl+C）かSIGTERMを送ると、同じ終了の手順が始まり、未保存の変更があれば確認の画面が出ます。取り消せばGhidraは動き続けます。確認の画面が出ている間のSIGINTとSIGTERMは、画面を重ねて出しません。起動した時点で無視する設定になっていたシグナル（スクリプトから `&` で起動したときのSIGINTや、`nohup` で起動したときのSIGHUP）は、無視したままにします。その場合はSIGTERMを使います。SIGHUPではGUIは閉じず、端末への出力を止めます（この版はログのファイルを書かないので、以後のログは残りません）。

<a id="limits"></a>

## 使えない機能

初版のGUIのバックエンドは、次のツールを公開しません。

| ツール | 理由 |
| --- | --- |
| `import_program`、`analyze_program` | 解析をGUIの背景の処理として扱う方式が、まだない |
| `create_project`、`close_session_and_remove_program` | GUIが一つのProjectを所有し、Programの削除はGUIの所有と両立しない |
| BSim、共有プロジェクトの同期、スクリプトのツール | 版管理の操作は人間がGUIで行う。スクリプトの隔離の方法がGUIに合わない |

`--tool-profile full` や `--enable-tool` を指定しても、これらは公開されず、起動ログに一覧が出ます。`--ghidra-server-user` などのServerの認証のオプションはエラーになり、Serverの認証はGhidraの標準の入力画面が扱います。`--bsim-*` と `--script-root` は効果がありません。

`load_project_program` の `version` の指定と、`open_program` や `register_target` で別のProjectを指定することは、`GUI_UNSUPPORTED` になります。

<a id="risks"></a>

## 残るリスク

AIのtransactionが開いている間も、Swingのスレッド以外で動く処理（自動解析、ツールの背景のコマンド）は、Ghidraの仕組み上、そのtransactionに合流し得ます。合流すると、どちらかの変更が失敗したときに、もう一方の変更も一緒に巻き戻ります。AIの書き込みが終わる時点で、合流した処理がまだ終わっていないか失敗していれば、成功とは答えず、`output_state` が `uncertain` か `absent` のエラーを返します。書き込みの区間を短くして機会を減らしていますが、なくすことはできません。人間のGUIのコマンドは、実行の直後に後処理の背景のコマンドを走らせるため、人間の編集の直後のAIの書き込みは、短く待つことがあります。

AIの書き込みの区間はSwingのスレッドで動くので、その間GUIは人間の操作に応答しません。多くの書き込みは短く、100件の `apply_edits`（コメント、関数名、関数のprototype）はどれも0.1秒未満でした。`parse_c_declarations` は入力の大きさに応じて長くなり、上限の100万文字（構造体14,029個）では約1秒かかりました（2026-09-26、macOSでの測定）。大きなヘッダーは分けて渡すと、GUIの止まる時間が短くなります。

revisionは人間の編集や自動解析でも進むので、`expected_revision` の不一致はheadlessより起きやすくなります。
