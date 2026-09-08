[English](shared-projects.md) | [日本語](shared-projects.ja.md) · [ドキュメント一覧](usage.ja.md) · [README](../README.ja.md)

# Ghidra Serverで解析結果を共有する

人とMCPクライアントで解析結果を共有する場合にGhidra Serverを使います。GUIとMCPは、同じリポジトリに接続する**別々のローカルキャッシュ**を使います。変更はチェックアウトとチェックインで受け渡し、GUIには保存・共有した状態を再読み込みして反映します。

```text
Ghidra GUI → ローカルキャッシュA ─┐
                                ├→ Ghidra Serverリポジトリ
Mecha Ghidra → ローカルキャッシュB ┘
```

同じローカル `.gpr/.rep` を2つのプロセスで開かないでください。`create_project` はローカルプロジェクトの作成用で、Ghidra Serverのリポジトリは作成しません。

## リポジトリを準備する

Ghidra同梱の `server/svrREADME.md` または[公式Ghidra Serverガイド](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/Common/server/svrREADME.md)に従って導入・設定します。ローカルパスワード認証では `-a0` と `-u` を使い、`server/server.conf` の最後のアプリケーション引数にリポジトリディレクトリを指定します。

```text
wrapper.app.parameter.1=-a0
wrapper.app.parameter.2=-u
wrapper.app.parameter.3=${ghidra.repositories.dir}
```

サービスを導入する前に、リポジトリの保存先とサービスの実行ユーザーを環境に合わせて設定してください。Linux/macOSのスクリプトを使った管理操作の例です。

```bash
sudo "$GHIDRA_INSTALL_DIR/server/svrInstall"
sudo "$GHIDRA_INSTALL_DIR/server/svrAdmin" -add analyst
sudo "$GHIDRA_INSTALL_DIR/server/svrAdmin" -add mecha-ghidra
```

導入後に設定を変更した場合は `sudo "$GHIDRA_INSTALL_DIR/server/ghidraSvr" restart` で再起動します。Windowsでは公式ガイドの `.bat` サービス手順を使ってください。

Ghidra GUIで次の準備をします。

1. **File → New Project → Shared Project** を選び、サーバーに接続します。
2. 作成した各アカウントでログインし、パスワードを設定します。ローカルパスワード認証で初期パスワードを明示せず作成したアカウントは、最初に `changeme` を使い、変更が必要です。
3. リポジトリを作成または選択し、`mecha-ghidra` にRead/Write権限を付与します。
4. MCP用に別のローカル共有プロジェクトキャッシュを作成します。Mecha Ghidraの起動前に、そのキャッシュをGUIで閉じてください。

<details>
<summary>共有プロジェクトの設定画面</summary>

![Shared Projectを選択](https://github.com/user-attachments/assets/1091c615-1590-4a49-aa2c-7628d6efed70)
![Ghidra Serverを指定](https://github.com/user-attachments/assets/0d1a0cef-fbee-4513-af18-3193a3529c2f)
![ログイン](https://github.com/user-attachments/assets/e03718b4-89df-4a2b-8609-521a42dd1878)
![初期パスワードを変更](https://github.com/user-attachments/assets/24da9ede-db7b-4ba2-8107-2fb7fe895968)
![リポジトリを作成](https://github.com/user-attachments/assets/3da1693c-3dd7-4ba8-a6e6-95b4767cf95c)
![リポジトリのアクセス権を設定](https://github.com/user-attachments/assets/76ef63d5-de7a-48ca-8758-76b5157a98c3)
![共有プロジェクトの設定を完了](https://github.com/user-attachments/assets/80a8aa7e-659b-4d8e-bf5f-65eea292dc7f)

</details>

## Mecha Ghidraを起動する

[ローカル導入](usage.ja.md#local-setup)と同様に `GHIDRA_INSTALL_DIR` を設定します。サーバープロセスの環境変数 `GHIDRA_SERVER_PASSWORD` にパスワードを設定し、作成済みのMCP用キャッシュを指定してください。

```bash
uv run ghidra-mcp \
  --project-location /work/mcp-cache/shared.gpr \
  --transport stdio \
  --add-category shared_sync \
  --shared-sync-exclusive-checkout \
  --ghidra-server-user mecha-ghidra \
  --ghidra-server-password-env GHIDRA_SERVER_PASSWORD
```

ユーザー名と、`--ghidra-server-password-env` または `--ghidra-server-password` のどちらか一方を指定します。パスワードの未設定・空文字・両オプションの同時指定は起動時に拒否されます。プロセス引数への直接記載より環境変数を推奨します。HTTPで使う場合は[接続方式とファイルアクセスの設定](configuration.ja.md)も適用してください。

## プログラムを編集して共有する

以下はMCP操作です。別名を登録していなければ `default` ターゲットを使います。

1. `list_project_programs` で対象を確認し、`get_project_sync_status(domain_path="/sample.bin")` で状態を読みます。
2. バージョン管理済みなら `checkout_project_program(domain_path="/sample.bin")` でチェックアウトします。リポジトリ接続済みプロジェクトの未共有ファイルは、先に `add_project_program_to_version_control` で共有管理へ追加します。
3. `load_project_program(domain_path="/sample.bin")` で開き、`rename_function` や `set_comment` で編集します。
4. `save_project_program` でローカルへ保存し、`commit_project_program` でリポジトリへチェックインします。応答の `committed` を確認してください。
5. もう一方のキャッシュで最新状態を取得し、GUIのプログラムを再読み込みします。MCPから最新状態へ追従するには `pull_project_program` を使います。

バージョン管理された共有ファイルの変更にはチェックアウトが必要です（`CHECKOUT_REQUIRED`）。チェックアウト時の `exclusive` を省略すると `--shared-sync-exclusive-checkout` の設定に従います。排他的チェックアウト中はほかのチェックアウトを防ぎ、ヘッドレスでマージできない競合を減らせます。チェックアウト、コミット、pullなどは、必要に応じて読み込み中のプログラムを閉じて開き直し、Ghidraの使用中制約を解除します。

<a id="conflicts"></a>

## 競合時の扱い

ヘッドレスGhidraでは競合マージを解決できません。既定の操作は、どの編集を失うかを自動で選ばず停止します。

| 操作 | 結果 |
| --- | --- |
| 既定の `on_conflict="abort"` でコミット | マージが必要なら `MERGE_REQUIRED` |
| `on_conflict="keep"` でコミット | ローカル編集を `.keep` に退避。`kept_program` と `committed=false` を返し、読み込み中ターゲットは退避コピーへ移る |
| `on_conflict="discard"` でコミット | 競合するローカル編集を破棄して最新へ追従。`committed=false` |
| `on_local_changes="discard"` でpull | 破棄可能な古いチェックアウトを解除し、最新バージョンへ追従 |
| 破棄可能なチェックアウトがなく、pullにマージが必要 | `UNSAFE_MERGE_REQUIRED` |

keep/discardの応答が `status="ok"` でも、チェックインしたとは限りません。`committed`、`conflict_kept`、`conflict_discarded` を確認します。競合する編集を統合したい場合は、GUIを使えるGhidra環境で解決してください。

<a id="history"></a>

## 履歴を調べる

`get_version_history` と `get_version_diff(include_details=true)` で履歴と差分を確認します。`load_project_program(domain_path="/sample.bin", version=N)` は過去バージョンを読み取り専用で開き、`read_only=true` を返します。変更は `READ_ONLY_PROGRAM` で失敗し、同期操作は固定した過去バージョンのセッションを切り替えません。現在のファイルへ戻るには `version` を省いて読み込みます。保持中のdomain pathを再び指定すると再読み込みになり、`reloaded=true` を返します。

## 共有ファイルを削除する

`delete_shared_project_file` には、明示的な `domain_path` と、その正規化後のパスに一致する `confirm` が必要です。対象は未読み込みで、有効なチェックアウトがない状態にします。未共有ファイルには `allow_private=true` も必要です。

バージョン管理済みファイルでは、さらに `expected_latest_version` と `allow_non_atomic_versioned_delete=true` を指定します。Ghidraにはバージョン比較と削除を不可分に実行するAPIがないため、この指定を使う前にほかの書き込みを除外してください。`terminate_project_program_checkout` は別の管理操作で、チェックアウトIDの明示が必要です。
