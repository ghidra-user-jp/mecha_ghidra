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

ビルド対象のGhidraは[ghidra_release.env](../scripts/ghidra_release.env)で12.1.3に固定されています。Ghidra ServerとBSimデータベースは必要な場合だけ用意します。

<a id="native-decompiler-artifacts"></a>

### ネイティブデコンパイラ

Ghidra 12.1.3の公式ZIPには、Linux ARM64とmacOSの両アーキテクチャ向けネイティブデコンパイラが含まれていません。[Mecha Ghidraのリリース](https://github.com/ghidra-user-jp/mecha_ghidra/releases)から用途に合う配布物を選んでください。

| 配布物 | 用途 |
| --- | --- |
| `ghidra_12.1.3_decompiler_natives_all.zip` | ネイティブファイルを追加済みのGhidra一式 |
| `ghidra_decompiler_natives_all.zip` | 既存のGhidra 12.1.3へ展開する追加ファイル |
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

uv run ghidra-mcp \
  --project-location "$PWD/projects" \
  --project-name analysis \
  --transport http \
  --allowed-import-root "$PWD/samples" \
  --allowed-project-root "$PWD/projects" \
  --allowed-export-root "$PWD/exports"
```

この起動例は `projects/analysis.gpr` を指す `default` ターゲットを登録します。プロジェクトの作成やプログラムの読み込みはまだ行いません。サーバーを起動したまま、別のアプリケーションから以下のMCPツールを呼び出します。

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

`import_program` でファイルを取り込みます。

```json
{
  "target": "default",
  "binary_path": "/absolute/path/to/mecha_ghidra/samples/sample.bin"
}
```

応答の **`program` フィールド**が、プロジェクト内のパスです。通常は `/sample.bin` になります。この値をそのまま `load_project_program` の `domain_path` に渡します。

```json
{
  "target": "default",
  "domain_path": "/sample.bin"
}
```

続いて `list_functions` を `{"target":"default","limit":20}` で呼びます。返された関数のアドレスを選び、`decompile_function` に `{"target":"default","address":"<function-address>"}` として渡してください。C風の疑似コード、または[大きな結果を取得するための案内](configuration.ja.md#large-results)が返れば、解析を始められる状態です。

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

## 保存と自動解析

編集後、保存のタイミングを明確にしたい場合は `save_project_program` を呼びます。プログラムの切り替えや `close_session` でも未保存の変更を保存します。プログラム編集ツールの呼び出しごとにトランザクションが作られ、`undo_program_change` と `redo_program_change` で操作できます。履歴はセッション内だけに残り、再読み込みすると失われます。解析済みか、未保存の変更があるか、取り消せるかは `get_program_info` で確認します。

ターゲットとプログラムの組に対する最初の読み込みでは、Ghidraが未解析と判定し、書き込み可能な場合に自動解析します。同じプログラムの再読み込みでは再解析しません。明示的に解析するには `analyze_program`、再解析には `force=true` を使います。過去バージョンや、必要なチェックアウトを取得していない共有プログラムは自動解析しません。

同じローカル `.gpr/.rep` をサーバーで開く前に、Ghidra GUIで閉じてください。GUIとMCPを併用する場合は、[共有リポジトリに対する別々のローカルキャッシュ](shared-projects.ja.md)を使います。
