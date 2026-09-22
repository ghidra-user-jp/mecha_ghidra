# Mecha Ghidra

AIによる完全自動解析と、人への解析結果・知見の引き継ぎを支えるGhidra MCPサーバーです。Ghidraプラグインに依存せず、逆コンパイルや編集などの低レベルの操作ツールを提供します。解析の方針や手順はAIが決め、必要なツールを選択・組み合わせて解析を進めます。

[English](README.md) | [日本語](README.ja.md) · [はじめに](docs/usage.ja.md) · [ツール一覧](docs/tools.ja.md) · [リリース](https://github.com/ghidra-user-jp/mecha_ghidra/releases)

<img src="https://github.com/user-attachments/assets/0adbf0e3-4ad9-4a7b-87a6-62a2f9921bb7" alt="Mecha Ghidra" width="９６０" />

## 特徴

- Ghidraプラグインに依存せず動作する
  - PyGhidraを通じてGhidra APIを利用する独立したMCPサーバー
  - プラグインの導入やGUI操作を必要としない
- AIの解析結果を人に引き継げる
  - AIが付与した名前・型・コメントなどをGhidra Serverの共有リポジトリに保存
  - 人はGhidra GUIから変更を取得し、解析を継続できる
- 解析の方針や手順はAIが決める
  - 逆コンパイル、参照の取得、名前・型の編集などの操作ツールを提供
  - サーバー側に解析ワークフローを固定せず、AIがツールを選択・組み合わせて解析
- コンテキストの消費を抑える
  - 用途に応じて公開するツールを絞り、ツール定義による消費を削減
  - 大きな結果は分割取得・検索し、必要な部分だけを取得
- 複数の解析対象を切り替えて比較できる
  - 複数のセッションを保持し、対象を切り替えながら解析
  - 亜種やバージョン間の比較、関連するEXE・DLLの調査に利用
- BSimで過去の解析結果を活用できる
  - 登録済みのバイナリから類似関数を検索
  - 検索先のバイナリを別の解析対象として開き、コードを比較

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture.dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/architecture.svg">
  <img alt="Mecha Ghidraの構成。MCPクライアントからローカルのGhidraプロジェクトを解析・編集し、任意でBSimとGhidra Serverを接続する。" src="docs/assets/architecture.svg">
</picture>

## できること

- **バイナリの解析：** 関数のデコンパイル・逆アセンブル、インポート、文字列、メモリ、相互参照の取得。
- **解析結果の記録：** シンボル名、型、コメントの編集、変更の取り消し、プログラムのエクスポート。
- **プログラムの比較：** 複数のターゲットを開き、BSimデータベースで類似関数を検索。
- **チームでの解析：** Ghidra Serverを使ったチェックアウト、保存、チェックイン。
- **コンテキスト量の調整：** 大きな結果を分割取得し、必要な箇所だけを検索。

ローカル解析にはGhidra ServerもBSimも不要です。共有編集はチェックアウト／チェックインで受け渡します。ヘッドレスでの競合マージには対応していません。詳しくは[共有プロジェクトの使い方](docs/shared-projects.ja.md)を参照してください。

## はじめる

使いたい環境に合わせて進んでください。

| 環境 | 最初に読むページ |
| --- | --- |
| 手元にGhidraをインストールして使う | [ローカル導入と最初の解析](docs/usage.ja.md#local-setup) |
| Ghidra同梱のコンテナで使う | [Dockerガイド](docs/docker.ja.md) |
| MCPサーバーはすでに起動している | [MCPクライアントの接続](docs/clients.ja.md) |

ローカル導入にはPython 3.10以上、[uv](https://docs.astral.sh/uv/getting-started/installation/)、Ghidra、対応するJDKが必要です。このリポジトリのネイティブビルドは現在Ghidra 12.1.3を対象としています。配布物の選び方は[前提環境とネイティブデコンパイラ](docs/usage.ja.md#requirements)を確認してください。

**既存の** `analysis.gpr` を使う最小のstdio起動例です。2つの絶対パスを実際の環境に置き換えてください。

```bash
git clone https://github.com/ghidra-user-jp/mecha_ghidra.git
cd mecha_ghidra
uv sync
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra

uv run mecha_ghidra \
  --project-location /absolute/path/to/analysis.gpr \
  --transport stdio
```

[クライアント設定例](docs/clients.ja.md)に沿って、このコマンドをMCPクライアントから起動します。接続後は `list_project_programs` でプログラムを選び、`load_project_program` で開いてから、`list_functions` や `decompile_function` を使います。

**バイナリファイルから始める場合：** [最初の解析](docs/usage.ja.md#first-analysis)で、プロジェクト作成 → インポート → 読み込みまで進めてください。サーバーを起動するだけでは、プロジェクトや解析対象は作成されません。

## ドキュメント

| ガイド | 内容 |
| --- | --- |
| [はじめに](docs/usage.ja.md) | 前提環境、導入、最初の解析、プロジェクトの基本 |
| [MCPクライアント](docs/clients.ja.md) | Codex、Claude Code、Kilo Code、stdio接続 |
| [設定](docs/configuration.ja.md) | 接続方式、ツールの公開範囲、ファイルアクセス、大きな結果 |
| [ツール一覧](docs/tools.ja.md) | 用途別の全ツール一覧 |
| [Docker](docs/docker.ja.md) | ビルド、保存先、最初のインポート、ARM64 |
| [共有プロジェクト](docs/shared-projects.ja.md) | Ghidra Server、チェックアウト／チェックイン、競合、履歴 |
| [BSim](docs/bsim.ja.md) | 類似検索、データベースへの登録、一致したプログラムの読み込み |
| [トラブルシューティング・移行](docs/troubleshooting.ja.md) | エラーコード、よくある問題、旧ツール名からの移行 |
| [開発](docs/development.ja.md) | 構成、テスト、ネイティブビルド、リリース |

## 開発への参加

環境構築と必要な検証は[開発ガイド](docs/development.ja.md)にまとめています。不具合の報告には、Mecha Ghidraのリビジョン、GhidraとJavaのバージョン、接続方式、最小の再現手順、エラーコードを添えてください。報告先は[GitHub Issues](https://github.com/ghidra-user-jp/mecha_ghidra/issues)です。

## ライセンス

[Apache License 2.0](LICENSE)。Ghidraと各依存パッケージには、それぞれのライセンスが適用されます。
