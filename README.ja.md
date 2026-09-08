# Mecha Ghidra

AIによる完全自動解析と、人への知見の引き継ぎを支えるGhidra MCPサーバー。Ghidraプラグインに依存せず、低レベルのツールをLLMが組み合わせて解析を進める設計です。

[English](README.md) | [日本語](README.ja.md) · [はじめに](docs/usage.ja.md) · [ツール一覧](docs/tools.ja.md) · [リリース](https://github.com/ghidra-user-jp/mecha_ghidra/releases)

<img src="https://github.com/user-attachments/assets/0adbf0e3-4ad9-4a7b-87a6-62a2f9921bb7" alt="Mecha Ghidra" width="480" />

## 設計思想

- **Ghidraプラグインから独立して動く。** PyGhidraを通じてGhidra APIを利用する、独立したMCPサーバーです。プラグインの導入やGUIの操作を必要とせず、プロジェクトの作成から解析・編集・保存までをAIが自動化できます。
- **AIの知見を人が受け取れる。** Ghidra Serverに対応し、AIが付けた名前・型・コメントなどを共有リポジトリへチェックインできます。人はその変更をGhidra GUIで取得・確認し、解析を引き継げます。
- **コンテキストを解析のために使う。** 公開するツールを用途に応じて必要最小限に絞れます。ツール説明の短縮や、大きな結果の分割取得・検索にも対応し、ツール定義と出力によるLLMのコンテキスト圧迫を抑えます。詳しくは[ツールの公開範囲](docs/configuration.ja.md#tool-exposure)と[大きな結果の取得](docs/configuration.ja.md#large-results)を参照してください。
- **高度な解析フローはLLMに委ねる。** 逆コンパイル、参照の取得、名前や型の編集といった低レベルの操作を提供し、仮説の立案やツールの選択・組み合わせはモデル側に任せます。解析手順をサーバーに固定せず、LLMの能力向上を解析に取り込める設計を目指しています。

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

uv run ghidra-mcp \
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
