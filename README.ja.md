# EBI - Evaluate Before Invocation (実行前評価ツール)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%3E%3D1.75-orange.svg)](https://www.rust-lang.org)

EBIは、LLMを活用してスクリプトを実行前に分析するセキュリティツールです。任意のコマンドの保護ラッパーとして機能し、悪意のあるコード、脆弱性、隠された命令を検出してシステムを安全に保ちます。

## 特徴

- 🛡️ **セキュリティファースト設計**: 疑わしいスクリプトの実行をデフォルトでブロック
- 🤖 **AI駆動の分析**: LLMを使用して脆弱性と悪意のあるパターンを検出
- 🔍 **多言語サポート**: 現在BashとPythonスクリプトに対応
- 🎯 **スマートな検出**: コード構造、コメント、文字列リテラルを個別に分析
- ⚡ **高速で効率的**: 設定可能なタイムアウトによる並列分析
- 🎨 **ユーザーフレンドリー**: リスクレベルと推奨事項を含む明確でカラフルなレポート

## インストール

### ソースからのインストール

```bash
# リポジトリをクローン
git clone https://github.com/co3k/ebi.git
cd ebi

# Cargoでビルド
cargo build --release

# システムにインストール
sudo cp target/release/ebi /usr/local/bin/

# インストールの確認
ebi --version
```

### 前提条件

- Rust 1.75以上
- インターネット接続（LLM APIコール用）
- OpenAIまたは互換LLMサービスのAPIキー

## 設定

LLM APIキーを設定:

```bash
# OpenAIの場合
export OPENAI_API_KEY="sk-your-api-key"

# Google Geminiの場合
export GEMINI_API_KEY="your-gemini-api-key"

# Anthropic Claudeの場合
export ANTHROPIC_API_KEY="your-anthropic-api-key"

# オプション: デフォルトモデルを設定
export EBI_DEFAULT_MODEL="gemini-2.5-flash"

# オプション: デフォルトタイムアウト（秒）を設定
export EBI_DEFAULT_TIMEOUT=120
```

### 言語設定

EBIは自動ロケール検出による複数出力言語をサポートしています：

```bash
# システムロケールからの自動言語検出
echo 'echo "Hello"' | ebi bash

# 明示的な言語選択
echo 'echo "Hello"' | ebi --output-lang japanese bash

# 環境変数による上書き
export EBI_OUTPUT_LANGUAGE=japanese
echo 'echo "Hello"' | ebi bash
```

**言語優先順位（高から低へ）:**
1. `EBI_OUTPUT_LANGUAGE` 環境変数
2. `--output-lang` CLIオプション
3. システムロケール検出（`LC_ALL`, `LC_MESSAGES`, `LANG`, `LANGUAGE`）
4. デフォルト: 英語

**サポート言語:**
- `english` (または `en`) - 英語出力
- `japanese` (または `ja`, `jp`) - 日本語出力

**ロケール検出:**
EBIはシステムロケールを自動検出し、適切な言語を使用します：
- 日本語ロケール（`ja_JP.UTF-8`, `ja`など）→ 日本語出力
- 英語ロケール（`en_US.UTF-8`, `en`, `C.UTF-8`など）→ 英語出力
- 不明なロケール → 英語出力（フォールバック）

## 使用方法

### 基本的な使用方法

実行前にシンプルなスクリプトを分析:

```bash
echo 'echo "Hello, World!"' | ebi bash
```

### インストールスクリプトの分析

インターネットからのスクリプトを安全に分析:

```bash
# この危険なアプローチの代わりに:
# curl -sL https://example.com/install.sh | bash

# まずEBIで分析:
curl -sL https://example.com/install.sh | ebi bash
```

### コマンドラインオプション

```bash
ebi [オプション] <コマンド> [コマンド引数...]
```

オプション:
- `-l, --lang <言語>`: 自動言語検出を上書き
- `-m, --model <モデル>`: 使用するLLMモデル（デフォルト: gpt-5-mini）
- `-t, --timeout <秒>`: 分析タイムアウト秒数（10-300、デフォルト: 300）
- `-v, --verbose`: 詳細出力を有効化
- `-d, --debug`: LLM通信を含むデバッグ出力を有効化
- `-h, --help`: ヘルプメッセージを表示
- `-V, --version`: バージョンを表示

### 使用例

```bash
# カスタムモデルでPythonスクリプトを分析
cat script.py | ebi --model gemini-2.5-flash python

# 詳細出力で分析
cat installer.sh | ebi --verbose bash

# 言語検出を強制
cat ambiguous_script | ebi --lang bash sh

# 大きなスクリプト用にタイムアウトを増やす
cat large_script.py | ebi --timeout 120 python
```

## リスクレベルの理解

| レベル | 説明 | 推奨事項 |
|-------|------|----------|
| **NONE** | セキュリティリスクなし | 安全に実行可能 |
| **LOW** | 軽微な懸念事項 | レビューして続行 |
| **MEDIUM** | 注目すべきリスクあり | 慎重なレビューが必要 |
| **HIGH** | 重大なセキュリティリスク | 実行は推奨されない |
| **CRITICAL** | 危険な操作を検出 | 実行をブロック |

## 動作原理

1. **入力処理**: stdinからスクリプトを受信
2. **言語検出**: CLI引数、コマンド名、シバンから言語を識別
3. **AST解析**: Tree-sitterを使用してスクリプト構造を解析
4. **コンポーネント抽出**: コード、コメント、文字列リテラルを分離
5. **並列分析**: LLMを使用して脆弱性と注入検出を実行
6. **リスク評価**: 結果を集約して全体的なリスクレベルを決定
7. **ユーザー対話**: レポートを提示し、実行決定を促す
8. **安全な実行**: ユーザー確認後のみ実行（安全な場合）

## 安全機能

- **フェイルセーフデフォルト**: LLMサービスが利用できない場合は実行をブロック
- **ログなし**: デフォルトではスクリプトや分析結果を保存しない
- **タイムアウト保護**: 分析とユーザー入力の両方に設定可能なタイムアウト
- **明示的な同意**: 実行前に常にユーザー確認が必要
- **保守的な分析**: 不確実な場合は高いリスクレベルにデフォルト

## 開発

### ソースからのビルド

```bash
# リポジトリをクローン
git clone https://github.com/co3k/ebi.git
cd ebi

# テストを実行
cargo test

# clippyで実行
cargo clippy

# リリース版をビルド
cargo build --release
```

### テストの実行

```bash
# すべてのテストを実行
cargo test

# 詳細出力で実行
cargo test -- --nocapture

# 特定のテストモジュールを実行
cargo test analyzer::
```

### プロジェクト構造

```
ebi/
├── src/
│   ├── analyzer/       # LLM分析モジュール
│   ├── cli/           # CLIインターフェースとユーザー対話
│   ├── executor/      # スクリプト実行処理
│   ├── models/        # データモデルと型
│   ├── parser/        # スクリプト解析とAST分析
│   └── main.rs        # エントリーポイント
├── tests/
│   ├── contract/      # APIコントラクトテスト
│   ├── integration/   # 統合テスト
│   └── unit/         # ユニットテスト
└── Cargo.toml        # 依存関係とメタデータ
```

## コントリビューション

コントリビューションを歓迎します！プルリクエストをお気軽に送信してください。

1. リポジトリをフォーク
2. フィーチャーブランチを作成 (`git checkout -b feature/AmazingFeature`)
3. 変更をコミット (`git commit -m 'Add some AmazingFeature'`)
4. ブランチにプッシュ (`git push origin feature/AmazingFeature`)
5. プルリクエストを開く

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています - 詳細は[LICENSE](LICENSE)ファイルを参照してください。

## 謝辞

- 堅牢なコード解析のためのTree-sitter
- 優れたライブラリとツールを提供するRustコミュニティ
- 強力なLLM機能を提供するOpenAI

## 免責事項

EBIは分析と推奨事項を提供するセキュリティツールです。悪意のあるコードと脆弱性の検出を目指していますが、完璧ではありません。実行前に常にスクリプトを慎重にレビューし、自身の判断を使用してください。EBI分析後に実行されたスクリプトによって引き起こされた損害について、作者は責任を負いません。

## サポート

問題、質問、提案については、GitHubでイシューを開いてください。