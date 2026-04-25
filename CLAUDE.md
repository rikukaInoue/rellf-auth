# Project: rellf-auth

Go + AWS Lambda + Cognito の OIDC 認証サービス

## Build & Test

- `make build` - Lambda 用バイナリビルド（API / PreSignUp / CustomMessage）
- `make test` - 統合テスト（docker compose + .env.local）
- `make fmt` - go fmt
- `make vet` - go vet
- `make swagger` - Swagger ドキュメント生成
- `make dev-local` - ローカル開発サーバー

## Critical Rules

- .env / .env.local ��ァイルは絶対に読み書きしない
- rm -rf は使わない
- git push --force は使わない
- terraform ディレクトリの��更は慎重に（インフラに直接影響する）
- Cognito のユーザープール設定を変更する場合は必ず確認を取る

## Task Execution Protocol

1. 各ステップ完了後にテストを実行して確認する
2. コンパクションが起きたら、まず CLAUDE.md と現在のタスク計画を再読する
3. 不明点がある場合は推測せず停止する
4. 大きな変更は小さなコミット単位に分割する

## Commit Rules

- 意味のある単位で適度にコミットする。一度に大量の変更を溜め込まない
- 目安: 1 機能・1 修正・1 リファクタリングにつき 1 コミット
- テストが通る状態でのみコミットする。壊れた状態でコミットしない
- コミットメッセージは変更の「なぜ」を書く（「何を」は diff を見ればわかる）
- 長時間作業では、30 分に 1 回はコミットできる粒度で進める。コミットはセーブポイント

## Long Session Rules

- 作業を急いで終わらせようとしないこと。品質が最優先
- 不確かな場合はテストを書いて検証する
- 長時間の作業では適度にコミットして進捗を保全する。コンパクションやクラッシュで作業が失われるリスクを減らす
