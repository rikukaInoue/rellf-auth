# アカウント統合手順

外部ID認証で別のCognitoユーザーが作成されてしまった場合の統合手順。

## 前提

- ユーザーA: パスワードで登録済み（`cognito-uuid-aaa`）
- ユーザーB: 外部IDで新規作成されてしまった（`cognito-uuid-bbb`、外部ID `openid2-example/12345` がリンク済み）

同一人物の2アカウントを、ユーザーAに統合する。

## 手順

### 1. ユーザーBの外部IDリンクを解除

```bash
aws cognito-idp admin-disable-provider-for-user \
  --user-pool-id ap-northeast-1_XXXXX \
  --user \
    ProviderName=openid2-example,ProviderAttributeName=Issuer,ProviderAttributeValue=12345
```

### 2. ユーザーAに外部IDをリンク

```bash
aws cognito-idp admin-link-provider-for-user \
  --user-pool-id ap-northeast-1_XXXXX \
  --destination-user \
    ProviderName=Cognito,ProviderAttributeValue=cognito-uuid-aaa \
  --source-user \
    ProviderName=openid2-example,ProviderAttributeName=Issuer,ProviderAttributeValue=12345
```

### 3. ユーザーBのグループをユーザーAに移行

```bash
# ユーザーBのグループを確認
aws cognito-idp admin-list-groups-for-user \
  --user-pool-id ap-northeast-1_XXXXX \
  --username cognito-uuid-bbb

# 各グループをユーザーAに追加
aws cognito-idp admin-add-user-to-group \
  --user-pool-id ap-northeast-1_XXXXX \
  --username cognito-uuid-aaa \
  --group-name lawyer
```

### 4. ユーザーBを削除

```bash
aws cognito-idp admin-delete-user \
  --user-pool-id ap-northeast-1_XXXXX \
  --username cognito-uuid-bbb
```

### 5. 確認

```bash
# ユーザーAに外部IDがリンクされているか確認
aws cognito-idp admin-get-user \
  --user-pool-id ap-northeast-1_XXXXX \
  --username cognito-uuid-aaa
```

## 注意事項

- 統合前にユーザーBのデータ（プロダクト側のDB等）をユーザーAのIDに紐づけ直す必要がある
- 監査ログ上はユーザーBのIDで記録された操作履歴が残るため、統合した旨を監査ログに記録する
- 統合は不可逆。実行前に両方のユーザー情報をバックアップする

## 管理画面からの統合（将来実装）

上記の手順をAPIとして提供する予定：

```
POST /admin/users/:username/merge
{
  "source_username": "cognito-uuid-bbb"
}
```

ドメインモデル上の流れ：
1. 両ユーザーを取得（両方ActiveUserであること）
2. ソースユーザーの外部IDリンクを解除
3. デスティネーションユーザーに外部IDをリンク
4. ソースユーザーのグループをデスティネーションに移行
5. ソースユーザーを削除（DeletedUser に遷移）
6. 監査ログに統合イベントを記録
