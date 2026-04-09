package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

const serviceName = "rellf-auth"

func handler(ctx context.Context, event events.CognitoEventUserPoolsCustomMessage) (events.CognitoEventUserPoolsCustomMessage, error) {
	code := event.Request.CodeParameter

	switch event.TriggerSource {
	case "CustomMessage_SignUp":
		event.Response.SMSMessage = fmt.Sprintf("確認コード: %s", code)
		event.Response.EmailSubject = fmt.Sprintf("[%s] メールアドレスの確認", serviceName)
		event.Response.EmailMessage = buildVerificationEmail(code)

	case "CustomMessage_ForgotPassword":
		event.Response.SMSMessage = fmt.Sprintf("パスワードリセットコード: %s", code)
		event.Response.EmailSubject = fmt.Sprintf("[%s] パスワードリセット", serviceName)
		event.Response.EmailMessage = buildPasswordResetEmail(code)

	case "CustomMessage_ResendCode":
		event.Response.SMSMessage = fmt.Sprintf("確認コード: %s", code)
		event.Response.EmailSubject = fmt.Sprintf("[%s] メールアドレスの確認", serviceName)
		event.Response.EmailMessage = buildVerificationEmail(code)

	case "CustomMessage_UpdateUserAttribute":
		event.Response.SMSMessage = fmt.Sprintf("確認コード: %s", code)
		event.Response.EmailSubject = fmt.Sprintf("[%s] メールアドレス変更の確認", serviceName)
		event.Response.EmailMessage = buildAttributeUpdateEmail(code)

	case "CustomMessage_VerifyUserAttribute":
		event.Response.SMSMessage = fmt.Sprintf("確認コード: %s", code)
		event.Response.EmailSubject = fmt.Sprintf("[%s] メールアドレスの確認", serviceName)
		event.Response.EmailMessage = buildVerificationEmail(code)
	}

	return event, nil
}

func buildVerificationEmail(code string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #333;">メールアドレスの確認</h2>
  <p>アカウント登録ありがとうございます。以下の確認コードを入力してメールアドレスを確認してください。</p>
  <div style="background: #f5f5f5; padding: 16px; border-radius: 8px; text-align: center; margin: 24px 0;">
    <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">%s</span>
  </div>
  <p style="color: #666; font-size: 14px;">このコードの有効期限は24時間です。心当たりのない場合はこのメールを無視してください。</p>
</body>
</html>`, code)
}

func buildPasswordResetEmail(code string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #333;">パスワードリセット</h2>
  <p>パスワードリセットのリクエストを受け付けました。以下のコードを入力してパスワードをリセットしてください。</p>
  <div style="background: #f5f5f5; padding: 16px; border-radius: 8px; text-align: center; margin: 24px 0;">
    <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">%s</span>
  </div>
  <p style="color: #666; font-size: 14px;">このコードの有効期限は1時間です。心当たりのない場合はこのメールを無視してください。</p>
</body>
</html>`, code)
}

func buildAttributeUpdateEmail(code string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #333;">メールアドレス変更の確認</h2>
  <p>メールアドレスの変更リクエストを受け付けました。以下のコードを入力して新しいメールアドレスを確認してください。</p>
  <div style="background: #f5f5f5; padding: 16px; border-radius: 8px; text-align: center; margin: 24px 0;">
    <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">%s</span>
  </div>
  <p style="color: #666; font-size: 14px;">このコードの有効期限は24時間です。心当たりのない場合はこのメールを無視してください。</p>
</body>
</html>`, code)
}

func main() {
	lambda.Start(handler)
}
