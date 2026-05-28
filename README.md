# WeChat Pay Service

Standalone internal payment service for WeChat Pay Native API v3.

The model optimizer API talks to this service over HTTP. This keeps WeChat Pay merchant credentials, request signing, order queries, and notification verification out of the main application container.

## Endpoints

- `GET /health`
- `POST /v1/native-orders`
- `GET /v1/orders/out-trade-no/:outTradeNo`
- `POST /v1/notifications/wechat/parse`
- `POST /v1/wechat/notify`

Set `PAYMENT_SERVICE_API_KEY` in both the payment service and the main API to protect internal endpoints. The main API sends it as `x-payment-service-key`.

## Configuration

- `WECHAT_PAY_APP_ID`
- `WECHAT_PAY_MCH_ID`
- `WECHAT_PAY_PRIVATE_KEY` or `WECHAT_PAY_PRIVATE_KEY_PATH`
- `WECHAT_PAY_CERT_SERIAL_NO`
- `WECHAT_PAY_API_V3_KEY`
- `WECHAT_PAY_PLATFORM_PUBLIC_KEY`, `WECHAT_PAY_PLATFORM_PUBLIC_KEY_PATH`, `WECHAT_PAY_PLATFORM_CERT`, or `WECHAT_PAY_PLATFORM_CERT_PATH`
- `WECHAT_PAY_API_BASE_URL`
- `WECHAT_PAY_SUPPORT_FAPIAO`
