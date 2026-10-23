# WeChat Pay public-key verification

Start from the deployed payment-service revision `503acc5`. The authorized
change is confined to this provider; it returns verified payment/invoice facts
and never writes billing, wallet, order or job state.

Every WeChat Pay request uses `Accept-Language: zh-CN` and `Wechatpay-Serial`
for the configured verification key. `WECHAT_PAY_PLATFORM_SERIAL_NO` identifies
the configured WeChat Pay public key; the merchant certificate serial remains
exclusive to merchant Authorization. Public-key configuration without a valid
`PUB_KEY_ID_` identifier is unavailable. Certificate-only configuration derives
the verification serial from its existing X509 certificate.

Direct Native create/query currently bypass the common request helper. Route
both through that helper, preserving their bodies, URLs, result mappings and
distinct non-2xx error prefixes. Partner and invoice behavior remains intact,
including invoice extra headers and signed empty successful responses.

Verify every successful response before JSON parsing, and reuse the verifier
for payment and invoice callbacks before parsing or AES decryption. Verify
exact raw response/callback text, including trailing newlines. Require all four
signature headers, an integer timestamp within 300 seconds in either direction,
and a valid RSA signature. Reject SIGNTEST probes and unknown serials. Select
only the key matching the incoming serial, from the configured public key and
optional existing platform certificate; never try another key on failure.

AES behavior and credentials are unchanged. Non-2xx response errors retain
their previous contract. No automatic certificate downloading, persistent key
storage, deployment, or remote push is included.

Tests use generated RSA fixtures and encrypted synthetic callbacks. A local
HTTP endpoint exercises real Node 22 Fetch defaults, rejects wildcard language,
and accepts the explicit language. Required regressions cover direct and
partner requests, invoice operations, both key types, signature failure modes,
raw text, signed 204, configuration readiness and callback verification order.
