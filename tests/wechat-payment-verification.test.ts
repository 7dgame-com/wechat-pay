import { createCipheriv, createSign, generateKeyPairSync, X509Certificate } from 'crypto';
import { once } from 'events';
import { readFileSync } from 'fs';
import { createServer } from 'http';
import type { AddressInfo } from 'net';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { config, isWechatPayConfigured, type WechatPayConfig } from '../src/config';
import { WechatNativePaymentProvider } from '../src/wechat-native-provider';
import type { CreateNativePaymentInput } from '../src/types';

const nativeFetch = globalThis.fetch;
const originalConfig = config.wechat;
const now = 1800000000;
const publicId = 'PUB_KEY_ID_1000000001';
const merchant = generateKeyPairSync('rsa', { modulusLength: 2048 });
const platform = generateKeyPairSync('rsa', { modulusLength: 2048 });
const fixture = (name: string) => join(__dirname, 'fixtures', name);
const oldCertificate = readFileSync(fixture('platform-test-cert.pem'), 'utf8');
const oldPrivateKey = readFileSync(fixture('platform-test-key.pem'), 'utf8');
const oldSerial = new X509Certificate(oldCertificate).serialNumber;
const settings: WechatPayConfig = {
  mode: 'direct', appId: 'test-app', mchId: 'test-merchant', certSerialNo: 'MERCHANT_CERT',
  privateKey: merchant.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  apiV3Key: '12345678901234567890123456789012',
  platformPublicKey: platform.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  platformSerialNo: publicId, platformCertificate: oldCertificate,
  apiBaseUrl: 'https://api.mch.weixin.qq.com', supportFapiao: false,
};
const order: CreateNativePaymentInput = {
  amountCents: 100, currency: 'CNY', description: 'test order', outTradeNo: 'order-1',
  notifyUrl: 'https://example.invalid/notify', attach: 'unchanged',
};
const transaction = { out_trade_no: 'order-1', transaction_id: 'transaction-1', trade_state: 'SUCCESS', amount: { total: 100 } };
const payment = { outTradeNo: 'order-1', transactionId: 'transaction-1', tradeState: 'SUCCESS', amountCents: 100 };
const provider = new WechatNativePaymentProvider();
const fetchMock = vi.fn<typeof fetch>();

function signedHeaders(raw: string, serial = publicId, key: string | typeof platform.privateKey = platform.privateKey, timestamp = now): Record<string, string> {
  return {
    'Wechatpay-Serial': serial, 'Wechatpay-Timestamp': String(timestamp), 'Wechatpay-Nonce': 'response-nonce',
    'Wechatpay-Signature': createSign('RSA-SHA256').update(`${timestamp}\nresponse-nonce\n${raw}\n`).sign(key, 'base64'),
  };
}
function signedResponse(body: unknown, status = 200, serial = publicId, key: string | typeof platform.privateKey = platform.privateKey): Response {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  return new Response(status === 204 ? null : raw, { status, headers: signedHeaders(raw, serial, key) });
}
function encryptedNotice(payload: unknown = transaction, eventType = 'TRANSACTION.SUCCESS'): string {
  const nonce = '0123456789ab';
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(settings.apiV3Key!), Buffer.from(nonce));
  cipher.setAAD(Buffer.from('transaction'));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final(), cipher.getAuthTag()]).toString('base64');
  return JSON.stringify({ event_type: eventType, resource: { algorithm: 'AEAD_AES_256_GCM', nonce, associated_data: 'transaction', ciphertext } }) + '\n';
}
const failureCases = ['tampered body', 'invalid signature', 'unknown serial', 'wrong known key', 'old timestamp', 'future timestamp', 'invalid timestamp', 'SIGNTEST', ...['Serial', 'Timestamp', 'Nonce', 'Signature'].map(name => `missing ${name}`)];
function invalidMessage(kind: string): { raw: string; headers: Record<string, string> } {
  let raw = 'not JSON';
  let headers = signedHeaders(raw);
  if (kind === 'tampered body') raw += '\n';
  else if (kind === 'invalid signature') headers['Wechatpay-Signature'] = Buffer.from('invalid').toString('base64');
  else if (kind === 'unknown serial') headers['Wechatpay-Serial'] = 'UNKNOWN';
  else if (kind === 'wrong known key') headers = signedHeaders(raw, oldSerial);
  else if (kind === 'old timestamp') headers = signedHeaders(raw, publicId, platform.privateKey, now - 301);
  else if (kind === 'future timestamp') headers = signedHeaders(raw, publicId, platform.privateKey, now + 301);
  else if (kind === 'invalid timestamp') headers['Wechatpay-Timestamp'] = 'invalid';
  else if (kind === 'SIGNTEST') headers['Wechatpay-Signature'] = 'WECHATPAY/SIGNTEST/' + headers['Wechatpay-Signature'];
  else delete headers[`Wechatpay-${kind.slice('missing '.length)}`];
  return { raw, headers };
}

beforeEach(() => {
  config.wechat = { ...settings };
  vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  config.wechat = originalConfig;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('authenticated WeChat Pay requests', () => {
  it('sends default headers on consecutive direct requests and preserves their contracts', async () => {
    fetchMock.mockResolvedValueOnce(signedResponse({ code_url: 'weixin://test-order' }))
      .mockResolvedValueOnce(signedResponse(JSON.stringify(transaction) + '\n'));
    await expect(provider.createNativeOrder(order)).resolves.toEqual({ codeUrl: 'weixin://test-order' });
    await expect(provider.queryOrderByOutTradeNo('order-1')).resolves.toMatchObject(payment);
    for (const [url, init] of fetchMock.mock.calls) {
      expect(new URL(String(url)).origin).toBe(settings.apiBaseUrl);
      const headers = new Headers(init?.headers);
      expect(headers.get('Wechatpay-Serial')).toBe(publicId);
      expect(headers.get('Accept-Language')).toBe('zh-CN');
      expect(headers.get('Authorization')).toContain('serial_no="MERCHANT_CERT"');
      expect(headers.get('Authorization')).toContain('mchid="test-merchant"');
    }
    const [createUrl, createInit] = fetchMock.mock.calls[0];
    expect(new URL(String(createUrl)).pathname).toBe('/v3/pay/transactions/native');
    expect(createInit?.method).toBe('POST');
    expect(JSON.parse(String(createInit?.body))).toEqual({ appid: 'test-app', mchid: 'test-merchant', description: 'test order', out_trade_no: 'order-1', notify_url: order.notifyUrl, attach: 'unchanged', amount: { total: 100, currency: 'CNY' }, support_fapiao: false });
    expect(String(fetchMock.mock.calls[1][0])).toBe(`${settings.apiBaseUrl}/v3/pay/transactions/out-trade-no/order-1?mchid=test-merchant`);
    expect(fetchMock.mock.calls[1][1]?.body).toBeUndefined();
  });

  it.each(failureCases)('rejects %s in a successful response before JSON parsing', async kind => {
    const message = invalidMessage(kind);
    fetchMock.mockImplementation(async () => new Response(message.raw, { headers: message.headers }));
    await expect(provider.createNativeOrder(order)).rejects.toThrow(/signature|serial|timestamp/i);
    await expect(provider.queryOrderByOutTradeNo('order-1')).rejects.toThrow(/signature|serial|timestamp/i);
  });

  it.each(['inline', 'path'])('accepts an existing certificate alongside the new public key (%s)', async source => {
    if (source === 'path') {
      config.wechat.platformCertificate = undefined;
      config.wechat.platformCertificatePath = fixture('platform-test-cert.pem');
    }
    fetchMock.mockResolvedValueOnce(signedResponse(transaction, 200, oldSerial, oldPrivateKey))
      .mockResolvedValueOnce(signedResponse(transaction));
    await expect(provider.queryOrderByOutTradeNo('order-1')).resolves.toMatchObject(payment);
    await expect(provider.queryOrderByOutTradeNo('order-1')).resolves.toMatchObject(payment);
  });

  it('derives the default serial for certificate-only configuration', async () => {
    config.wechat.platformPublicKey = undefined;
    config.wechat.platformSerialNo = undefined;
    expect(isWechatPayConfigured()).toBe(true);
    fetchMock.mockResolvedValue(signedResponse(transaction, 200, oldSerial, oldPrivateKey));
    await expect(provider.queryOrderByOutTradeNo('order-1')).resolves.toMatchObject(payment);
    expect(new Headers(fetchMock.mock.calls[0][1]?.headers).get('Wechatpay-Serial')).toBe(oldSerial);
  });

  it('loads an explicitly configured public key file with its own ID', async () => {
    config.wechat.platformPublicKey = undefined;
    config.wechat.platformPublicKeyPath = fixture('platform-test-public.pem');
    fetchMock.mockResolvedValue(signedResponse(transaction, 200, publicId, oldPrivateKey));
    await expect(provider.queryOrderByOutTradeNo('order-1')).resolves.toMatchObject(payment);
  });

  it.each([undefined, '', 'MERCHANT_CERT'])('requires a public-key ID when a public key is configured (%s)', async id => {
    config.wechat.platformSerialNo = id;
    expect(isWechatPayConfigured()).toBe(false);
    await expect(provider.queryOrderByOutTradeNo('order-1')).rejects.toThrow(/WECHAT_PAY_PLATFORM_SERIAL_NO/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('retains non-2xx errors for direct and shared request paths', async () => {
    fetchMock.mockImplementation(async () => new Response('provider-error', { status: 400 }));
    await expect(provider.createNativeOrder(order)).rejects.toThrow('WeChat Pay Native order failed: 400 provider-error');
    await expect(provider.queryOrderByOutTradeNo('order-1')).rejects.toThrow('WeChat Pay query order failed: 400 provider-error');
    await expect(provider.checkWechatInvoiceSubMerchantStatus({ subMchid: 'sub' })).rejects.toThrow('WeChat Pay request failed: 400 provider-error');
  });

  it('verifies signed empty 204 responses and rejects unsigned 204', async () => {
    fetchMock.mockResolvedValueOnce(signedResponse('', 204)).mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(provider.configureWechatInvoiceDevelopmentConfig({ showFapiaoCell: true })).resolves.toMatchObject({ raw: {} });
    await expect(provider.checkWechatInvoiceSubMerchantStatus({ subMchid: 'sub' })).rejects.toThrow(/signature/i);
  });

  it('preserves partner identity, request paths, sub-merchant fields and verified results', async () => {
    Object.assign(config.wechat, { mode: 'partner', spAppId: 'sp-app', spMchId: 'sp-merchant', subAppId: 'sub-app', subMchId: 'sub-merchant' });
    fetchMock.mockResolvedValueOnce(signedResponse({ code_url: 'weixin://partner' })).mockResolvedValueOnce(signedResponse(transaction));
    await expect(provider.createNativeOrder(order)).resolves.toEqual({ codeUrl: 'weixin://partner' });
    await expect(provider.queryOrderByOutTradeNo('order-1')).resolves.toMatchObject(payment);
    expect(new URL(String(fetchMock.mock.calls[0][0])).pathname).toBe('/v3/pay/partner/transactions/native');
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toMatchObject({ sp_appid: 'sp-app', sp_mchid: 'sp-merchant', sub_appid: 'sub-app', sub_mchid: 'sub-merchant' });
    const query = new URL(String(fetchMock.mock.calls[1][0]));
    expect(query.searchParams.get('sp_mchid')).toBe('sp-merchant');
    expect(query.searchParams.get('sub_mchid')).toBe('sub-merchant');
    for (const [, init] of fetchMock.mock.calls) expect(new Headers(init?.headers).get('Authorization')).toContain('mchid="sp-merchant"');
  });

  it('keeps invoice extra headers, payload fields and signed response mappings', async () => {
    fetchMock.mockResolvedValueOnce(signedResponse({ fapiao_apply_id: 'apply', fapiao_information: [{ fapiao_id: 'invoice', status: 'ISSUED' }] }))
      .mockResolvedValueOnce(signedResponse({ fapiao_download_info_list: [{ fapiao_id: 'invoice', download_url: 'https://example.invalid/invoice' }] }));
    await expect(provider.createWechatInvoiceApplication({ scene: 'WITH_WECHATPAY', fapiaoApplyId: 'apply', subMchid: 'sub', buyerInformation: { type: 'INDIVIDUAL', name: 'Test buyer' }, fapiaoInformation: [{ fapiaoId: 'invoice', totalAmount: 100, items: [{ taxCode: 'test-tax', goodsName: 'test', quantity: 1, totalAmount: 100, discount: false }] }] })).resolves.toMatchObject({ fapiaoApplyId: 'apply', fapiaoId: 'invoice', status: 'ISSUED' });
    await expect(provider.getWechatInvoiceFiles('apply', 'invoice')).resolves.toMatchObject([{ fapiaoId: 'invoice', downloadUrl: 'https://example.invalid/invoice' }]);
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toMatchObject({ sub_mchid: 'sub', scene: 'WITH_WECHATPAY', buyer_information: { name: 'Test buyer' } });
    for (const [, init] of fetchMock.mock.calls) {
      const headers = new Headers(init?.headers);
      expect(headers.get('Wechatpay-Serial')).toBe(publicId);
      expect(headers.get('Accept-Language')).toBe('zh-CN');
    }
  });

  it('uses a supported language with real Node 22 Fetch on both direct paths', async () => {
    const languages: Array<string | undefined> = [];
    const server = createServer(async (request, response) => {
      languages.push(request.headers['accept-language']);
      const accepted = request.headers['accept-language'] === 'zh-CN';
      const body = accepted ? (request.method === 'POST' ? { code_url: 'weixin://loopback' } : transaction) : { code: 'PARAM_ERROR', message: '传入了不支持的Accept-Language' };
      const signed = signedResponse(body, accepted ? 200 : 406);
      response.writeHead(signed.status, Object.fromEntries(signed.headers));
      response.end(await signed.text());
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    config.wechat.apiBaseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    vi.stubGlobal('fetch', nativeFetch);
    try {
      const rejected = await nativeFetch(config.wechat.apiBaseUrl);
      expect(rejected.status).toBe(406);
      await rejected.text();
      expect(languages).toEqual(['*']);
      await expect(provider.createNativeOrder(order)).resolves.toEqual({ codeUrl: 'weixin://loopback' });
      await expect(provider.queryOrderByOutTradeNo('order-1')).resolves.toMatchObject(payment);
      expect(languages).toEqual(['*', 'zh-CN', 'zh-CN']);
    } finally {
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });
});

describe('verified callbacks', () => {
  it('preserves verified invoice notification facts without writing business state', async () => {
    const raw = encryptedNotice({ mchid: 'test-merchant', sub_mchid: 'sub', fapiao_apply_id: 'apply', scene: 'WITH_WECHATPAY', buyer_information: { type: 'ORGANIZATION', name: 'Test company', taxpayer_id: 'test-taxpayer' } }, 'FAPIAO.USER_APPLIED');
    await expect(provider.parseWechatInvoiceNotification(signedHeaders(raw), raw)).resolves.toMatchObject({ eventType: 'FAPIAO.USER_APPLIED', dedupeKey: 'FAPIAO.USER_APPLIED:apply', mchId: 'test-merchant', subMchid: 'sub', fapiaoApplyId: 'apply', outTradeNo: 'apply', buyer: { type: 'ORGANIZATION', name: 'Test company', taxpayerId: 'test-taxpayer' } });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([publicId, oldSerial])('authenticates raw callback text with serial %s before decrypting', async serial => {
    const raw = encryptedNotice();
    const headers = signedHeaders(raw, serial, serial === oldSerial ? oldPrivateKey : platform.privateKey);
    await expect(provider.parsePaymentNotification(headers, Buffer.from(raw))).resolves.toMatchObject(payment);
    await expect(provider.parsePaymentNotification(headers, raw.trimEnd())).rejects.toThrow(/signature/i);
  });

  it.each(failureCases)('rejects %s before parsing either callback type', async kind => {
    const { raw, headers } = invalidMessage(kind);
    await expect(provider.parsePaymentNotification(headers, raw)).rejects.toThrow(/signature|serial|timestamp/i);
    await expect(provider.parseWechatInvoiceNotification(headers, raw)).rejects.toThrow(/signature|serial|timestamp/i);
  });

  it('rejects an unknown serial before attempting AES decryption', async () => {
    const raw = JSON.stringify({ resource: { algorithm: 'INVALID', ciphertext: 'invalid' } });
    await expect(provider.parsePaymentNotification(signedHeaders(raw, 'UNKNOWN'), raw)).rejects.toThrow(/serial/i);
  });

  it.each([-300, 300])('accepts the allowed clock boundary %i', async offset => {
    const raw = encryptedNotice();
    await expect(provider.parsePaymentNotification(signedHeaders(raw, publicId, platform.privateKey, now + offset), raw)).resolves.toMatchObject(payment);
  });
});
