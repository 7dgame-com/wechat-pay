import * as fs from 'fs';
import { constants, createDecipheriv, createSign, createVerify, randomBytes, X509Certificate } from 'crypto';
import { config } from './config';
import type {
  CheckWechatInvoiceSubMerchantStatusInput,
  ConfigureWechatInvoiceDevelopmentConfigInput,
  CreateNativePaymentInput,
  CreateWechatInvoiceApplicationInput,
  NativePaymentOrder,
  PaymentNotification,
  PaymentProvider,
  WechatInvoiceDevelopmentConfig,
  WechatInvoiceApplicationResult,
  WechatInvoiceBuyer,
  WechatInvoiceFile,
  WechatInvoiceNotification,
  WechatInvoiceSubMerchantStatus,
} from './types';

interface WechatEncryptedResource {
  original_type?: string;
  algorithm: string;
  ciphertext: string;
  associated_data?: string;
  nonce: string;
}

interface WechatPaymentNotifyBody {
  event_type?: string;
  resource?: WechatEncryptedResource;
}

interface WechatTransaction {
  out_trade_no: string;
  transaction_id?: string;
  trade_state: string;
  success_time?: string;
  amount?: {
    total?: number;
    currency?: string;
    payer_total?: number;
    payer_currency?: string;
  };
}

interface WechatInvoiceNotifyResource {
  mchid?: string;
  sub_mchid?: string;
  fapiao_apply_id?: string;
  out_trade_no?: string;
  scene?: 'WITH_WECHATPAY' | 'WITHOUT_WECHATPAY';
  apply_time?: string;
  buyer_information?: WechatBuyerInformation;
  title?: string;
  taxpayer_id?: string;
  fapiao_id?: string;
  invoice_no?: string;
  download_url?: string;
  status?: string;
}

interface WechatBuyerInformation {
  type?: 'INDIVIDUAL' | 'ORGANIZATION';
  name?: string;
  taxpayer_id?: string;
  address?: string;
  telephone?: string;
  bank_name?: string;
  bank_account?: string;
  phone?: string;
  email?: string;
}

interface WechatFapiaoApplicationResponse {
  fapiao_apply_id?: string;
  fapiao_information?: Array<{
    fapiao_id?: string;
    status?: string;
    invoice_no?: string;
    download_url?: string;
  }>;
}

interface WechatFapiaoFilesResponse {
  fapiao_download_info_list?: Array<{
    fapiao_id?: string;
    download_url?: string;
    status?: string;
  }>;
}

interface WechatFapiaoDevelopmentConfigResponse {
  callback_url?: string;
  show_fapiao_cell?: boolean;
}

function requireConfig(value: string | undefined, name: string): string {
  if (!value) throw new Error(`${name} is required for WeChat Pay.`);
  return value;
}

function readTextFile(filePath: string | undefined, name: string): string {
  if (!filePath) throw new Error(`${name} is required for WeChat Pay.`);
  return fs.readFileSync(filePath, 'utf8');
}

function loadMerchantPrivateKey(): string {
  if (config.wechat.privateKey) {
    return config.wechat.privateKey.replace(/\\n/g, '\n');
  }
  return readTextFile(config.wechat.privateKeyPath, 'WECHAT_PAY_PRIVATE_KEY_PATH');
}

function loadWechatPayPublicKey(): string {
  if (config.wechat.platformPublicKey) {
    return config.wechat.platformPublicKey.replace(/\\n/g, '\n');
  }
  if (config.wechat.platformPublicKeyPath) {
    return readTextFile(config.wechat.platformPublicKeyPath, 'WECHAT_PAY_PLATFORM_PUBLIC_KEY_PATH');
  }
  if (config.wechat.platformCertificate) {
    const certificate = new X509Certificate(config.wechat.platformCertificate.replace(/\\n/g, '\n'));
    return certificate.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }
  if (config.wechat.platformCertificatePath) {
    const certificate = new X509Certificate(readTextFile(config.wechat.platformCertificatePath, 'WECHAT_PAY_PLATFORM_CERT_PATH'));
    return certificate.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }
  throw new Error(
    'WECHAT_PAY_PLATFORM_PUBLIC_KEY, WECHAT_PAY_PLATFORM_PUBLIC_KEY_PATH, WECHAT_PAY_PLATFORM_CERT, or WECHAT_PAY_PLATFORM_CERT_PATH is required for WeChat Pay notification verification.'
  );
}

function nonce(): string {
  return randomBytes(16).toString('hex');
}

function timestampSeconds(): string {
  return Math.floor(Date.now() / 1000).toString();
}

function normalizeHeader(headers: Record<string, unknown>, name: string): string {
  const lowerName = name.toLowerCase();
  const found = Object.entries(headers).find(([key]) => key.toLowerCase() === lowerName)?.[1];
  if (Array.isArray(found)) return String(found[0] || '');
  return typeof found === 'string' ? found : '';
}

function canonicalUrl(url: URL): string {
  return `${url.pathname}${url.search}`;
}

export function buildWechatAuthorization(input: {
  method: string;
  url: URL;
  body: string;
  mchId: string;
  serialNo: string;
  privateKey: string;
  nonceStr?: string;
  timestamp?: string;
}): string {
  const nonceStr = input.nonceStr || nonce();
  const timestamp = input.timestamp || timestampSeconds();
  const message = `${input.method}\n${canonicalUrl(input.url)}\n${timestamp}\n${nonceStr}\n${input.body}\n`;
  const signature = createSign('RSA-SHA256').update(message).sign(input.privateKey, 'base64');
  const fields = [
    `mchid="${input.mchId}"`,
    `nonce_str="${nonceStr}"`,
    `timestamp="${timestamp}"`,
    `serial_no="${input.serialNo}"`,
    `signature="${signature}"`,
  ];
  return `WECHATPAY2-SHA256-RSA2048 ${fields.join(',')}`;
}

function toPaymentNotification(transaction: WechatTransaction): PaymentNotification {
  return {
    outTradeNo: transaction.out_trade_no,
    transactionId: transaction.transaction_id,
    tradeState: transaction.trade_state,
    successTime: transaction.success_time,
    amountCents: transaction.amount?.total,
  };
}

export function decryptWechatResource<T = unknown>(resource: WechatEncryptedResource, apiV3Key: string): T {
  if (resource.algorithm !== 'AEAD_AES_256_GCM') {
    throw new Error(`Unsupported WeChat Pay resource algorithm: ${resource.algorithm}`);
  }
  const key = Buffer.from(apiV3Key, 'utf8');
  if (key.length !== 32) {
    throw new Error('WECHAT_PAY_API_V3_KEY must be 32 bytes for AES-256-GCM.');
  }
  const ciphertext = Buffer.from(resource.ciphertext, 'base64');
  const authTag = ciphertext.subarray(ciphertext.length - 16);
  const encrypted = ciphertext.subarray(0, ciphertext.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(resource.nonce, 'utf8'), {
    authTagLength: 16,
  });
  decipher.setAuthTag(authTag);
  if (resource.associated_data) {
    decipher.setAAD(Buffer.from(resource.associated_data, 'utf8'));
  }
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  return JSON.parse(decrypted) as T;
}

function toWechatInvoiceBuyer(input: WechatBuyerInformation | undefined): WechatInvoiceBuyer | undefined {
  if (!input?.name) return undefined;
  return {
    type: input.type === 'ORGANIZATION' ? 'ORGANIZATION' : 'INDIVIDUAL',
    name: input.name,
    taxpayerId: input.taxpayer_id,
    address: input.address,
    telephone: input.telephone,
    bankName: input.bank_name,
    bankAccount: input.bank_account,
    phoneMasked: input.phone,
    emailMasked: input.email,
  };
}

function toWechatBuyerPayload(input: WechatInvoiceBuyer): Record<string, unknown> {
  return {
    type: input.type,
    name: input.name,
    taxpayer_id: input.taxpayerId,
    address: input.address,
    telephone: input.telephone,
    bank_name: input.bankName,
    bank_account: input.bankAccount,
  };
}

function toWechatFapiaoApplicationPayload(input: CreateWechatInvoiceApplicationInput): Record<string, unknown> {
  return {
    sub_mchid: input.subMchid,
    scene: input.scene,
    fapiao_apply_id: input.fapiaoApplyId,
    buyer_information: toWechatBuyerPayload(input.buyerInformation),
    fapiao_information: input.fapiaoInformation.map((invoice) => ({
      fapiao_id: invoice.fapiaoId,
      total_amount: invoice.totalAmount,
      need_list: invoice.needList,
      remark: invoice.remark,
      items: invoice.items.map((item) => ({
        tax_code: item.taxCode,
        goods_category: item.goodsCategory,
        goods_name: item.goodsName,
        quantity: item.quantity,
        total_amount: item.totalAmount,
        tax_rate: item.taxRate,
        discount: item.discount,
      })),
    })),
  };
}

function removeUndefined(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(removeUndefined);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .map(([key, item]) => [key, removeUndefined(item)])
  );
}

function getSigningMchId(): string {
  if (config.wechat.mode === 'partner') {
    return requireConfig(config.wechat.spMchId || config.wechat.mchId, 'WECHAT_PAY_SP_MCH_ID or WECHAT_PAY_MCH_ID');
  }
  return requireConfig(config.wechat.mchId, 'WECHAT_PAY_MCH_ID');
}

function getPartnerPaymentConfig(): {
  spAppId: string;
  spMchId: string;
  subAppId?: string;
  subMchid: string;
} {
  return {
    spAppId: requireConfig(config.wechat.spAppId || config.wechat.appId, 'WECHAT_PAY_SP_APP_ID or WECHAT_PAY_APP_ID'),
    spMchId: requireConfig(config.wechat.spMchId || config.wechat.mchId, 'WECHAT_PAY_SP_MCH_ID or WECHAT_PAY_MCH_ID'),
    subAppId: config.wechat.subAppId,
    subMchid: requireConfig(config.wechat.subMchId, 'WECHAT_PAY_SUB_MCH_ID'),
  };
}

export class WechatNativePaymentProvider implements PaymentProvider {
  async createNativeOrder(input: CreateNativePaymentInput): Promise<NativePaymentOrder> {
    if (config.wechat.mode === 'partner') {
      return this.createPartnerNativeOrder(input);
    }

    const appId = requireConfig(config.wechat.appId, 'WECHAT_PAY_APP_ID');
    const mchId = requireConfig(config.wechat.mchId, 'WECHAT_PAY_MCH_ID');
    const serialNo = requireConfig(config.wechat.certSerialNo, 'WECHAT_PAY_CERT_SERIAL_NO');
    const privateKey = loadMerchantPrivateKey();
    const url = new URL('/v3/pay/transactions/native', config.wechat.apiBaseUrl);
    const body = JSON.stringify({
      appid: appId,
      mchid: mchId,
      description: input.description,
      out_trade_no: input.outTradeNo,
      time_expire: input.expiresAt,
      notify_url: input.notifyUrl,
      attach: input.attach,
      amount: {
        total: input.amountCents,
        currency: input.currency,
      },
      support_fapiao: input.supportFapiao ?? config.wechat.supportFapiao,
    });

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: buildWechatAuthorization({
          method: 'POST',
          url,
          body,
          mchId,
          serialNo,
          privateKey,
        }),
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'wechat-pay-service/1.0',
      },
      body,
    });
    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(`WeChat Pay Native order failed: ${response.status} ${responseText}`);
    }
    const parsed = JSON.parse(responseText) as { code_url?: string };
    if (!parsed.code_url) throw new Error('WeChat Pay Native order response did not include code_url.');
    return { codeUrl: parsed.code_url };
  }

  private async createPartnerNativeOrder(input: CreateNativePaymentInput): Promise<NativePaymentOrder> {
    const partner = getPartnerPaymentConfig();
    const url = new URL('/v3/pay/partner/transactions/native', config.wechat.apiBaseUrl);
    const parsed = await this.wechatRequest<{ code_url?: string }>(
      'POST',
      url,
      JSON.stringify(
        removeUndefined({
          sp_appid: partner.spAppId,
          sp_mchid: partner.spMchId,
          sub_appid: partner.subAppId,
          sub_mchid: partner.subMchid,
          description: input.description,
          out_trade_no: input.outTradeNo,
          time_expire: input.expiresAt,
          notify_url: input.notifyUrl,
          attach: input.attach,
          amount: {
            total: input.amountCents,
            currency: input.currency,
          },
          support_fapiao: input.supportFapiao ?? config.wechat.supportFapiao,
        })
      )
    );
    if (!parsed.code_url) throw new Error('WeChat Pay Partner Native order response did not include code_url.');
    return { codeUrl: parsed.code_url };
  }

  async queryOrderByOutTradeNo(outTradeNo: string): Promise<PaymentNotification> {
    if (config.wechat.mode === 'partner') {
      const partner = getPartnerPaymentConfig();
      const url = new URL(
        `/v3/pay/partner/transactions/out-trade-no/${encodeURIComponent(outTradeNo)}`,
        config.wechat.apiBaseUrl
      );
      url.searchParams.set('sp_mchid', partner.spMchId);
      url.searchParams.set('sub_mchid', partner.subMchid);
      return toPaymentNotification(await this.wechatRequest<WechatTransaction>('GET', url));
    }

    const mchId = requireConfig(config.wechat.mchId, 'WECHAT_PAY_MCH_ID');
    const serialNo = requireConfig(config.wechat.certSerialNo, 'WECHAT_PAY_CERT_SERIAL_NO');
    const privateKey = loadMerchantPrivateKey();
    const url = new URL(`/v3/pay/transactions/out-trade-no/${encodeURIComponent(outTradeNo)}`, config.wechat.apiBaseUrl);
    url.searchParams.set('mchid', mchId);
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: buildWechatAuthorization({
          method: 'GET',
          url,
          body: '',
          mchId,
          serialNo,
          privateKey,
        }),
        Accept: 'application/json',
        'User-Agent': 'wechat-pay-service/1.0',
      },
    });
    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(`WeChat Pay query order failed: ${response.status} ${responseText}`);
    }
    return toPaymentNotification(JSON.parse(responseText) as WechatTransaction);
  }

  async parsePaymentNotification(headers: Record<string, unknown>, rawBody: Buffer | string): Promise<PaymentNotification> {
    const bodyText = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    this.verifyNotificationSignature(headers, bodyText);
    const body = JSON.parse(bodyText) as WechatPaymentNotifyBody;
    if (!body.resource) throw new Error('WeChat Pay notification missing resource.');
    const transaction = decryptWechatResource<WechatTransaction>(
      body.resource,
      requireConfig(config.wechat.apiV3Key, 'WECHAT_PAY_API_V3_KEY')
    );
    return toPaymentNotification(transaction);
  }

  async parseWechatInvoiceNotification(
    headers: Record<string, unknown>,
    rawBody: Buffer | string
  ): Promise<WechatInvoiceNotification> {
    const bodyText = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    this.verifyNotificationSignature(headers, bodyText);
    const body = JSON.parse(bodyText) as WechatPaymentNotifyBody;
    if (!body.resource) throw new Error('WeChat fapiao notification missing resource.');
    const resource = decryptWechatResource<WechatInvoiceNotifyResource>(
      body.resource,
      requireConfig(config.wechat.apiV3Key, 'WECHAT_PAY_API_V3_KEY')
    );
    const fapiaoApplyId = resource.fapiao_apply_id || resource.out_trade_no;
    return {
      eventType: body.event_type || 'WECHAT_FAPIAO_NOTIFICATION',
      dedupeKey: `${body.event_type || 'WECHAT_FAPIAO_NOTIFICATION'}:${fapiaoApplyId || resource.fapiao_id || body.resource.nonce}`,
      mchId: resource.mchid,
      subMchid: resource.sub_mchid,
      fapiaoApplyId,
      outTradeNo: resource.out_trade_no || (resource.scene === 'WITH_WECHATPAY' ? fapiaoApplyId : undefined),
      buyer: toWechatInvoiceBuyer(resource.buyer_information || {
        type: resource.taxpayer_id ? 'ORGANIZATION' : 'INDIVIDUAL',
        name: resource.title,
        taxpayer_id: resource.taxpayer_id,
      }),
      raw: resource,
    };
  }

  async getWechatInvoiceUserTitle(
    fapiaoApplyId: string,
    scene: 'WITH_WECHATPAY' | 'WITHOUT_WECHATPAY' = 'WITH_WECHATPAY'
  ): Promise<WechatInvoiceBuyer> {
    const url = new URL('/v3/new-tax-control-fapiao/user-title', config.wechat.apiBaseUrl);
    url.searchParams.set('fapiao_apply_id', fapiaoApplyId);
    url.searchParams.set('scene', scene);
    const parsed = await this.wechatRequest<WechatBuyerInformation>('GET', url);
    const buyer = toWechatInvoiceBuyer(parsed);
    if (!buyer) throw new Error('WeChat fapiao user title response did not include buyer name.');
    return buyer;
  }

  async createWechatInvoiceApplication(
    input: CreateWechatInvoiceApplicationInput
  ): Promise<WechatInvoiceApplicationResult> {
    const url = new URL('/v3/new-tax-control-fapiao/fapiao-applications', config.wechat.apiBaseUrl);
    const subMchid = input.subMchid || (config.wechat.mode === 'partner' ? config.wechat.subMchId : undefined);
    const parsed = await this.wechatRequest<WechatFapiaoApplicationResponse>(
      'POST',
      url,
      JSON.stringify(removeUndefined(toWechatFapiaoApplicationPayload({ ...input, subMchid }))),
      { 'Wechatpay-Serial': requireConfig(config.wechat.platformSerialNo, 'WECHAT_PAY_PLATFORM_SERIAL_NO') }
    );
    const first = parsed.fapiao_information?.[0];
    return {
      fapiaoApplyId: parsed.fapiao_apply_id || input.fapiaoApplyId,
      fapiaoId: first?.fapiao_id || input.fapiaoInformation[0]?.fapiaoId,
      status: first?.status,
      invoiceNo: first?.invoice_no,
      downloadUrl: first?.download_url,
      raw: parsed,
    };
  }

  async getWechatInvoiceFiles(fapiaoApplyId: string, fapiaoId?: string): Promise<WechatInvoiceFile[]> {
    const url = new URL(`/v3/new-tax-control-fapiao/fapiao-applications/${encodeURIComponent(fapiaoApplyId)}/fapiao-files`, config.wechat.apiBaseUrl);
    if (fapiaoId) url.searchParams.set('fapiao_id', fapiaoId);
    const parsed = await this.wechatRequest<WechatFapiaoFilesResponse>('GET', url);
    return (parsed.fapiao_download_info_list || []).map((item) => ({
      fapiaoId: item.fapiao_id,
      downloadUrl: item.download_url,
      status: item.status,
    }));
  }

  async configureWechatInvoiceDevelopmentConfig(
    input: ConfigureWechatInvoiceDevelopmentConfigInput
  ): Promise<WechatInvoiceDevelopmentConfig> {
    const url = new URL('/v3/new-tax-control-fapiao/merchant/development-config', config.wechat.apiBaseUrl);
    const subMchid = input.subMchid || (config.wechat.mode === 'partner' ? config.wechat.subMchId : undefined);
    const body = JSON.stringify(
      removeUndefined({
        callback_url: input.callbackUrl,
        sub_mch_code: subMchid,
        show_fapiao_cell: input.showFapiaoCell,
      })
    );
    const parsed = await this.wechatRequest<WechatFapiaoDevelopmentConfigResponse>('PATCH', url, body);
    return {
      callbackUrl: parsed.callback_url,
      showFapiaoCell: parsed.show_fapiao_cell,
      raw: parsed,
    };
  }

  async checkWechatInvoiceSubMerchantStatus(
    input: CheckWechatInvoiceSubMerchantStatusInput
  ): Promise<WechatInvoiceSubMerchantStatus> {
    const subMchid = requireConfig(input.subMchid, 'subMchid');
    const url = new URL(
      `/v3/new-tax-control-fapiao/merchant/${encodeURIComponent(subMchid)}/check`,
      config.wechat.apiBaseUrl
    );
    await this.wechatRequest<Record<string, never>>('POST', url);
    return { subMchid, available: true };
  }

  private async wechatRequest<T>(
    method: 'GET' | 'POST' | 'PATCH',
    url: URL,
    body = '',
    extraHeaders: Record<string, string> = {}
  ): Promise<T> {
    const mchId = getSigningMchId();
    const serialNo = requireConfig(config.wechat.certSerialNo, 'WECHAT_PAY_CERT_SERIAL_NO');
    const privateKey = loadMerchantPrivateKey();
    const response = await fetch(url, {
      method,
      headers: {
        Authorization: buildWechatAuthorization({
          method,
          url,
          body,
          mchId,
          serialNo,
          privateKey,
        }),
        Accept: 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        'User-Agent': 'wechat-pay-service/1.0',
        ...extraHeaders,
      },
      body: body || undefined,
    });
    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(`WeChat Pay request failed: ${response.status} ${responseText}`);
    }
    return (responseText ? JSON.parse(responseText) : {}) as T;
  }

  private verifyNotificationSignature(headers: Record<string, unknown>, bodyText: string): void {
    const timestamp = normalizeHeader(headers, 'Wechatpay-Timestamp');
    const nonceStr = normalizeHeader(headers, 'Wechatpay-Nonce');
    const signature = normalizeHeader(headers, 'Wechatpay-Signature');
    if (!timestamp || !nonceStr || !signature) {
      throw new Error('WeChat Pay notification signature headers are incomplete.');
    }

    const message = `${timestamp}\n${nonceStr}\n${bodyText}\n`;
    const verifier = createVerify('RSA-SHA256');
    verifier.update(message);
    const verified = verifier.verify(
      {
        key: loadWechatPayPublicKey(),
        padding: constants.RSA_PKCS1_PADDING,
      },
      signature,
      'base64'
    );
    if (!verified) throw new Error('Invalid WeChat Pay notification signature.');
  }
}
