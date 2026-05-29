export type WechatPayMode = 'direct' | 'partner';

export interface WechatPayConfig {
  mode: WechatPayMode;
  appId?: string;
  mchId?: string;
  spAppId?: string;
  spMchId?: string;
  subAppId?: string;
  subMchId?: string;
  privateKey?: string;
  privateKeyPath?: string;
  certSerialNo?: string;
  apiV3Key?: string;
  platformPublicKey?: string;
  platformPublicKeyPath?: string;
  platformCertificate?: string;
  platformCertificatePath?: string;
  platformSerialNo?: string;
  apiBaseUrl: string;
  supportFapiao: boolean;
}

export interface ServiceConfig {
  host: string;
  port: number;
  apiKey?: string;
  jsonLimit: string;
  wechat: WechatPayConfig;
}

function parseNumber(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : defaultValue;
}

function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (!value) return defaultValue;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

function parseWechatPayMode(value: string | undefined): WechatPayMode {
  return value === 'partner' ? 'partner' : 'direct';
}

export const config: ServiceConfig = {
  host: process.env.HOST || '0.0.0.0',
  port: parseNumber(process.env.PORT, 3010),
  apiKey: process.env.PAYMENT_SERVICE_API_KEY,
  jsonLimit: process.env.JSON_LIMIT || '1mb',
  wechat: {
    mode: parseWechatPayMode(process.env.WECHAT_PAY_MODE),
    appId: process.env.WECHAT_PAY_APP_ID,
    mchId: process.env.WECHAT_PAY_MCH_ID,
    spAppId: process.env.WECHAT_PAY_SP_APP_ID,
    spMchId: process.env.WECHAT_PAY_SP_MCH_ID,
    subAppId: process.env.WECHAT_PAY_SUB_APP_ID,
    subMchId: process.env.WECHAT_PAY_SUB_MCH_ID || process.env.WECHAT_FAPIAO_SUB_MCH_ID,
    privateKey: process.env.WECHAT_PAY_PRIVATE_KEY,
    privateKeyPath: process.env.WECHAT_PAY_PRIVATE_KEY_PATH,
    certSerialNo: process.env.WECHAT_PAY_CERT_SERIAL_NO,
    apiV3Key: process.env.WECHAT_PAY_API_V3_KEY,
    platformPublicKey: process.env.WECHAT_PAY_PLATFORM_PUBLIC_KEY,
    platformPublicKeyPath: process.env.WECHAT_PAY_PLATFORM_PUBLIC_KEY_PATH,
    platformCertificate: process.env.WECHAT_PAY_PLATFORM_CERT,
    platformCertificatePath: process.env.WECHAT_PAY_PLATFORM_CERT_PATH,
    platformSerialNo: process.env.WECHAT_PAY_PLATFORM_SERIAL_NO,
    apiBaseUrl: process.env.WECHAT_PAY_API_BASE_URL || 'https://api.mch.weixin.qq.com',
    supportFapiao: parseBoolean(process.env.WECHAT_PAY_SUPPORT_FAPIAO, false),
  },
};

export function isWechatPayConfigured(): boolean {
  const hasDirectIdentity = Boolean(config.wechat.appId && config.wechat.mchId);
  const hasPartnerIdentity = Boolean(
    (config.wechat.spAppId || config.wechat.appId) &&
      (config.wechat.spMchId || config.wechat.mchId) &&
      config.wechat.subMchId
  );
  return Boolean(
    (config.wechat.mode === 'partner' ? hasPartnerIdentity : hasDirectIdentity) &&
      (config.wechat.privateKey || config.wechat.privateKeyPath) &&
      config.wechat.certSerialNo &&
      config.wechat.apiV3Key &&
      (config.wechat.platformPublicKey ||
        config.wechat.platformPublicKeyPath ||
        config.wechat.platformCertificate ||
        config.wechat.platformCertificatePath)
  );
}
