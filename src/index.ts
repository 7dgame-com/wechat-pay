import express, { NextFunction, Request, Response } from 'express';
import { config, isWechatPayConfigured } from './config';
import type {
  CheckWechatInvoiceSubMerchantStatusInput,
  ConfigureWechatInvoiceDevelopmentConfigInput,
  CreateNativePaymentInput,
  CreateWechatInvoiceApplicationInput,
} from './types';
import { WechatNativePaymentProvider } from './wechat-native-provider';

declare global {
  namespace Express {
    interface Request {
      rawBody?: Buffer;
    }
  }
}

interface ParseNotificationBody {
  headers?: Record<string, unknown>;
  rawBodyBase64?: string;
}

const app = express();
const payments = new WechatNativePaymentProvider();

app.use(
  express.json({
    limit: config.jsonLimit,
    verify: (req, _res, buffer) => {
      (req as Request).rawBody = Buffer.from(buffer);
    },
  })
);

function requireServiceKey(req: Request, res: Response, next: NextFunction): void {
  if (!config.apiKey) {
    next();
    return;
  }
  if (req.header('x-payment-service-key') !== config.apiKey) {
    res.status(401).json({ success: false, error: { code: 'PAYMENT_SERVICE_UNAUTHORIZED', message: 'Unauthorized.' } });
    return;
  }
  next();
}

function assertNativeOrderInput(body: Partial<CreateNativePaymentInput>): CreateNativePaymentInput {
  if (!Number.isFinite(body.amountCents) || Number(body.amountCents) <= 0) {
    throw new Error('amountCents must be a positive number.');
  }
  if (body.currency !== 'CNY') throw new Error('currency must be CNY.');
  if (!body.description) throw new Error('description is required.');
  if (!body.outTradeNo) throw new Error('outTradeNo is required.');
  if (!body.notifyUrl) throw new Error('notifyUrl is required.');
  return {
    amountCents: Math.floor(Number(body.amountCents)),
    currency: 'CNY',
    description: body.description,
    outTradeNo: body.outTradeNo,
    notifyUrl: body.notifyUrl,
    expiresAt: body.expiresAt,
    attach: body.attach,
    supportFapiao: body.supportFapiao,
  };
}

function assertWechatInvoiceDevelopmentConfigInput(
  body: Partial<ConfigureWechatInvoiceDevelopmentConfigInput>
): ConfigureWechatInvoiceDevelopmentConfigInput {
  if (body.callbackUrl !== undefined) {
    if (typeof body.callbackUrl !== 'string') throw new Error('callbackUrl must be a string.');
    const url = new URL(body.callbackUrl);
    if (url.protocol !== 'https:') throw new Error('callbackUrl must use https.');
  }
  if (body.showFapiaoCell !== undefined && typeof body.showFapiaoCell !== 'boolean') {
    throw new Error('showFapiaoCell must be a boolean.');
  }
  if (body.subMchid !== undefined && typeof body.subMchid !== 'string') {
    throw new Error('subMchid must be a string.');
  }
  if (body.callbackUrl === undefined && body.showFapiaoCell === undefined && body.subMchid === undefined) {
    throw new Error('At least one development config field is required.');
  }
  return {
    callbackUrl: body.callbackUrl,
    showFapiaoCell: body.showFapiaoCell,
    subMchid: body.subMchid,
  };
}

function assertWechatInvoiceSubMerchantStatusInput(
  input: Partial<CheckWechatInvoiceSubMerchantStatusInput>
): CheckWechatInvoiceSubMerchantStatusInput {
  if (!input.subMchid || typeof input.subMchid !== 'string') {
    throw new Error('subMchid is required.');
  }
  return { subMchid: input.subMchid };
}

function errorResponse(error: unknown, res: Response): void {
  const message = error instanceof Error ? error.message : 'Payment service request failed.';
  res.status(400).json({ success: false, error: { code: 'PAYMENT_SERVICE_ERROR', message } });
}

app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'wechat-pay',
    wechatConfigured: isWechatPayConfigured(),
    wechatMode: config.wechat.mode,
    subMerchantConfigured: Boolean(config.wechat.subMchId),
    timestamp: new Date().toISOString(),
  });
});

app.post('/v1/native-orders', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const order = await payments.createNativeOrder(assertNativeOrderInput(req.body as Partial<CreateNativePaymentInput>));
    res.status(201).json({ order });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.get('/v1/orders/out-trade-no/:outTradeNo', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const payment = await payments.queryOrderByOutTradeNo(req.params.outTradeNo);
    res.json({ payment });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.post('/v1/notifications/wechat/parse', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const body = req.body as ParseNotificationBody;
    if (!body.rawBodyBase64) throw new Error('rawBodyBase64 is required.');
    const payment = await payments.parsePaymentNotification(body.headers || {}, Buffer.from(body.rawBodyBase64, 'base64'));
    res.json({ payment });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.post('/v1/fapiao/notifications/parse', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const body = req.body as ParseNotificationBody;
    if (!body.rawBodyBase64) throw new Error('rawBodyBase64 is required.');
    const invoiceEvent = await payments.parseWechatInvoiceNotification(
      body.headers || {},
      Buffer.from(body.rawBodyBase64, 'base64')
    );
    res.json({ invoiceEvent });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.get('/v1/fapiao/user-title/:fapiaoApplyId', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const scene = req.query.scene === 'WITHOUT_WECHATPAY' ? 'WITHOUT_WECHATPAY' : 'WITH_WECHATPAY';
    const buyer = await payments.getWechatInvoiceUserTitle(req.params.fapiaoApplyId, scene);
    res.json({ buyer });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.post('/v1/fapiao/applications', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const invoiceApplication = await payments.createWechatInvoiceApplication(req.body as CreateWechatInvoiceApplicationInput);
    res.status(202).json({ invoiceApplication });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.get('/v1/fapiao/applications/:fapiaoApplyId/files', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const fapiaoId = typeof req.query.fapiaoId === 'string' ? req.query.fapiaoId : undefined;
    const files = await payments.getWechatInvoiceFiles(req.params.fapiaoApplyId, fapiaoId);
    res.json({ files });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.patch('/v1/fapiao/development-config', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const developmentConfig = await payments.configureWechatInvoiceDevelopmentConfig(
      assertWechatInvoiceDevelopmentConfigInput(req.body as Partial<ConfigureWechatInvoiceDevelopmentConfigInput>)
    );
    res.json({ developmentConfig });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.post('/v1/fapiao/merchant/:subMchid/check', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const subMerchantStatus = await payments.checkWechatInvoiceSubMerchantStatus(
      assertWechatInvoiceSubMerchantStatusInput({ subMchid: req.params.subMchid })
    );
    res.json({ subMerchantStatus });
  } catch (error) {
    errorResponse(error, res);
  }
});

app.post('/v1/wechat/notify', requireServiceKey, async (req: Request, res: Response) => {
  try {
    const payment = await payments.parsePaymentNotification(req.headers, req.rawBody || Buffer.from(JSON.stringify(req.body)));
    res.json({ code: 'SUCCESS', message: '成功', payment });
  } catch (error) {
    errorResponse(error, res);
  }
});

if (require.main === module) {
  app.listen(config.port, config.host, () => {
    console.info(`wechat-pay service listening on ${config.host}:${config.port}`);
  });
}

export default app;
