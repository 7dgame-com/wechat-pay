import express, { NextFunction, Request, Response } from 'express';
import { config, isWechatPayConfigured } from './config';
import type { CreateNativePaymentInput } from './types';
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

function errorResponse(error: unknown, res: Response): void {
  const message = error instanceof Error ? error.message : 'Payment service request failed.';
  res.status(400).json({ success: false, error: { code: 'PAYMENT_SERVICE_ERROR', message } });
}

app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'wechat-pay',
    wechatConfigured: isWechatPayConfigured(),
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
