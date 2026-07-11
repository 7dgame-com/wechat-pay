import { describe, expect, it } from 'vitest';
import { assertServiceConfig, getServiceConfigErrors, type ServiceConfig } from '../src/config';

function makeConfig(apiKey?: string): ServiceConfig {
  return {
    host: '127.0.0.1',
    port: 3010,
    apiKey,
    jsonLimit: '1mb',
    wechat: {
      mode: 'direct',
      apiBaseUrl: 'https://api.mch.weixin.qq.com',
      supportFapiao: false,
    },
  };
}

describe('payment service security configuration', () => {
  it('rejects a missing internal API key in production', () => {
    expect(getServiceConfigErrors(makeConfig(), 'production')).toContain(
      'PAYMENT_SERVICE_API_KEY is required in production.'
    );
    expect(() => assertServiceConfig(makeConfig(), 'production')).toThrow(
      'PAYMENT_SERVICE_API_KEY is required in production.'
    );
  });

  it('allows an explicitly configured production API key', () => {
    expect(getServiceConfigErrors(makeConfig('service-secret'), 'production')).toEqual([]);
    expect(() => assertServiceConfig(makeConfig('service-secret'), 'production')).not.toThrow();
  });

  it('rejects documented placeholder keys in production', () => {
    expect(getServiceConfigErrors(makeConfig('change-me'), 'production')).toContain(
      'PAYMENT_SERVICE_API_KEY must not use a documented placeholder in production.'
    );
  });

  it('keeps keyless local development available', () => {
    expect(getServiceConfigErrors(makeConfig(), 'development')).toEqual([]);
  });
});
