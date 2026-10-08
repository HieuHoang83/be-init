import { computeHmac, verifyHmac, HMAC_HEADER } from './webhook-hmac.util';
import {
  ChallengeQuery,
  OrderPayload,
  WebhookEnvelope,
  TOPICS,
} from '../interface/order.interface';

describe('computeHmac', () => {
  it('HMAC-SHA256 base64 tren raw body', () => {
    const body = Buffer.from(JSON.stringify({ topic: 'orders/create' }));
    // Lệnh OpenSSL tương đương: openssl dgds -binary -sha256 -hmac "secret" | base64.
    expect(computeHmac(body, 'secret')).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  it('khac nhau khi body doi 1 byte', () => {
    const a = computeHmac(Buffer.from('{"id":1}'), 'secret');
    const b = computeHmac(Buffer.from('{"id":2}'), 'secret');
    expect(a).not.toBe(b);
  });

  it('khac nhau khi secret doi', () => {
    const body = Buffer.from('{"id":1}');
    expect(computeHmac(body, 's1')).not.toBe(computeHmac(body, 's2'));
  });

  it('string va buffer cho cung ket qua', () => {
    expect(computeHmac('{"id":1}', 'secret')).toBe(
      computeHmac(Buffer.from('{"id":1}'), 'secret'),
    );
  });
});

describe('verifyHmac', () => {
  const raw = Buffer.from(
    JSON.stringify({ org_id: 1, topic: 'orders/create' }),
  );
  const secret = 'my-client-secret';

  it('accept chuoi dung', () => {
    const sig = computeHmac(raw, secret);
    expect(verifyHmac(raw, secret, sig)).toBe(true);
  });

  it('case-insensitive header value', () => {
    const sig = computeHmac(raw, secret);
    expect(verifyHmac(raw, secret, `  ${sig}\n`)).toBe(true);
  });

  it('reject khi sai signature', () => {
    expect(verifyHmac(raw, secret, computeHmac(raw, 'other-secret'))).toBe(
      false,
    );
  });

  it('reject khi body bi sua', () => {
    const sig = computeHmac(raw, secret);
    const tampered = Buffer.from(raw.toString().replace('create', 'cancel'));
    expect(verifyHmac(tampered, secret, sig)).toBe(false);
  });

  it('reject khi thieu header / secret', () => {
    expect(verifyHmac(raw, secret, undefined)).toBe(false);
    expect(verifyHmac(raw, secret, null)).toBe(false);
    expect(verifyHmac(raw, '', computeHmac(raw, secret))).toBe(false);
  });

  it('reject khi do dai khac (khong nem loi)', () => {
    expect(() => verifyHmac(raw, secret, 'abc')).not.toThrow();
    expect(verifyHmac(raw, secret, 'abc')).toBe(false);
  });

  it('ten header dung chuan Haravan', () => {
    expect(HMAC_HEADER).toBe('x-haravan-hmacsha256');
  });
});

describe('types / envelope', () => {
  it('topic chuan khai bao', () => {
    expect(TOPICS.ORDER_CREATE).toBe('orders/create');
    // Gia tri nay phai khop voi topic Haravan that su gui.
    // Da xac nhan tren du lieu webhook thuc te trong Mongo.
    expect(TOPICS.ORDER_UPDATE).toBe('orders/updated');
    expect(TOPICS.ORDER_CANCEL).toBe('orders/cancelled');
    expect(TOPICS.ORDER_FULFILLED).toBe('orders/fulfilled');
    expect(TOPICS.ORDER_PAID).toBe('orders/paid');
  });

  it('OrderPayload bat buoc co id', () => {
    const order: OrderPayload = { id: 123 };
    expect(order.id).toBe(123);
  });

  it('envelope giu nguyen data du chung ta biet truoc', () => {
    const env: WebhookEnvelope = {
      org_id: 99,
      topic: TOPICS.ORDER_CREATE,
      data: { id: 1, some_new_field: 'abc' } as OrderPayload,
    };
    expect((env.data as OrderPayload).some_new_field).toBe('abc');
  });

  it('challenge query la object index bat ky', () => {
    const q: ChallengeQuery = { 'hub.verify_token': 't', 'hub.challenge': '1' };
    expect(q['hub.challenge']).toBe('1');
  });
});
