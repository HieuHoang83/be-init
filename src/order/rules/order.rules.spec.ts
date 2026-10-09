import { SkipReason } from '../entities/order.entity';
import { ConfirmInput, decideConfirm } from './order.rules';

/**
 * Luật xác nhận đơn là hàm thuần nên test không cần mock Mongoose hay NestJS.
 */
describe('decideConfirm', () => {
  const base: ConfirmInput = {
    hasCustomerIdentity: true,
    isCancelledOrClosed: false,
    isAlreadyConfirmed: false,
    priorOrderCount: 3,
    priorSpent: 500000,
    rule: { minPriorOrders: 1, minPriorSpent: 0 },
  };

  it('xac nhan don khi du so don truoc', () => {
    expect(decideConfirm(base)).toMatchObject({
      shouldConfirm: true,
      isReturningCustomer: true,
      skipReason: SkipReason.NONE,
    });
  });

  it('bo qua don khong co dinh danh khach', () => {
    expect(
      decideConfirm({ ...base, hasCustomerIdentity: false }),
    ).toMatchObject({
      shouldConfirm: false,
      skipReason: SkipReason.NO_CUSTOMER,
    });
  });

  it('bo qua don da huy hoac da dong', () => {
    expect(decideConfirm({ ...base, isCancelledOrClosed: true })).toMatchObject({
      skipReason: SkipReason.ORDER_CANCELLED,
    });
  });

  it('bo qua don Haravan da xac nhan', () => {
    expect(decideConfirm({ ...base, isAlreadyConfirmed: true })).toMatchObject({
      skipReason: SkipReason.ALREADY_CONFIRMED,
    });
  });

  it('phan biet lan mua dau va chua du so don truoc', () => {
    expect(decideConfirm({ ...base, priorOrderCount: 0 })).toMatchObject({
      skipReason: SkipReason.FIRST_TIME_BUYER,
    });
    expect(decideConfirm({ ...base, priorOrderCount: 2, rule: { minPriorOrders: 3, minPriorSpent: 0 } })).toMatchObject({
      skipReason: SkipReason.NOT_ENOUGH_PRIOR_ORDERS,
    });
  });

  it('bo qua khi chua du chi tieu truoc', () => {
    expect(
      decideConfirm({
        ...base,
        priorSpent: 100000,
        rule: { minPriorOrders: 1, minPriorSpent: 500000 },
      }),
    ).toMatchObject({
      shouldConfirm: false,
      isReturningCustomer: true,
      skipReason: SkipReason.NOT_ENOUGH_PRIOR_SPENT,
    });
  });
});
