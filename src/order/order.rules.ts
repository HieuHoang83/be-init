import { SkipReason } from './order.entity';

export interface ConfirmDecision {
  shouldConfirm: boolean;
  isReturningCustomer: boolean;
  priorOrderCount: number;
  priorSpent: number;
  skipReason: SkipReason;
}

/** Ngưỡng xác nhận đơn, đọc từ biến môi trường. */
export interface ConfirmRule {
  minPriorOrders: number;
  minPriorSpent: number;
}

/** Dữ liệu đầu vào của quyết định, đã được gom sẵn từ DB và payload. */
export interface ConfirmInput {
  hasCustomerIdentity: boolean;
  isCancelledOrClosed: boolean;
  isAlreadyConfirmed: boolean;
  priorOrderCount: number;
  priorSpent: number;
  rule: ConfirmRule;
}

/**
 * Quyết định có tự động xác nhận đơn hay không.
 * Hàm thuần: không đụng database, không phụ thuộc NestJS — test được trực tiếp.
 */
export function decideConfirm(input: ConfirmInput): ConfirmDecision {
  if (!input.hasCustomerIdentity) return skip(SkipReason.NO_CUSTOMER);
  if (input.isCancelledOrClosed) return skip(SkipReason.ORDER_CANCELLED);
  if (input.isAlreadyConfirmed) return skip(SkipReason.ALREADY_CONFIRMED);

  const { priorOrderCount, priorSpent, rule } = input;

  if (priorOrderCount < rule.minPriorOrders) {
    return {
      shouldConfirm: false,
      isReturningCustomer: false,
      priorOrderCount,
      priorSpent,
      skipReason:
        priorOrderCount === 0
          ? SkipReason.FIRST_TIME_BUYER
          : SkipReason.NOT_ENOUGH_PRIOR_ORDERS,
    };
  }

  if (rule.minPriorSpent > 0 && priorSpent < rule.minPriorSpent) {
    return {
      shouldConfirm: false,
      isReturningCustomer: true,
      priorOrderCount,
      priorSpent,
      skipReason: SkipReason.NOT_ENOUGH_PRIOR_SPENT,
    };
  }

  return {
    shouldConfirm: true,
    isReturningCustomer: true,
    priorOrderCount,
    priorSpent,
    skipReason: SkipReason.NONE,
  };
}

function skip(reason: SkipReason): ConfirmDecision {
  return {
    shouldConfirm: false,
    isReturningCustomer: false,
    priorOrderCount: 0,
    priorSpent: 0,
    skipReason: reason,
  };
}
