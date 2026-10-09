import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsDateString,
  IsIn,
  IsInt,
  IsNumber,
  IsOptional,
  IsString,
  ValidateIf,
  Matches,
  Max,
  Min,
  ArrayMinSize,
  IsArray,
  IsEmail,
  ValidateNested,
} from 'class-validator';
import {
  HARAVAN_FINANCIAL_FILTERS,
  FinancialStatus,
  HARAVAN_FULFILLMENT_FILTERS,
  HARAVAN_ORDER_STATUSES,
  HaravanOrderStatus,
} from '../../interface/order.interface';
import { WebhookPrivateStatus } from '../../webhook-private/webhook-private.entity';

function csvListPattern(values: readonly string[]) {
  const alternatives = values.join('|');
  return new RegExp(`^(${alternatives})(,(${alternatives}))*$`);
}

export class ListOrdersQuery {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  orgId?: number;

  @IsOptional()
  @IsString()
  email?: string;

  @IsOptional()
  @IsString()
  orderNumber?: string;

  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @IsIn([...HARAVAN_ORDER_STATUSES, 'any'])
  status?: HaravanOrderStatus | 'any';

  @IsOptional()
  @IsIn(HARAVAN_FINANCIAL_FILTERS)
  financialStatus?: FinancialStatus;

  @IsOptional()
  @IsString()
  @Matches(csvListPattern(HARAVAN_FINANCIAL_FILTERS))
  financialStatuses?: string;

  @IsOptional()
  @IsString()
  @Matches(csvListPattern(HARAVAN_FULFILLMENT_FILTERS))
  fulfillmentStatuses?: string;

  @IsOptional()
  @IsString()
  @Matches(csvListPattern(HARAVAN_ORDER_STATUSES))
  haravanStatuses?: string;

  @IsOptional()
  @IsString()
  @Matches(csvListPattern(['first', 'repeat']))
  customerOrderTypes?: string;

  @IsOptional()
  @IsIn(['confirmed', 'unconfirmed'])
  confirmedStatus?: string;

  @IsOptional()
  @IsString()
  @Matches(/^(confirmed|unconfirmed)(,(confirmed|unconfirmed))*$/)
  confirmedStatuses?: string;

  @IsOptional()
  @IsDateString()
  createdFrom?: string;

  @IsOptional()
  @IsDateString()
  createdTo?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;
}

export class ListWebhookEventsQuery {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  orgId?: number;

  @IsOptional()
  @IsString()
  topic?: string;

  @IsOptional()
  @IsIn(Object.values(WebhookPrivateStatus))
  status?: WebhookPrivateStatus;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;
}

export class ConfirmOrderBody {
  /** Người thực hiện. */
  @IsOptional()
  @IsString()
  actor?: string;

  /** Bỏ qua rule khi xác nhận thủ công. */
  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  force?: boolean;
}

export class CreateOrderLineItem {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  variant_id?: number;

  @ValidateIf((item: CreateOrderLineItem) => item.variant_id === undefined)
  @IsString()
  @Matches(/.*\S.*/)
  title?: string;

  @ValidateIf((item: CreateOrderLineItem) => item.variant_id === undefined)
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  price?: number;

  @Type(() => Number)
  @IsInt()
  @Min(1)
  quantity!: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  total_discount?: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateOrderAppliedDiscount)
  applied_discounts?: CreateOrderAppliedDiscount[];
}

export class CreateOrderAppliedDiscount {
  @IsString()
  description!: string;

  @Type(() => Number)
  @IsNumber()
  @Min(0)
  amount!: number;
}

export class CreateOrderDiscountCode {
  @IsString()
  code!: string;

  @IsBoolean()
  is_coupon_code!: boolean;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  amount?: number;
}

export class CreateOrderNoteAttribute {
  @IsString()
  name!: string;

  @IsString()
  value!: string;
}

export class CreateOrderBody {
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => CreateOrderLineItem)
  line_items!: CreateOrderLineItem[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateOrderDiscountCode)
  discount_codes?: CreateOrderDiscountCode[];

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  total_discounts?: number;

  @IsOptional()
  @IsIn(['pending', 'paid'])
  financial_status?: 'pending' | 'paid';

  @IsOptional()
  @IsString()
  gateway?: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  is_cod_gateway?: boolean;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateOrderNoteAttribute)
  note_attributes?: CreateOrderNoteAttribute[];

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  customer_id?: number;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  phone?: string;

  @IsOptional()
  @IsString()
  note?: string;

  @IsOptional()
  @IsString()
  first_name?: string;

  @IsOptional()
  @IsString()
  last_name?: string;

  @IsOptional()
  @IsString()
  address1?: string;

  @IsOptional()
  @IsString()
  city?: string;

  @IsOptional()
  @IsString()
  province?: string;

  @IsOptional()
  @IsString()
  country?: string;
}

export class GetOrderStatsQuery {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  orgId?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  minTotalPrice?: number;
}

/** Người thực hiện thao tác thủ công trên UI. */
export class ActorBody {
  @IsOptional()
  @IsString()
  actor?: string;
}

/**
 * Huỷ đơn. Theo tài liệu Haravan, `amount` là số tiền hoàn lại (bỏ trống = hoàn toàn bộ).
 * `refund` chỉ ghi nhận hoàn tiền khi đơn đã capture; COD thì tiền không thực trả.
 */
export class CancelOrderBody {
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  amount?: number;

  @IsOptional()
  @IsString()
  email?: string;

  @IsOptional()
  @IsString()
  reason?: string;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  refund?: boolean;

  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  restock?: boolean;

  @IsOptional()
  @IsString()
  note?: string;

  /** Giữ nguyên trạng thái giao hàng thay vì tự động gỡ fulfillment. */
  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  ignore_cancel_fulfillment?: boolean;

  @IsOptional()
  @IsString()
  actor?: string;
}

export class CloseOrderBody {
  @IsOptional()
  @IsString()
  note?: string;

  @IsOptional()
  @IsString()
  actor?: string;
}

export class OpenOrderBody {
  @IsOptional()
  @IsString()
  actor?: string;
}

/**
 * Cập nhật đơn. Haravan KHÔNG cho sửa line_items / số lượng / financial_status,
 * nên DTO này chỉ mở các trường an toàn.
 */
export class UpdateOrderBody {
  @IsOptional()
  @IsString()
  note?: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateOrderNoteAttribute)
  note_attributes?: CreateOrderNoteAttribute[];

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  phone?: string;

  @IsOptional()
  @IsString()
  actor?: string;
}

export class RefundTransactionInput {
  @IsIn(['refund'])
  kind!: 'refund';

  @Type(() => Number)
  @IsNumber()
  @Min(1)
  amount!: number;

  @IsOptional()
  @IsString()
  gateway?: string;

  @IsOptional()
  @IsString()
  note?: string;

  /** Tham chiếu giao dịch capture gốc khi hoàn một phần. */
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  parent_id?: number;
}

export class CreateRefundBody {
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RefundTransactionInput)
  transactions?: RefundTransactionInput[];

  @IsOptional()
  @IsString()
  note?: string;

  @IsOptional()
  @IsString()
  actor?: string;
}

export class ListRefundsQuery {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;
}

/**
 * 5 loại giao dịch theo tài liệu Haravan Transaction:
 * pending, authorization, sale, capture, void, refund.
 */
export const TRANSACTION_KINDS = [
  'pending',
  'authorization',
  'sale',
  'capture',
  'void',
  'refund',
] as const;

export type TransactionKind = (typeof TRANSACTION_KINDS)[number];

export class CreateTransactionBody {
  @IsIn(TRANSACTION_KINDS as unknown as string[])
  kind!: TransactionKind;

  @Type(() => Number)
  @IsNumber()
  @Min(0)
  amount!: number;

  @IsOptional()
  @IsString()
  gateway?: string;

  /** Giao dịch cha (ví dụ refund tham chiếu capture trước đó). */
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  parentId?: number;

  @IsOptional()
  @IsString()
  note?: string;
}

export class ListTransactionsQuery {
  /** Danh sách field cần lấy, cách nhau bằng dấu phẩy. */
  @IsOptional()
  @IsString()
  fields?: string;
}
