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
