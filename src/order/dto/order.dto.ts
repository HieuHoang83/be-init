import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsDateString,
  IsIn,
  IsInt,
  IsNumber,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
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
  @IsOptional() @Type(() => Number) @IsInt()
  orgId?: number;

  @IsOptional() @IsString()
  email?: string;

  @IsOptional() @IsString()
  orderNumber?: string;

  @IsOptional() @IsString()
  search?: string;

  @IsOptional() @IsIn([...HARAVAN_ORDER_STATUSES, 'any'])
  status?: HaravanOrderStatus | 'any';

  @IsOptional() @IsIn(HARAVAN_FINANCIAL_FILTERS)
  financialStatus?: FinancialStatus;

  @IsOptional() @IsString()
  @Matches(csvListPattern(HARAVAN_FINANCIAL_FILTERS))
  financialStatuses?: string;

  @IsOptional() @IsString()
  @Matches(csvListPattern(HARAVAN_FULFILLMENT_FILTERS))
  fulfillmentStatuses?: string;

  @IsOptional() @IsString()
  @Matches(csvListPattern(HARAVAN_ORDER_STATUSES))
  haravanStatuses?: string;

  @IsOptional() @IsString()
  @Matches(csvListPattern(['first', 'repeat']))
  customerOrderTypes?: string;

  @IsOptional() @IsIn(['confirmed', 'unconfirmed'])
  confirmedStatus?: string;

  @IsOptional() @IsString()
  @Matches(/^(confirmed|unconfirmed)(,(confirmed|unconfirmed))*$/)
  confirmedStatuses?: string;

  @IsOptional() @IsDateString()
  createdFrom?: string;

  @IsOptional() @IsDateString()
  createdTo?: string;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1)
  page?: number;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100)
  limit?: number;
}

export class ListWebhookEventsQuery {
  @IsOptional() @Type(() => Number) @IsInt()
  orgId?: number;

  @IsOptional() @IsString()
  topic?: string;

  @IsOptional() @IsIn(Object.values(WebhookPrivateStatus))
  status?: WebhookPrivateStatus;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1)
  page?: number;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100)
  limit?: number;
}

export class ConfirmOrderBody {
  /** Người thực hiện. */
  @IsOptional() @IsString()
  actor?: string;

  /** Bỏ qua rule khi xác nhận thủ công. */
  @IsOptional() @Type(() => Boolean) @IsBoolean()
  force?: boolean;
}

export class GetOrderStatsQuery {
  @IsOptional() @Type(() => Number) @IsInt()
  orgId?: number;

  @IsOptional() @Type(() => Number) @IsNumber()
  minTotalPrice?: number;
}
